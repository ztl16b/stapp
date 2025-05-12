#!/usr/bin/env python3
"""
bytescale_worker.py — UPDATED
─────────────────────────────
• Monitors the *Temp* bucket for new images.
• Runs Gemini audits (text, likeness, clip) on the ORIGINAL file.
    – If **text** or **likeness** fails → moves the original file (with metadata) to Issue bucket.
    – Always records **clip_1** result in metadata.
• If text + likeness pass → Converts the image to WebP (464×510 smart‑crop) via Bytescale.
• Runs the **clip** audit again on the processed file (records **clip_2**).
• Saves the WebP in Upload bucket (duplicate‑checked).  Duplicates or Gemini‑rejects route to Issue bucket.
"""

import os, sys, time, traceback, logging, base64, requests           # type: ignore
from io import BytesIO
from datetime import datetime
import boto3                                                         # type: ignore
from dotenv import load_dotenv                                      # type: ignore
import schedule                                                      # type: ignore
from google import genai                                            # type: ignore

# ─── ENV ────────────────────────────────────────────────────────────────────
load_dotenv()

AWS_ACCESS_KEY_ID       = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY   = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION              = os.getenv("AWS_REGION")

S3_TEMP_BUCKET          = os.getenv("S3_TEMP_BUCKET")
S3_TEMP_BUCKET_PREFIX   = os.getenv("S3_TEMP_BUCKET_PREFIX", "")

S3_UPLOAD_BUCKET        = os.getenv("S3_UPLOAD_BUCKET")          # final bucket
S3_UPLOAD_BUCKET_PREFIX = os.getenv("S3_UPLOAD_BUCKET_PREFIX", "")

S3_ISSUE_BUCKET         = os.getenv("S3_ISSUE_BUCKET")           # dupes + rejects
S3_ISSUE_BUCKET_PREFIX  = os.getenv("S3_ISSUE_BUCKET_PREFIX", "")

BYTESCALE_API_KEY       = os.getenv("BYTESCALE_API_KEY")
BYTESCALE_UPLOAD_URL    = os.getenv("BYTESCALE_UPLOAD_URL")

GEMINI_API_KEY          = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL_ID         = os.getenv("GEMINI_MODEL_ID", "gemini-2.5-pro-preview-03-25")

# ─── PROMPTS (place‑holders — tweak to taste) ───────────────────────────────
TEXT_PROMPT = """You are a strict moderator. Analyse the provided image and answer only with \nPASS or FAIL\n— PASS if the image contains *no* visible text, watermarks, logos, or trademarks.\n— FAIL if *any* text, watermark, logo, or trademark is visible."""

LIKENESS_PROMPT = """You are verifying performer authenticity. Given the image of a *live‑event performer*, decide if the person looks like a believable, naturally lit concert photograph.\nReturn only PASS or FAIL (FAIL for obvious AI artefacts, distorted anatomy, or unrealistic lighting)."""

CLIP_PROMPT = """Detect **body parts or objects passing through solid, opaque objects** (clipping).\nReturn one line: \nVerdict: <PASS/FAIL> — <one‑sentence explanation>."""

# ─── LOGGING ───────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("bytescale_worker")

for name, val in (
    ("Temp bucket"   , f"{S3_TEMP_BUCKET}/{S3_TEMP_BUCKET_PREFIX or '(root)'}"),
    ("Upload bucket" , f"{S3_UPLOAD_BUCKET}/{S3_UPLOAD_BUCKET_PREFIX or '(root)'}"),
    ("Issue bucket"  , f"{S3_ISSUE_BUCKET}/{S3_ISSUE_BUCKET_PREFIX or '(root)'}"),
):
    logger.info("Using %s: %s", name, val)

# ─── ENV VALIDATION ────────────────────────────────────────────────────────
missing = [
    var for var, val in {
        "AWS_ACCESS_KEY_ID"     : AWS_ACCESS_KEY_ID,
        "AWS_SECRET_ACCESS_KEY" : AWS_SECRET_ACCESS_KEY,
        "AWS_REGION"            : AWS_REGION,
        "S3_TEMP_BUCKET"        : S3_TEMP_BUCKET,
        "S3_UPLOAD_BUCKET"      : S3_UPLOAD_BUCKET,
        "S3_ISSUE_BUCKET"       : S3_ISSUE_BUCKET,
        "BYTESCALE_API_KEY"     : BYTESCALE_API_KEY,
        "BYTESCALE_UPLOAD_URL"  : BYTESCALE_UPLOAD_URL,
        "GEMINI_API_KEY"        : GEMINI_API_KEY,
    }.items() if not val
]
if missing:
    logger.error("Missing required environment variables: %s", ", ".join(missing))
    sys.exit(1)

# ─── INITIALISE CLIENTS ────────────────────────────────────────────────────
try:
    s3 = boto3.client(
        "s3",
        aws_access_key_id     = AWS_ACCESS_KEY_ID,
        aws_secret_access_key = AWS_SECRET_ACCESS_KEY,
        region_name           = AWS_REGION,
    )
    s3.list_buckets()
    logger.info("✔︎ Connected to S3")
except Exception as e:
    logger.error("Failed to initialise S3 client: %s", e)
    sys.exit(1)

try:
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel(GEMINI_MODEL_ID)
    logger.info("✔︎ Gemini model ready (%s)", GEMINI_MODEL_ID)
except Exception as e:
    logger.error("Failed to initialise Gemini client: %s", e)
    sys.exit(1)

# ─── GEMINI HELPERS ────────────────────────────────────────────────────────

def _img_part(img_bytes: bytes, mime: str = "image/jpeg") -> dict:
    return {"mime_type": mime, "data": base64.b64encode(img_bytes).decode()}  # type: ignore[return-value]


def gemini_single(prompt: str, img_bytes: bytes) -> str:
    """Call Gemini with *prompt* + image; return text response."""
    try:
        resp = gemini_model.generate_content([
            {"text": prompt},
            _img_part(img_bytes)
        ])
        return resp.text.strip()
    except Exception as e:
        logger.error("Gemini call failed: %s", e)
        return "ERROR"


def gemini_audit(img_bytes: bytes) -> dict:
    """Run the three audits; return dict with results."""
    text_verdict     = gemini_single(TEXT_PROMPT, img_bytes)
    likeness_verdict = gemini_single(LIKENESS_PROMPT, img_bytes)
    clip_output      = gemini_single(CLIP_PROMPT, img_bytes)
    return {
        "text"    : text_verdict.upper(),        # expect PASS / FAIL
        "likeness": likeness_verdict.upper(),
        "clip"    : clip_output,
    }

# ─── CORE LOGIC ────────────────────────────────────────────────────────────

def process_image(key: str) -> bool:
    """Full pipeline for a single image key."""
    try:
        filename   = key.split("/")[-1]
        base_name, ext = os.path.splitext(filename)
        logger.info("Processing %s …", filename)

        # 1. Download original from Temp
        obj       = s3.get_object(Bucket=S3_TEMP_BUCKET, Key=key)
        img_bytes = obj["Body"].read()
        if not img_bytes:
            logger.error("Downloaded file is empty → skip")
            return False
        content_type = obj.get("ContentType", "image/jpeg")

        meta              = obj.get("Metadata", {}) or {}
        uploader_initials = meta.get("uploader-initials", "")
        review_status     = meta.get("review_status", "FALSE")
        perfimg_status    = meta.get("perfimg_status", "FALSE")

        # 2. FIRST GEMINI AUDIT ------------------------------------------------
        audit1 = gemini_audit(img_bytes)
        clip_1 = audit1["clip"]
        text_pass     = audit1["text"    ] == "PASS"
        likeness_pass = audit1["likeness"] == "PASS"

        if not (text_pass and likeness_pass):
            logger.info("Gemini rejected (text/likeness) — moving to Issue bucket")
            issue_key = f"{S3_ISSUE_BUCKET_PREFIX}{base_name}_geminiReject{ext}"
            meta_out = {
                **meta,
                "clip_1"      : clip_1,
                "gemini_text" : audit1["text"],
                "gemini_like" : audit1["likeness"],
                "upload_time" : datetime.utcnow().isoformat(),
            }
            if uploader_initials:
                meta_out["uploader-initials"] = uploader_initials
            s3.put_object(
                Bucket = S3_ISSUE_BUCKET,
                Key    = issue_key,
                Body   = img_bytes,
                ContentType = content_type,
                Metadata    = meta_out,
            )
            s3.delete_object(Bucket=S3_TEMP_BUCKET, Key=key)
            logger.info("Moved to %s/%s and deleted from Temp", S3_ISSUE_BUCKET, issue_key)
            return True

        # 3. BYTESCALE CONVERSION ---------------------------------------------
        with requests.Session() as sess:
            up_resp = sess.post(
                BYTESCALE_UPLOAD_URL,
                headers={"Authorization": f"Bearer {BYTESCALE_API_KEY}"},
                files={"file": (filename, img_bytes, content_type)},
                timeout=60,
            )
        if up_resp.status_code != 200:
            logger.error("Bytescale upload failed: %s", up_resp.text[:400])
            return False
        file_url = next(
            (f["fileUrl"] for f in up_resp.json().get("files", []) if f.get("formDataFieldName") == "file"),
            None,
        )
        if not file_url:
            logger.error("Bytescale response missing fileUrl")
            return False

        proc_url = (
            file_url.replace("/raw/", "/image/") +
            "?f=webp&w=464&h=510&fit=crop&crop=smart"
        )
        with requests.get(proc_url, stream=True, timeout=60) as resp:
            resp.raise_for_status()
            processed_bytes = resp.content

        # 4. SECOND CLIP AUDIT -------------------------------------------------
        clip_2 = gemini_single(CLIP_PROMPT, processed_bytes)

        # 5. Build S3 metadata -------------------------------------------------
        processed_filename = f"{base_name.replace('-', '.')}.webp"
        upload_key         = f"{S3_UPLOAD_BUCKET_PREFIX}{processed_filename}"

        metadata_out = {
            "review_status"  : review_status,
            "perfimg_status" : perfimg_status,
            "clip_1"         : clip_1,
            "clip_2"         : clip_2,
            "upload_time"    : datetime.utcnow().isoformat(),
        }
        if uploader_initials:
            metadata_out["uploader-initials"] = uploader_initials

        # 6. Duplicate check ---------------------------------------------------
        is_dupe = False
        try:
            s3.head_object(Bucket=S3_UPLOAD_BUCKET, Key=upload_key)
            is_dupe = True
            logger.info("Duplicate detected in Upload bucket → Issue bucket")
        except Exception:
            pass

        target_bucket = S3_ISSUE_BUCKET if is_dupe else S3_UPLOAD_BUCKET
        target_key    = (
            f"{S3_ISSUE_BUCKET_PREFIX}{base_name}_dupeUpload.webp" if is_dupe else upload_key
        )

        s3.put_object(
            Bucket      = target_bucket,
            Key         = target_key,
            Body        = processed_bytes,
            ContentType = "image/webp",
            Metadata    = metadata_out,
        )
        logger.info("Uploaded to %s/%s", target_bucket, target_key)

        # 7. Delete original ---------------------------------------------------
        s3.delete_object(Bucket=S3_TEMP_BUCKET, Key=key)
        logger.info("Deleted original %s from Temp bucket", key)
        return True

    except Exception as e:
        logger.error("Error processing %s: %s", key, e)
        traceback.print_exc()
        return False


# ─── BUCKET SCAN / SCHEDULER ───────────────────────────────────────────────

def check_temp_bucket():
    logger.info("Scanning Temp bucket …")
    try:
        resp = s3.list_objects_v2(Bucket=S3_TEMP_BUCKET, Prefix=S3_TEMP_BUCKET_PREFIX)
        if "Contents" not in resp:
            logger.info("No objects found.")
            return

        image_exts = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp")
        work = [o for o in resp["Contents"] if o["Key"].lower().endswith(image_exts)]
        if not work:
            logger.info("No images to process.")
            return

        logger.info("Found %d image(s)", len(work))
        for obj in work:
            ok = process_image(obj["Key"])
            if ok:
                logger.info("✓ %s processed", obj["Key"])
            else:
                logger.error("✗ %s failed", obj["Key"])
    except Exception as e:
        logger.error("Temp‑bucket scan failed: %s", e)
        traceback.print_exc()


def run_scheduler():
    logger.info("Bytescale worker started (checks every 30 s)")
    check_temp_bucket()                              # immediate first run
    schedule.every(30).seconds.do(check_temp_bucket)
    while True:
        try:
            schedule.run_pending()
            time.sleep(1)
        except Exception as e:
            logger.error("Scheduler loop error: %s", e)
            traceback.print_exc()
            time.sleep(60)


# ─── ENTRY ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        run_scheduler()
    except KeyboardInterrupt:
        logger.info("Exiting (Ctrl‑C)")
    except Exception as exc:
        logger.error("Fatal error: %s", exc)
        traceback.print_exc()