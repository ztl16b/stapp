#!/usr/bin/env python3
"""
bytescale_worker.py
───────────────────
• Watches the *Temp* bucket for new images.
• Sends each image to Bytescale for conversion → WebP (464 × 510, smart-crop).
• Saves the processed image in the **Upload** bucket (duplicate-checked).
• If a duplicate name already exists in Upload, file is saved to the Issue bucket with “_dupeUpload” suffix.
• Deletes the original image from Temp once the Upload (or Issue) write succeeds.
"""

import os, sys, time, traceback, logging, requests      # type: ignore
from io import BytesIO
from datetime import datetime
import boto3                                            # type: ignore
from dotenv import load_dotenv                         # type: ignore
import schedule                                         # type: ignore

# ─── ENV ────────────────────────────────────────────────────────────────────
load_dotenv()

AWS_ACCESS_KEY_ID       = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY   = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION              = os.getenv("AWS_REGION")

S3_TEMP_BUCKET          = os.getenv("S3_TEMP_BUCKET")
S3_TEMP_BUCKET_PREFIX   = os.getenv("S3_TEMP_BUCKET_PREFIX", "")

S3_UPLOAD_BUCKET        = os.getenv("S3_UPLOAD_BUCKET")          # ← final bucket
S3_UPLOAD_BUCKET_PREFIX = os.getenv("S3_UPLOAD_BUCKET_PREFIX", "")

S3_ISSUE_BUCKET         = os.getenv("S3_ISSUE_BUCKET")           # for dupes
S3_ISSUE_BUCKET_PREFIX  = os.getenv("S3_ISSUE_BUCKET_PREFIX", "")

BYTESCALE_API_KEY       = os.getenv("BYTESCALE_API_KEY")
BYTESCALE_UPLOAD_URL    = os.getenv("BYTESCALE_UPLOAD_URL")

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
    logger.info(f"Using {name}: {val}")

# ─── ENV VALIDATION ────────────────────────────────────────────────────────
missing = [
    var for var, val in {
        "AWS_ACCESS_KEY_ID"      : AWS_ACCESS_KEY_ID,
        "AWS_SECRET_ACCESS_KEY"  : AWS_SECRET_ACCESS_KEY,
        "AWS_REGION"             : AWS_REGION,
        "S3_TEMP_BUCKET"         : S3_TEMP_BUCKET,
        "S3_UPLOAD_BUCKET"       : S3_UPLOAD_BUCKET,
        "S3_ISSUE_BUCKET"        : S3_ISSUE_BUCKET,
        "BYTESCALE_API_KEY"      : BYTESCALE_API_KEY,
        "BYTESCALE_UPLOAD_URL"   : BYTESCALE_UPLOAD_URL,
    }.items() if not val
]
if missing:
    logger.error("Missing required environment variables: %s", ", ".join(missing))
    sys.exit(1)

# ─── AWS S3 CLIENT ────────────────────────────────────────────────────────
try:
    s3 = boto3.client(
        "s3",
        aws_access_key_id     = AWS_ACCESS_KEY_ID,
        aws_secret_access_key = AWS_SECRET_ACCESS_KEY,
        region_name           = AWS_REGION
    )
    s3.list_buckets()
    logger.info("✔︎ Connected to S3")
except Exception as e:
    logger.error("Failed to initialise S3 client: %s", e)
    sys.exit(1)

# ─── CORE LOGIC ────────────────────────────────────────────────────────────
def process_image(key: str) -> bool:
    """Download → Bytescale convert → upload to *Upload* bucket (or Issue if dupe)."""
    try:
        filename              = key.split("/")[-1]
        base_name, _          = os.path.splitext(filename)
        logger.info("Processing %s …", filename)

        # 1. Download from Temp
        obj       = s3.get_object(Bucket=S3_TEMP_BUCKET, Key=key)
        file_data = obj["Body"].read()
        if not file_data:
            logger.error("Downloaded file is empty → skip")
            return False

        meta              = obj.get("Metadata", {})
        uploader_initials = meta.get("uploader-initials", "")
        review_status     = meta.get("review_status", "FALSE")
        perfimg_status    = meta.get("perfimg_status", "FALSE")

        # 2. Upload raw to Bytescale
        with requests.Session() as sess:
            up_resp = sess.post(
                BYTESCALE_UPLOAD_URL,
                headers={"Authorization": f"Bearer {BYTESCALE_API_KEY}"},
                files={"file": (filename, file_data, obj.get("ContentType","image/jpeg"))},
                timeout=60,
            )
        if up_resp.status_code != 200:
            logger.error("Bytescale upload failed: %s", up_resp.text[:400])
            return False
        file_url = next(
            (f["fileUrl"] for f in up_resp.json().get("files", [])
             if f.get("formDataFieldName") == "file"), None
        )
        if not file_url:
            logger.error("Bytescale response missing fileUrl")
            return False

        # 3. Download processed (resized / smart-crop) image
        proc_url = file_url.replace("/raw/", "/image/") + "?f=webp&w=464&h=510&fit=crop&crop=smart"
        with requests.get(proc_url, stream=True, timeout=60) as resp:
            resp.raise_for_status()
            processed_data = resp.content

        # 4. Build Upload-bucket paths + metadata
        processed_filename   = f"{base_name.replace('-','.')}.webp"
        upload_key           = f"{S3_UPLOAD_BUCKET_PREFIX}{processed_filename}"

        extra_args = {
            "ContentType": "image/webp",
            "Metadata": {
                "review_status" : review_status,
                "perfimg_status": perfimg_status,
                "upload_time"   : datetime.utcnow().isoformat()
            }
        }
        if uploader_initials:
            extra_args["Metadata"]["uploader-initials"] = uploader_initials

        # 5. Duplicate check on Upload bucket
        is_dupe = False
        try:
            s3.head_object(Bucket=S3_UPLOAD_BUCKET, Key=upload_key)
            is_dupe = True
            logger.info("Duplicate detected in Upload bucket → will route to Issue bucket")
        except Exception:
            pass

        # 6. Write to Upload or Issue bucket
        target_bucket = S3_ISSUE_BUCKET if is_dupe else S3_UPLOAD_BUCKET
        target_key    = (
            f"{S3_ISSUE_BUCKET_PREFIX}{base_name}_dupeUpload.webp"
            if is_dupe else
            upload_key
        )
        s3.put_object(
            Bucket = target_bucket,
            Key    = target_key,
            Body   = processed_data,
            **extra_args
        )
        logger.info("Uploaded to %s/%s", target_bucket, target_key)

        # 7. Delete original from Temp
        s3.delete_object(Bucket=S3_TEMP_BUCKET, Key=key)
        logger.info("Deleted original %s from Temp bucket", key)
        return True

    except Exception as e:
        logger.error("Error processing %s: %s", key, e)
        traceback.print_exc()
        return False

def check_temp_bucket():
    """Scan Temp bucket for images and process them."""
    logger.info("Checking Temp bucket …")
    try:
        resp = s3.list_objects_v2(
            Bucket = S3_TEMP_BUCKET,
            Prefix = S3_TEMP_BUCKET_PREFIX or ""
        )
        if "Contents" not in resp:
            logger.info("No objects found.")
            return

        image_exts = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp")
        imgs = [o for o in resp["Contents"] if o["Key"].lower().endswith(image_exts)]
        if not imgs:
            logger.info("No images to process.")
            return

        logger.info("Found %d image(s)", len(imgs))
        for obj in imgs:
            ok = process_image(obj["Key"])
            if ok:
                logger.info("✓ %s processed", obj["Key"])
            else:
                logger.error("✗ %s failed", obj["Key"])

    except Exception as e:
        logger.error("Temp-bucket scan failed: %s", e)
        traceback.print_exc()

def run_scheduler():
    logger.info("Bytescale worker started (checks every 30 s)")
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

if __name__ == "__main__":
    try:
        run_scheduler()
    except KeyboardInterrupt:
        logger.info("Exiting (Ctrl-C)")
    except Exception as exc:
        logger.error("Fatal error: %s", exc)
        traceback.print_exc()