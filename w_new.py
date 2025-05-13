#!/usr/bin/env python3
"""
bytescale_worker.py
──────────────────────────────────────────────────────────────────────────────
Scheduled Heroku worker that:

• Watches the *Temp* S3 bucket for new uploads.
• Runs three Gemini audits (text, likeness, clip) on the ORIGINAL image.
    – If text or likeness *fail* → moves the original to the Issue bucket.
    – Always records the first clip result (clip_1).
• If text+likeness *pass* → converts the image to WebP (464×510 smart-crop)
  with Bytescale, then:
    – Runs the clip audit again on the processed image (clip_2).
    – Saves the WebP into the Upload bucket (or Issue bucket if a duplicate).
All Gemini + pipeline results are pushed into object metadata (ASCII-safe).
"""

from __future__ import annotations

import base64
import logging
import os
import sys
import time
import traceback
from datetime import datetime, timezone
from io import BytesIO
from typing import Dict, Tuple

import boto3  # type: ignore
import google.generativeai as genai  # type: ignore
import requests  # type: ignore
import schedule  # type: ignore
from dotenv import load_dotenv  # type: ignore

# ─── ENV ────────────────────────────────────────────────────────────────────
load_dotenv()

AWS_ACCESS_KEY_ID: str | None = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY: str | None = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION: str | None = os.getenv("AWS_REGION")

S3_TEMP_BUCKET: str | None = os.getenv("S3_TEMP_BUCKET")
S3_TEMP_BUCKET_PREFIX: str = os.getenv("S3_TEMP_BUCKET_PREFIX", "")

S3_UPLOAD_BUCKET: str | None = os.getenv("S3_UPLOAD_BUCKET")          # final bucket
S3_UPLOAD_BUCKET_PREFIX: str = os.getenv("S3_UPLOAD_BUCKET_PREFIX", "")

S3_ISSUE_BUCKET: str | None = os.getenv("S3_ISSUE_BUCKET")           # dupes + rejects
S3_ISSUE_BUCKET_PREFIX: str = os.getenv("S3_ISSUE_BUCKET_PREFIX", "")

BYTESCALE_API_KEY: str | None = os.getenv("BYTESCALE_API_KEY")
BYTESCALE_UPLOAD_URL: str | None = os.getenv("BYTESCALE_UPLOAD_URL")

GEMINI_API_KEY: str | None = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL_ID: str = os.getenv("GEMINI_MODEL_ID", "gemini-2.5-pro-preview-03-25")

# ─── PROMPTS ────────────────────────────────────────────────────────────────
TEXT_PROMPT = (
    "You are a strict moderator. Analyse the provided image and answer only with\n"
    "PASS or FAIL\n"
    "— PASS if the image contains *no* visible text, watermarks, logos, or trademarks.\n"
    "— FAIL if *any* text, watermark, logo, or trademark is visible."
)

LIKENESS_PROMPT = (
    "You are verifying performer authenticity. Given the image of a *live-event "
    "performer*, decide if the person looks like a believable, naturally lit "
    "concert photograph.\nReturn only PASS or FAIL (FAIL for obvious AI artefacts, "
    "distorted anatomy, or unrealistic lighting)."
)

CLIP_PROMPT = (
    "Detect **body parts or objects passing through solid, opaque objects** (clipping).\n"
    "Return one line: \nVerdict: <PASS/FAIL> — <one-sentence explanation>."
)

# ─── LOGGING ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("bytescale_worker")

for name, val in (
    ("Temp bucket", f"{S3_TEMP_BUCKET}/{S3_TEMP_BUCKET_PREFIX or '(root)'}"),
    ("Upload bucket", f"{S3_UPLOAD_BUCKET}/{S3_UPLOAD_BUCKET_PREFIX or '(root)'}"),
    ("Issue bucket", f"{S3_ISSUE_BUCKET}/{S3_ISSUE_BUCKET_PREFIX or '(root)'}"),
):
    logger.info("Using %s: %s", name, val)

# ─── ENV VALIDATION ────────────────────────────────────────────────────────
missing_env = [
    var
    for var, v in {
        "AWS_ACCESS_KEY_ID": AWS_ACCESS_KEY_ID,
        "AWS_SECRET_ACCESS_KEY": AWS_SECRET_ACCESS_KEY,
        "AWS_REGION": AWS_REGION,
        "S3_TEMP_BUCKET": S3_TEMP_BUCKET,
        "S3_UPLOAD_BUCKET": S3_UPLOAD_BUCKET,
        "S3_ISSUE_BUCKET": S3_ISSUE_BUCKET,
        "BYTESCALE_API_KEY": BYTESCALE_API_KEY,
        "BYTESCALE_UPLOAD_URL": BYTESCALE_UPLOAD_URL,
        "GEMINI_API_KEY": GEMINI_API_KEY,
    }.items()
    if not v
]
if missing_env:
    logger.error("Missing required environment variables: %s", ", ".join(missing_env))
    sys.exit(1)

# ─── INITIALISE CLIENTS ────────────────────────────────────────────────────
try:
    s3 = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION,
    )
    s3.list_buckets()
    logger.info("✔︎ Connected to S3")
except Exception as exc:
    logger.error("Failed to initialise S3 client: %s", exc)
    sys.exit(1)

try:
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel(GEMINI_MODEL_ID)
    logger.info("✔︎ Gemini model ready (%s)", GEMINI_MODEL_ID)
except Exception as exc:
    logger.error("Failed to initialise Gemini client: %s", exc)
    sys.exit(1)

# ─── HELPERS ───────────────────────────────────────────────────────────────


def _ascii_safe(text: str, max_len: int = 250) -> str:
    """
    Keep only ASCII chars (S3 metadata requirement) and trim length.
    """
    return text.encode("ascii", "ignore").decode()[:max_len]


def _img_part(img_bytes: bytes, mime: str = "image/jpeg") -> Dict[str, str]:
    return {"mime_type": mime, "data": base64.b64encode(img_bytes).decode()}


def gemini_single(prompt: str, img: bytes) -> str:
    """Call Gemini with prompt + image; return raw response text."""
    try:
        resp = gemini_model.generate_content([{"text": prompt}, _img_part(img)])
        return resp.text.strip()
    except Exception as exc:
        logger.error("Gemini call failed: %s", exc)
        return "ERROR"


def _parse_clip(response: str) -> Tuple[str, str]:
    """
    Extract PASS/FAIL verdict and explanation from Gemini clip response.
    """
    up = response.upper()
    verdict = "PASS" if "PASS" in up else "FAIL"
    # strip leading "Verdict:" if present
    explanation = response.split("—", 1)[-1].strip() if "—" in response else response
    return verdict, explanation


def gemini_audit(img: bytes) -> Dict[str, str]:
    text_v = gemini_single(TEXT_PROMPT, img).upper()
    like_v = gemini_single(LIKENESS_PROMPT, img).upper()
    clip_raw = gemini_single(CLIP_PROMPT, img)
    clip_verdict, clip_exp = _parse_clip(clip_raw)
    return {
        "text": text_v,
        "likeness": like_v,
        "clip_verdict": clip_verdict,
        "clip_explain": clip_exp,
    }


# ─── CORE LOGIC ────────────────────────────────────────────────────────────
def process_image(key: str) -> bool:
    """End-to-end pipeline for a single S3 object key in the temp bucket."""
    try:
        filename = key.rsplit("/", 1)[-1]
        base_name, ext = os.path.splitext(filename)
        logger.info("Processing %s …", filename)

        # 1️⃣  Download original
        obj = s3.get_object(Bucket=S3_TEMP_BUCKET, Key=key)
        img_bytes = obj["Body"].read()
        if not img_bytes:
            logger.error("Downloaded file is empty → skip")
            return False
        content_type = obj.get("ContentType", "image/jpeg")
        meta_in = obj.get("Metadata", {}) or {}
        uploader_initials = meta_in.get("uploader-initials", "")
        review_status = meta_in.get("review_status", "FALSE")
        perfimg_status = meta_in.get("perfimg_status", "FALSE")

        # 2️⃣  First Gemini audit
        audit1 = gemini_audit(img_bytes)
        clip1_verdict = audit1["clip_verdict"]

        text_pass = audit1["text"] == "PASS"
        like_pass = audit1["likeness"] == "PASS"

        if not (text_pass and like_pass):
            logger.info("Gemini rejected (text/likeness) → Issue bucket")
            issue_key = f"{S3_ISSUE_BUCKET_PREFIX}{base_name}_geminiReject{ext}"
            meta_out = {
                "clip_1": _ascii_safe(clip1_verdict),
                "clip1_msg": _ascii_safe(audit1["clip_explain"]),
                "gemini_text": audit1["text"],
                "gemini_like": audit1["likeness"],
                "upload_time": datetime.now(timezone.utc).isoformat(),
            }
            if uploader_initials:
                meta_out["uploader-initials"] = _ascii_safe(uploader_initials)

            s3.put_object(
                Bucket=S3_ISSUE_BUCKET,
                Key=issue_key,
                Body=img_bytes,
                ContentType=content_type,
                Metadata=meta_out,
            )
            s3.delete_object(Bucket=S3_TEMP_BUCKET, Key=key)
            logger.info("Moved to %s/%s and removed from Temp", S3_ISSUE_BUCKET, issue_key)
            return True

        # 3️⃣  Bytescale conversion
        with requests.Session() as sess:
            up_resp = sess.post(
                BYTESCALE_UPLOAD_URL,
                headers={"Authorization": f"Bearer {BYTESCALE_API_KEY}"},
                files={"file": (filename, img_bytes, content_type)},
                timeout=60,
            )
        if up_resp.status_code != 200:
            logger.error("Bytescale upload failed (%s): %s", up_resp.status_code, up_resp.text[:300])
            return False

        try:
            file_url = next(
                f["fileUrl"]
                for f in up_resp.json().get("files", [])
                if f.get("formDataFieldName") == "file"
            )
        except StopIteration:
            logger.error("Bytescale response missing fileUrl")
            return False

        proc_url = (
            file_url.replace("/raw/", "/image/")
            + "?f=webp&w=464&h=510&fit=crop&crop=smart"
        )
        proc_resp = requests.get(proc_url, stream=True, timeout=60)
        proc_resp.raise_for_status()
        processed_bytes = proc_resp.content

        # 4️⃣  Second clip audit
        clip2_raw = gemini_single(CLIP_PROMPT, processed_bytes)
        clip2_verdict, clip2_exp = _parse_clip(clip2_raw)

        # 5️⃣  Build metadata
        processed_filename = f"{base_name.replace('-', '.')}.webp"
        upload_key = f"{S3_UPLOAD_BUCKET_PREFIX}{processed_filename}"
        metadata_out = {
            "review_status": _ascii_safe(review_status),
            "perfimg_status": _ascii_safe(perfimg_status),
            "clip_1": _ascii_safe(clip1_verdict),
            "clip1_msg": _ascii_safe(audit1["clip_explain"]),
            "clip_2": _ascii_safe(clip2_verdict),
            "clip2_msg": _ascii_safe(clip2_exp),
            "upload_time": datetime.now(timezone.utc).isoformat(),
        }
        if uploader_initials:
            metadata_out["uploader-initials"] = _ascii_safe(uploader_initials)

        # 6️⃣  Duplicate check
        try:
            s3.head_object(Bucket=S3_UPLOAD_BUCKET, Key=upload_key)
            is_dupe = True
            logger.info("Duplicate detected → Issue bucket")
        except s3.exceptions.ClientError:
            is_dupe = False

        target_bucket = S3_ISSUE_BUCKET if is_dupe else S3_UPLOAD_BUCKET
        target_key = (
            f"{S3_ISSUE_BUCKET_PREFIX}{base_name}_dupeUpload.webp"
            if is_dupe
            else upload_key
        )

        s3.put_object(
            Bucket=target_bucket,
            Key=target_key,
            Body=processed_bytes,
            ContentType="image/webp",
            Metadata=metadata_out,
        )
        logger.info("Uploaded to %s/%s", target_bucket, target_key)

        # 7️⃣  House-keeping
        s3.delete_object(Bucket=S3_TEMP_BUCKET, Key=key)
        logger.info("Deleted original %s from Temp bucket", key)
        return True

    except Exception as exc:
        logger.error("Error processing %s: %s", key, exc)
        traceback.print_exc()
        return False


# ─── BUCKET SCAN / SCHEDULER ───────────────────────────────────────────────
def check_temp_bucket() -> None:
    logger.info("Scanning Temp bucket …")
    try:
        resp = s3.list_objects_v2(Bucket=S3_TEMP_BUCKET, Prefix=S3_TEMP_BUCKET_PREFIX)
        if "Contents" not in resp:
            logger.info("No objects found.")
            return

        image_exts = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp")
        candidates = [o for o in resp["Contents"] if o["Key"].lower().endswith(image_exts)]
        if not candidates:
            logger.info("No images to process.")
            return

        logger.info("Found %d image(s)", len(candidates))
        for obj in candidates:
            key = obj["Key"]
            ok = process_image(key)
            if ok:
                logger.info("✓ %s processed", key)
            else:
                logger.error("✗ %s failed", key)
    except Exception as exc:
        logger.error("Temp-bucket scan failed: %s", exc)
        traceback.print_exc()


def run_scheduler() -> None:
    logger.info("Bytescale worker started (checks every 30 s)")
    check_temp_bucket()  # immediate first run
    schedule.every(30).seconds.do(check_temp_bucket)
    while True:
        try:
            schedule.run_pending()
            time.sleep(1)
        except Exception as exc:
            logger.error("Scheduler loop error: %s", exc)
            traceback.print_exc()
            time.sleep(60)


# ─── ENTRY-POINT ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        run_scheduler()
    except KeyboardInterrupt:
        logger.info("Exiting (Ctrl-C)")
    except Exception as exc:
        logger.error("Fatal error: %s", exc)
        traceback.print_exc()