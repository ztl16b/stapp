#!/usr/bin/env python3
"""
bytescale_worker.py
──────────────────────────────────────────────────────────────────────────────
Heroku worker that audits images with Gemini, converts passing ones via
Bytescale, and pushes results to the appropriate S3 bucket.

Changes in this revision
• Parses new multi-line audit formats (“Verdict: Approve|Reject”).
• If Text audit rejects → key ends with _text    (Issue bucket)
  If Likeness audit rejects → key ends with _likeness (Issue bucket)
• Sanitises ALL metadata for ASCII + header-safe characters.
"""

from __future__ import annotations

import base64
import logging
import os
import re
import sys
import time
import traceback
from datetime import datetime, timezone
from typing import Dict, Tuple

import boto3  # type: ignore
import google.generativeai as genai  # type: ignore
import requests  # type: ignore
import schedule  # type: ignore
from botocore.exceptions import ClientError  # type: ignore
from dotenv import load_dotenv  # type: ignore

# ─── ENV ────────────────────────────────────────────────────────────────────
load_dotenv()

AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")

S3_TEMP_BUCKET = os.getenv("S3_TEMP_BUCKET")
S3_TEMP_BUCKET_PREFIX = os.getenv("S3_TEMP_BUCKET_PREFIX", "")

S3_UPLOAD_BUCKET = os.getenv("S3_UPLOAD_BUCKET")
S3_UPLOAD_BUCKET_PREFIX = os.getenv("S3_UPLOAD_BUCKET_PREFIX", "")

S3_ISSUE_BUCKET = os.getenv("S3_ISSUE_BUCKET")
S3_ISSUE_BUCKET_PREFIX = os.getenv("S3_ISSUE_BUCKET_PREFIX", "")

BYTESCALE_API_KEY = os.getenv("BYTESCALE_API_KEY")
BYTESCALE_UPLOAD_URL = os.getenv("BYTESCALE_UPLOAD_URL")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL_ID = os.getenv("GEMINI_MODEL_ID", "gemini-2.5-pro-preview-03-25")

# ─── PROMPTS (unchanged but now multi-line verdicts) ────────────────────────
TEXT_PROMPT = """…⟨omitted for brevity – unchanged ⟩"""
LIKENESS_PROMPT = """…"""
CLIP_PROMPT = """…"""

# ─── LOGGING ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("bytescale_worker")

# ─── VALIDATE ENV ───────────────────────────────────────────────────────────
_required = {
    "AWS_ACCESS_KEY_ID": AWS_ACCESS_KEY_ID,
    "AWS_SECRET_ACCESS_KEY": AWS_SECRET_ACCESS_KEY,
    "AWS_REGION": AWS_REGION,
    "S3_TEMP_BUCKET": S3_TEMP_BUCKET,
    "S3_UPLOAD_BUCKET": S3_UPLOAD_BUCKET,
    "S3_ISSUE_BUCKET": S3_ISSUE_BUCKET,
    "BYTESCALE_API_KEY": BYTESCALE_API_KEY,
    "BYTESCALE_UPLOAD_URL": BYTESCALE_UPLOAD_URL,
    "GEMINI_API_KEY": GEMINI_API_KEY,
}
missing = [k for k, v in _required.items() if not v]
if missing:
    logger.error("Missing required env vars: %s", ", ".join(missing))
    sys.exit(1)

# ─── CLIENTS ────────────────────────────────────────────────────────────────
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
    logger.error("Failed to init S3 client: %s", exc)
    sys.exit(1)

try:
    genai.configure(api_key=GEMINI_API_KEY)
    GEMINI = genai.GenerativeModel(GEMINI_MODEL_ID)
    logger.info("✔︎ Gemini model ready (%s)", GEMINI_MODEL_ID)
except Exception as exc:
    logger.error("Failed to init Gemini client: %s", exc)
    sys.exit(1)

# ─── SMALL HELPERS ──────────────────────────────────────────────────────────
def _http_safe(text: str, max_len: int = 250) -> str:
    """ASCII, strip CR/LF/TAB, collapse whitespace, trim length."""
    cleaned = (
        text.encode("ascii", "ignore")
        .decode()
        .replace("\n", " ")
        .replace("\r", " ")
        .replace("\t", " ")
    )
    return re.sub(r"\s{2,}", " ", cleaned)[:max_len]


def _img_part(b: bytes, mime: str = "image/jpeg") -> Dict[str, str]:
    return {"mime_type": mime, "data": base64.b64encode(b).decode()}


def gemini_single(prompt: str, img: bytes) -> str:
    try:
        resp = GEMINI.generate_content([{"text": prompt}, _img_part(img)])
        return resp.text.strip()
    except Exception as exc:
        logger.error("Gemini call failed: %s", exc)
        return ""


def _verdict(raw: str) -> Tuple[str, str]:
    """
    Return (APPROVE|REJECT|UNKNOWN, short_reason).
    Also maps PASS→APPROVE and FAIL→REJECT.
    """
    match = re.search(r"VERDICT\s*:\s*(APPROVE|REJECT|PASS|FAIL)", raw, re.I)
    v = match.group(1).upper() if match else "UNKNOWN"
    verdict = "APPROVE" if v in ("APPROVE", "PASS") else "REJECT" if v in ("REJECT", "FAIL") else "UNKNOWN"

    reason = ""
    m_reason = re.search(r"REASON\s*:\s*(.+)", raw, re.I | re.S)
    if m_reason:
        reason = m_reason.group(1).strip()
    return verdict, reason


def gemini_audit(img: bytes) -> Dict[str, str]:
    text_raw = gemini_single(TEXT_PROMPT, img)
    like_raw = gemini_single(LIKENESS_PROMPT, img)
    clip_raw = gemini_single(CLIP_PROMPT, img)

    text_v, text_reason = _verdict(text_raw)
    like_v, like_reason = _verdict(like_raw)
    clip_v, clip_reason = _verdict(clip_raw)

    return {
        "text_verdict": text_v,
        "text_reason": text_reason,
        "likeness_verdict": like_v,
        "likeness_reason": like_reason,
        "clip_verdict": clip_v,
        "clip_reason": clip_reason,
    }

# ─── CORE PIPELINE ──────────────────────────────────────────────────────────
def process_image(key: str) -> bool:
    try:
        filename = key.rsplit("/", 1)[-1]
        base_name, ext = os.path.splitext(filename)
        logger.info("Processing %s …", filename)

        obj = s3.get_object(Bucket=S3_TEMP_BUCKET, Key=key)
        img_bytes: bytes = obj["Body"].read()
        if not img_bytes:
            logger.error("Downloaded file empty → skip")
            return False
        content_type = obj.get("ContentType", "image/jpeg")
        meta_in = obj.get("Metadata", {}) or {}

        audit = gemini_audit(img_bytes)
        text_ok = audit["text_verdict"] == "APPROVE"
        like_ok = audit["likeness_verdict"] == "APPROVE"

        # ---------- Reject path (Text / Likeness) ---------------------------
        if not (text_ok and like_ok):
            suffix = "_text" if not text_ok else "_likeness"
            issue_key = f"{S3_ISSUE_BUCKET_PREFIX}{base_name}{suffix}{ext}"

            meta = {
                "text_v": audit["text_verdict"],
                "like_v": audit["likeness_verdict"],
                "clip_v": audit["clip_verdict"],
                "clip_reason": _http_safe(audit["clip_reason"]),
                "upload_time": datetime.now(timezone.utc).isoformat(),
            }
            s3.put_object(
                Bucket=S3_ISSUE_BUCKET,
                Key=issue_key,
                Body=img_bytes,
                ContentType=content_type,
                Metadata={k: _http_safe(v) for k, v in meta.items()},
            )
            s3.delete_object(Bucket=S3_TEMP_BUCKET, Key=key)
            logger.info("Rejected → %s/%s", S3_ISSUE_BUCKET, issue_key)
            return True

        # ---------- Bytescale conversion for passing images -----------------
        with requests.Session() as sess:
            resp = sess.post(
                BYTESCALE_UPLOAD_URL,
                headers={"Authorization": f"Bearer {BYTESCALE_API_KEY}"},
                files={"file": (filename, img_bytes, content_type)},
                timeout=60,
            )
        if resp.status_code != 200:
            logger.error("Bytescale upload failed (%s): %s", resp.status_code, resp.text[:300])
            return False

        file_url = next(
            (f["fileUrl"] for f in resp.json().get("files", []) if f["formDataFieldName"] == "file"),
            None,
        )
        if not file_url:
            logger.error("Bytescale response missing fileUrl")
            return False

        proc_url = file_url.replace("/raw/", "/image/") + "?f=webp&w=464&h=510&fit=crop&crop=smart"
        proc_bytes = requests.get(proc_url, timeout=60).content

        # second clip audit
        clip2_raw = gemini_single(CLIP_PROMPT, proc_bytes)
        clip2_v, clip2_reason = _verdict(clip2_raw)

        # Metadata
        processed_filename = f"{base_name.replace('-', '.')}.webp"
        upload_key = f"{S3_UPLOAD_BUCKET_PREFIX}{processed_filename}"
        meta_out = {
            "text_v": audit["text_verdict"],
            "like_v": audit["likeness_verdict"],
            "clip_v1": audit["clip_verdict"],
            "clip_v2": clip2_v,
            "clip_r2": _http_safe(clip2_reason),
            "upload_time": datetime.now(timezone.utc).isoformat(),
        }

        # Duplicate?
        try:
            s3.head_object(Bucket=S3_UPLOAD_BUCKET, Key=upload_key)
            is_dupe = True
        except ClientError:
            is_dupe = False

        target_bucket = S3_ISSUE_BUCKET if is_dupe else S3_UPLOAD_BUCKET
        target_key = (
            f"{S3_ISSUE_BUCKET_PREFIX}{base_name}_dupeUpload.webp" if is_dupe else upload_key
        )

        s3.put_object(
            Bucket=target_bucket,
            Key=target_key,
            Body=proc_bytes,
            ContentType="image/webp",
            Metadata={k: _http_safe(v) for k, v in meta_out.items()},
        )
        logger.info("Uploaded to %s/%s", target_bucket, target_key)

        # cleanup
        s3.delete_object(Bucket=S3_TEMP_BUCKET, Key=key)
        return True

    except Exception as exc:
        logger.error("Error processing %s: %s", key, exc)
        traceback.print_exc()
        return False

# ─── SCHEDULER ──────────────────────────────────────────────────────────────
def check_temp_bucket() -> None:
    logger.info("Scanning Temp bucket …")
    try:
        resp = s3.list_objects_v2(Bucket=S3_TEMP_BUCKET, Prefix=S3_TEMP_BUCKET_PREFIX)
        objs = resp.get("Contents", [])
        imgs = [o for o in objs if o["Key"].lower().endswith((".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"))]
        if not imgs:
            logger.info("No images to process.")
            return
        logger.info("Found %d image(s)", len(imgs))
        for o in imgs:
            process_image(o["Key"])
    except Exception as exc:
        logger.error("Temp-bucket scan failed: %s", exc)
        traceback.print_exc()


def run_scheduler() -> None:
    logger.info("Bytescale worker started (checks every 30 s)")
    check_temp_bucket()  # immediate run
    schedule.every(30).seconds.do(check_temp_bucket)
    while True:
        schedule.run_pending()
        time.sleep(1)

# ─── ENTRY ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        run_scheduler()
    except KeyboardInterrupt:
        logger.info("Exiting (Ctrl-C)")
    except Exception as exc:
        logger.error("Fatal error: %s", exc)
        traceback.print_exc()