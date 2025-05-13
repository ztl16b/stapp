#!/usr/bin/env python3
"""
bytescale_worker.py — sequential Gemini audits
──────────────────────────────────────────────────────────────────────────────
1. Text audit  → if Reject ➜ Issue bucket (_text)
2. Likeness    → if Reject ➜ Issue bucket (_likeness)
3. Clip audit  (original)  ➜ clip_1 metadata
4. Bytescale convert (WebP)
5. Clip audit  (WebP)      ➜ clip_2 metadata
Duplicates still routed to Issue bucket (_dupeUpload.webp)
"""

from __future__ import annotations

import base64, logging, os, re, sys, time, traceback
from datetime import datetime, timezone
from typing import Dict, Tuple

import boto3                 # type: ignore
import google.generativeai as genai   # type: ignore
import requests               # type: ignore
import schedule               # type: ignore
from botocore.exceptions import ClientError  # type: ignore
from dotenv import load_dotenv  # type: ignore

# ─────────────────────────── ENV ────────────────────────────────────────────
load_dotenv()

AWS_ACCESS_KEY_ID       = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY   = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION              = os.getenv("AWS_REGION")

S3_TEMP_BUCKET          = os.getenv("S3_TEMP_BUCKET")
S3_TEMP_BUCKET_PREFIX   = os.getenv("S3_TEMP_BUCKET_PREFIX", "")

S3_UPLOAD_BUCKET        = os.getenv("S3_UPLOAD_BUCKET")
S3_UPLOAD_BUCKET_PREFIX = os.getenv("S3_UPLOAD_BUCKET_PREFIX", "")

S3_ISSUE_BUCKET         = os.getenv("S3_ISSUE_BUCKET")
S3_ISSUE_BUCKET_PREFIX  = os.getenv("S3_ISSUE_BUCKET_PREFIX", "")

BYTESCALE_API_KEY       = os.getenv("BYTESCALE_API_KEY")
BYTESCALE_UPLOAD_URL    = os.getenv("BYTESCALE_UPLOAD_URL")

GEMINI_API_KEY          = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL_ID         = os.getenv("GEMINI_MODEL_ID", "gemini-2.5-pro-preview-05-06")

# ─────────────────────── PROMPTS (short-form here) ──────────────────────────
TEXT_PROMPT     = "... your full text prompt ..."
LIKENESS_PROMPT = "... your full likeness prompt ..."
CLIP_PROMPT     = "... your full clip prompt ..."

# ───────────────────────── LOGGING ──────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("bytescale_worker")

# ──────────────────────── CLIENTS / INIT ────────────────────────────────────
for var in (
    AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION,
    S3_TEMP_BUCKET, S3_UPLOAD_BUCKET, S3_ISSUE_BUCKET,
    BYTESCALE_API_KEY, BYTESCALE_UPLOAD_URL, GEMINI_API_KEY
):
    if not var:
        logger.error("Required env var missing. Exiting.")
        sys.exit(1)

s3 = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION,
)

genai.configure(api_key=GEMINI_API_KEY)
GEMINI = genai.GenerativeModel(GEMINI_MODEL_ID)

# ───────────────────────── HELPERS ──────────────────────────────────────────
def _http_safe(txt: str, n: int = 250) -> str:
    return re.sub(r"\s{2,}", " ", txt.encode("ascii", "ignore").decode()
                  .replace("\n", " ").replace("\r", " "))[:n]

def _img_part(b: bytes, mime="image/jpeg") -> Dict[str, str]:
    return {"mime_type": mime, "data": base64.b64encode(b).decode()}

def _gemini(prompt: str, img: bytes) -> str:
    try:
        return GEMINI.generate_content([{"text": prompt}, _img_part(img)]).text.strip()
    except Exception as e:
        logger.error("Gemini error: %s", e)
        return ""

def _verdict(raw: str) -> Tuple[str, str]:
    m = re.search(r"VERDICT\s*:\s*(APPROVE|REJECT|PASS|FAIL)", raw, re.I)
    verdict = (m.group(1).upper() if m else "UNKNOWN")
    verdict = "APPROVE" if verdict in ("APPROVE", "PASS") else "REJECT" if verdict in ("REJECT", "FAIL") else verdict
    reason  = _http_safe(re.search(r"REASON\s*:\s*(.+)", raw, re.I | re.S).group(1)) if re.search(r"REASON\s*:", raw, re.I) else ""
    return verdict, reason

# ─────────────────────── PROCESS IMAGE ──────────────────────────────────────
def process_image(key: str) -> bool:
    try:
        filename = key.split("/")[-1]
        base, ext = os.path.splitext(filename)
        logger.info("→ %s", filename)

        obj   = s3.get_object(Bucket=S3_TEMP_BUCKET, Key=key)
        bytes_orig: bytes = obj["Body"].read()
        ctype = obj.get("ContentType", "image/jpeg")

        # 1) TEXT AUDIT
        raw_text = _gemini(TEXT_PROMPT, bytes_orig)
        text_v, text_r = _verdict(raw_text)
        if text_v != "APPROVE":
            _to_issue(bytes_orig, ctype, base + "_text" + ext,
                      {"text_v": text_v, "text_r": text_r})
            s3.delete_object(Bucket=S3_TEMP_BUCKET, Key=key)
            return True

        # 2) LIKENESS AUDIT
        raw_like = _gemini(LIKENESS_PROMPT, bytes_orig)
        like_v, like_r = _verdict(raw_like)
        if like_v != "APPROVE":
            _to_issue(bytes_orig, ctype, base + "_likeness" + ext,
                      {"text_v": text_v, "like_v": like_v, "like_r": like_r})
            s3.delete_object(Bucket=S3_TEMP_BUCKET, Key=key)
            return True

        # 3) CLIP-1
        raw_clip1 = _gemini(CLIP_PROMPT, bytes_orig)
        clip1_v, clip1_r = _verdict(raw_clip1)

        # 4) BYTESCALE CONVERT
        webp_bytes = _bytescale_convert(filename, bytes_orig, ctype)
        if not webp_bytes:
            return False

        # 5) CLIP-2
        raw_clip2 = _gemini(CLIP_PROMPT, webp_bytes)
        clip2_v, clip2_r = _verdict(raw_clip2)

        # 6) SAVE (dup-aware)
        processed_name = f"{base.replace('-', '.')}.webp"
        upload_key = f"{S3_UPLOAD_BUCKET_PREFIX}{processed_name}"
        duplicate = _object_exists(S3_UPLOAD_BUCKET, upload_key)

        bucket = S3_ISSUE_BUCKET if duplicate else S3_UPLOAD_BUCKET
        key_out = (f"{S3_ISSUE_BUCKET_PREFIX}{base}_dupeUpload.webp"
                   if duplicate else upload_key)

        meta = {
            "text_v": text_v,
            "like_v": like_v,
            "clip1_v": clip1_v,
            "clip2_v": clip2_v,
            "clip1_r": clip1_r,
            "clip2_r": clip2_r,
            "upload_time": datetime.now(timezone.utc).isoformat(),
        }

        s3.put_object(
            Bucket=bucket,
            Key=key_out,
            Body=webp_bytes,
            ContentType="image/webp",
            Metadata={k: _http_safe(v) for k, v in meta.items()},
        )
        logger.info("✓ Stored in %s/%s", bucket, key_out)

        s3.delete_object(Bucket=S3_TEMP_BUCKET, Key=key)
        return True

    except Exception as e:
        logger.error("Process failed: %s", e)
        traceback.print_exc()
        return False

# ───────────── helper: upload to Issue bucket ─────────────
def _to_issue(body: bytes, ctype: str, keyname: str, extra_meta: Dict[str, str]) -> None:
    meta = {**extra_meta, "upload_time": datetime.now(timezone.utc).isoformat()}
    s3.put_object(
        Bucket=S3_ISSUE_BUCKET,
        Key=f"{S3_ISSUE_BUCKET_PREFIX}{keyname}",
        Body=body,
        ContentType=ctype,
        Metadata={k: _http_safe(v) for k, v in meta.items()},
    )
    logger.info("Rejected → %s/%s", S3_ISSUE_BUCKET, keyname)

# ───────────── helper: Bytescale conversion ─────────────
def _bytescale_convert(name: str, data: bytes, ctype: str) -> bytes | None:
    r = requests.post(
        BYTESCALE_UPLOAD_URL,
        headers={"Authorization": f"Bearer {BYTESCALE_API_KEY}"},
        files={"file": (name, data, ctype)},
        timeout=60,
    )
    if r.status_code != 200:
        logger.error("Bytescale upload error %s", r.status_code)
        return None
    url = next((f["fileUrl"] for f in r.json()["files"] if f["formDataFieldName"] == "file"), "")
    if not url:
        logger.error("Bytescale response missing fileUrl.")
        return None
    img_url = url.replace("/raw/", "/image/") + "?f=webp&w=464&h=510&fit=crop&crop=smart"
    return requests.get(img_url, timeout=60).content

# ───────────── helper: object exists ─────────────
def _object_exists(bucket: str, key: str) -> bool:
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError:
        return False

# ───────────────── SCHEDULER LOOP ─────────────────
def _scan():
    resp = s3.list_objects_v2(Bucket=S3_TEMP_BUCKET, Prefix=S3_TEMP_BUCKET_PREFIX)
    objs = [o["Key"] for o in resp.get("Contents", [])
            if o["Key"].lower().endswith((".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"))]
    if not objs:
        return
    logger.info("Scanning %d object(s)", len(objs))
    for k in objs:
        process_image(k)

def run():
    logger.info("Worker up – polling every 30 s")
    _scan()
    schedule.every(30).seconds.do(_scan)
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        logger.info("Shutdown.")