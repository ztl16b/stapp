#!/usr/bin/env python3
"""
bytescale_worker.py — sequential Gemini audits (dynamic alias/category lookup)

Runs as a Heroku worker dyno. Workflow:
1. Pull raw images from *S3_TEMP_BUCKET*.
2. Text audit  → Gemini (key 1) – if reject ➜ Issue bucket ("_text").
3. Likeness    → Gemini (key 2) – if reject ➜ Issue bucket ("_likeness").
4. Clip audit  (original)  → Gemini (key AY) – metadata clip_1.
5. Bytescale   → convert to 464×510 WebP.
6. Clip audit  (WebP)      → Gemini (key AY) – metadata clip_2.
7. Save to Upload bucket (or Issue bucket on dup / fail).

Prompts are defined below as placeholders for brevity.
"""

from __future__ import annotations
import base64, csv, logging, os, re, sys, time, traceback
from datetime import datetime, timezone
from io import StringIO
from typing import Dict, Tuple

import boto3                                # type: ignore
import google.generativeai as genai         # type: ignore
import requests                             # type: ignore
import schedule                             # type: ignore
from botocore.exceptions import ClientError # type: ignore
from dotenv import load_dotenv              # type: ignore

load_dotenv()

# ─────────────────────────── ENV ────────────────────────────────────────────
AWS_ACCESS_KEY_ID       = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY   = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION              = os.getenv("AWS_REGION")

S3_TEMP_BUCKET          = os.getenv("S3_TEMP_BUCKET")
S3_TEMP_BUCKET_PREFIX   = os.getenv("S3_TEMP_BUCKET_PREFIX", "")

S3_UPLOAD_BUCKET        = os.getenv("S3_UPLOAD_BUCKET")
S3_UPLOAD_BUCKET_PREFIX = os.getenv("S3_UPLOAD_BUCKET_PREFIX", "")

S3_ISSUE_BUCKET         = os.getenv("S3_ISSUE_BUCKET")
S3_ISSUE_BUCKET_PREFIX  = os.getenv("S3_ISSUE_BUCKET_PREFIX", "")

#  NEW: resources bucket + CSV key
S3_RESOURCES_BUCKET     = os.getenv("S3_RESOURCES_BUCKET")
PERFORMER_META_CSV_KEY  = os.getenv("PERFORMER_META_CSV_KEY")  # e.g. "lookups/performers.csv"

BYTESCALE_API_KEY       = os.getenv("BYTESCALE_API_KEY")
BYTESCALE_UPLOAD_URL    = os.getenv("BYTESCALE_UPLOAD_URL")

# ── Gemini keys (rotated by audit step) ─────────────────────────────────────
GEMINI_API_KEY          = os.getenv("GEMINI_API_KEY")      # text audit
GEMINI_API_KEY_2        = os.getenv("GEMINI_API_KEY_2")    # likeness audit
GEMINI_API_KEY_AY       = os.getenv("GEMINI_API_KEY_AY")   # clip audits

GEMINI_MODEL_ID         = os.getenv("GEMINI_MODEL_ID", "gemini-2.5-pro-preview-05-06")

REQUIRED_VARS = (
    AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION,
    S3_TEMP_BUCKET, S3_UPLOAD_BUCKET, S3_ISSUE_BUCKET,
    S3_RESOURCES_BUCKET, PERFORMER_META_CSV_KEY,
    BYTESCALE_API_KEY, BYTESCALE_UPLOAD_URL,
    GEMINI_API_KEY, GEMINI_API_KEY_2, GEMINI_API_KEY_AY,
)
if not all(REQUIRED_VARS):
    logging.error("Missing one or more required environment variables; exiting.")
    sys.exit(1)

# ─────────────────────── PROMPTS (placeholders) ─────────────────────────────
TEXT_PROMPT = """<TEXT_AUDIT_PROMPT>"""

LIKENESS_PROMPT = """<LIKENESS_AUDIT_PROMPT>"""

CLIP_PROMPT = """<CLIP_AUDIT_PROMPT>"""

# ───────────────────────── LOGGING ──────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("bytescale_worker")

# ──────────────────────── CLIENTS / INIT ────────────────────────────────────
s3 = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION,
)

# (No global genai.configure — we set per‑call)

# ─────────────────────── LOAD PERFORMER LOOK‑UP ─────────────────────────────

def _load_performer_csv() -> dict[str, tuple[str, str]]:
    """Return {performer_id: (name_alias, category_name)}."""
    try:
        obj = s3.get_object(Bucket=S3_RESOURCES_BUCKET, Key=PERFORMER_META_CSV_KEY)
        csv_text = obj["Body"].read().decode()
        reader = csv.DictReader(StringIO(csv_text))
        table: dict[str, tuple[str, str]] = {}
        for row in reader:
            pid = row.get("performer_id", "").strip()
            alias = row.get("name_alias", "").strip()
            cat   = row.get("category_name", "").strip()
            if pid:
                table[pid] = (alias, cat)
        logger.info("Loaded %d performer rows from %s/%s", len(table), S3_RESOURCES_BUCKET, PERFORMER_META_CSV_KEY)
        return table
    except Exception as e:
        logger.error("Failed to load performer CSV: %s", e)
        return {}

PERFORMER_INFO = _load_performer_csv()

# ───────────────────────── HELPERS ──────────────────────────────────────────

def _http_safe(txt: str, n: int = 250) -> str:
    return re.sub(r"\s{2,}", " ", txt.encode("ascii", "ignore").decode().replace("\n", " ").replace("\r", " "))[:n]


def _img_part(b: bytes, mime: str = "image/jpeg") -> Dict[str, str]:
    return {"mime_type": mime, "data": base64.b64encode(b).decode()}


def _gemini(prompt_tmpl: str, img: bytes, tag: str,
            alias: str, category: str, api_key: str) -> str:
    """Send an image+prompt to Gemini using the provided *api_key*."""
    prompt = prompt_tmpl.format(name_alias=alias or "N/A", category_name=category or "N/A")
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(GEMINI_MODEL_ID)
        resp_txt = model.generate_content([{"text": prompt}, _img_part(img)]).text.strip()
        logger.info("Gemini %s response:\n%s", tag, resp_txt)
        return resp_txt
    except Exception as e:
        logger.error("Gemini error during %s audit: %s", tag, e)
        return ""


def _verdict(raw: str) -> Tuple[str, str]:
    m = re.search(r"VERDICT\s*:\s*(APPROVE|REJECT|PASS|FAIL)", raw, re.I)
    verdict = (m.group(1).upper() if m else "UNKNOWN")
    verdict = "APPROVE" if verdict in ("APPROVE", "PASS") else (
              "REJECT"  if verdict in ("REJECT", "FAIL") else verdict)
    reason = _http_safe(re.search(r"REASON\s*:\s*(.+)", raw, re.I | re.S).group(1)) if re.search(r"REASON\s*:", raw, re.I) else ""
    return verdict, reason


def _extract_performer_id(fname: str) -> str:
    m = re.match(r"(\d+)", fname)
    return m.group(1) if m else ""

# ───────────────────── PROCESS IMAGE ───────────────────────────────────────

def process_image(key: str) -> bool:
    try:
        filename = key.rsplit("/", 1)[-1]
        base, ext = os.path.splitext(filename)
        logger.info("→ %s", filename)

        # look‑up alias & category
        pid = _extract_performer_id(base)
        alias, category = PERFORMER_INFO.get(pid, ("", ""))
        if not alias and not category:
            logger.warning("Performer ID %s not found in CSV; using blanks.", pid)

        obj = s3.get_object(Bucket=S3_TEMP_BUCKET, Key=key)
        img_bytes: bytes = obj["Body"].read()
        ctype = obj.get("ContentType", "image/jpeg")

        # 1) TEXT AUDIT – GEMINI_API_KEY
        text_raw = _gemini(TEXT_PROMPT, img_bytes, "TEXT", alias, category, GEMINI_API_KEY)
        text_v, text_r = _verdict(text_raw)
        if text_v != "APPROVE":
            _to_issue(img_bytes, ctype, base + "_text" + ext, {"text_v": text_v, "text_r": text_r})
            s3.delete_object(Bucket=S3_TEMP_BUCKET, Key=key)
            return True

        # 2) LIKENESS AUDIT – GEMINI_API_KEY_2
        like_raw = _gemini(LIKENESS_PROMPT, img_bytes, "LIKENESS", alias, category, GEMINI_API_KEY_2)
        like_v, like_r = _verdict(like_raw)
        if like_v != "APPROVE":
            _to_issue(img_bytes, ctype, base + "_likeness" + ext,
                      {"text_v": text_v, "like_v": like_v, "like_r": like_r})
            s3.delete_object(Bucket=S3_TEMP_BUCKET, Key=key)
            return True

        # 3) CLIP‑1 AUDIT – GEMINI_API_KEY_AY
        clip1_raw = _gemini(CLIP_PROMPT, img_bytes, "CLIP-1", alias, category, GEMINI_API_KEY_AY)
        clip1_v, clip1_r = _verdict(clip1_raw)

        # 4) BYTESCALE CONVERT
        webp_bytes = _bytescale_convert(filename, img_bytes, ctype)
        if not webp_bytes:
            return False

        # 5) CLIP‑2 AUDIT – GEMINI_API_KEY_AY
        clip2_raw = _gemini(CLIP_PROMPT, webp_bytes, "CLIP-2", alias, category, GEMINI_API_KEY_AY)
        clip2_v, clip2_r = _verdict(clip2_raw)

        # 6) SAVE (dup‑aware)
        processed_name = f"{base.replace('-', '.')}\.webp"
        upload_key = f"{S3_UPLOAD_BUCKET_PREFIX}{processed_name}"
        duplicate = _object_exists(S3_UPLOAD_BUCKET, upload_key)

        bucket  = S3_ISSUE_BUCKET if duplicate else S3_UPLOAD_BUCKET
        key_out = (f"{S3_ISSUE_BUCKET_PREFIX}{base}_dupeUpload.webp" if duplicate else upload_key)

        meta = {
            "text_v": text_v,  "like_v": like_v,
            "clip1_v": clip1_v, "clip2_v": clip2_v,
            "clip1_r": clip1_r, "clip2_r": clip2_r,
            "upload_time": datetime.now(timezone.utc).isoformat(),
            "name_alias": _http_safe(alias), "category": _http_safe(category),
        }

        s3.put_object(
            Bucket=bucket,
            Key=key_out,
            ACL="public-read",
            ContentDisposition="inline",
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

    # Determine content type for the S3 upload
    upload_content_type = ctype
    file_extension = os.path.splitext(keyname)[1].lower()

    if upload_content_type == "application/octet-stream" or (
        ctype == "image/jpeg" and file_extension not in [".jpg", ".jpeg", ""]):
        upload_content_type = {
            ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
            ".png": "image/png",  ".gif": "image/gif",
            ".webp": "image/webp", ".bmp": "image/bmp",
        }.get(file_extension, upload_content_type)

    s3.put_object(
        Bucket=S3_ISSUE_BUCKET,
        Key=f"{S3_ISSUE_BUCKET_PREFIX}{keyname}",
        ACL="public-read",
        ContentDisposition="inline",
        Body=body,
        ContentType=upload_content_type,
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
    objs = [o["Key"] for o in resp.get("Contents", []) if o["Key"].lower().endswith((
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"))]
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
