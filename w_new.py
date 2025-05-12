#!/usr/bin/env python3
"""
audit_and_reformat_worker.py
────────────────────────────
• Watches the *Temp* S3 bucket for new images.
• **Step 1 – Audit (Gemini):**
  ─ Runs TEXT & LIKENESS prompts on Gemini-Flash.  
  ─ If either verdict is “Reject” (or unknown) → moves the original image to
    *Issue* bucket with “_auditFail” suffix; responses stored in metadata.  
  ─ If both verdicts are “Approve” → runs CLIP prompt on Gemini-Pro.  
    ▸ Full CLIP response is written to the “clip_audit” metadata key
      (truncated < 2 KB).
• **Step 2 – Reformat (Bytescale):**
  ─ Sends the (still-approved) image to Bytescale → 464 × 510 smart-crop WebP.  
  ─ Duplicate-checks the *Upload* bucket.  
    ▸ If duplicate → routes to *Issue* bucket with “_dupeUpload.webp”.  
    ▸ Else → saves to *Upload* bucket.  
  ─ Adds all audit metadata to the uploaded object.
• Deletes the original from *Temp* once processing completes.
• Runs every 30 s.

Required ENV
────────────
AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION
S3_TEMP_BUCKET, S3_UPLOAD_BUCKET, S3_ISSUE_BUCKET
BYTESCALE_API_KEY, BYTESCALE_UPLOAD_URL
GEMINI_API_KEY

Optional ENV
────────────
S3_*_BUCKET_PREFIX, PERFORMER_CSV
"""

from __future__ import annotations

import io
import logging
import os
import re
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, Tuple

import boto3                                # type: ignore
import pandas as pd                         # type: ignore
import requests                             # type: ignore
import schedule                             # type: ignore
from PIL import Image                       # type: ignore
from dotenv import load_dotenv              # type: ignore
from google import genai                    # type: ignore
from google.genai.types import (            # type: ignore
    Tool,
    GenerateContentConfig,
    GoogleSearch,
)

# ─── HARD-CODED PROMPTS ────────────────────────────────────────────────────
TEXT_PROMPT = """
# ——— TEXT AUDIT : unwanted text & overlays ———
Subject : "{name_alias}"
Event   : {category_name}

Check the image for any textual elements such as watermarks, logos,
headlines, or captions.

SCORING & VERDICT
• If ANY text is visible → **Verdict = Reject**.
• If NO text is visible → **Verdict = Approve**.

OUTPUT — EXACT FORMAT
Verdict: <Approve|Reject>
""".strip()

LIKENESS_PROMPT = """
# ——— LIKENESS AUDIT : performer identity ———
Subject : "{name_alias}"
Event   : {category_name}

Determine whether the person in the photo is unmistakably the named
performer. Focus on facial structure, age, hairline, tattoos, and other
unique markers.

SCORING & VERDICT
• Clearly same person    → **Verdict = Approve**
• Unclear or mismatch    → **Verdict = Reject**

OUTPUT — EXACT FORMAT
Verdict: <Approve|Reject>
""".strip()

CLIP_PROMPT = """
# ——— CLIPPING AUDIT : limbs vs. solid objects ———
Detect one thing only: **body parts passing THROUGH solid, opaque objects.**

Subject : "{name_alias}"
Event   : {category_name}

INSTRUCTIONS (silent reasoning)
1. For every visible limb or body segment, trace its outline.
2. If that outline disappears and re-emerges INSIDE (or beyond) a solid
   object with no gap → this is CLIPPING.
3. When unsure, assume clipping exists.

SCORING & VERDICT
• If ANY clipping found → **Verdict = Reject**
• If NO clipping         → **Verdict = Approve**

OUTPUT — EXACT FORMAT
Verdict: <Approve|Reject>
""".strip()

# ─── ENV / INIT ────────────────────────────────────────────────────────────
load_dotenv()

AWS_ACCESS_KEY_ID       = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY   = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION              = os.getenv("AWS_REGION")

S3_TEMP_BUCKET          = os.getenv("S3_TEMP_BUCKET")
S3_TEMP_PREFIX          = os.getenv("S3_TEMP_BUCKET_PREFIX", "")

S3_UPLOAD_BUCKET        = os.getenv("S3_UPLOAD_BUCKET")
S3_UPLOAD_PREFIX        = os.getenv("S3_UPLOAD_BUCKET_PREFIX", "")

S3_ISSUE_BUCKET         = os.getenv("S3_ISSUE_BUCKET")
S3_ISSUE_PREFIX         = os.getenv("S3_ISSUE_BUCKET_PREFIX", "")

BYTESCALE_API_KEY       = os.getenv("BYTESCALE_API_KEY")
BYTESCALE_UPLOAD_URL    = os.getenv("BYTESCALE_UPLOAD_URL")

GEMINI_API_KEY          = os.getenv("GEMINI_API_KEY")
MODEL_FLASH_ID          = "gemini-2.0-flash"
MODEL_PRO_ID            = "gemini-2.5-pro-preview-03-25"

PERFORMER_CSV_PATH      = os.getenv("PERFORMER_CSV")   # Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s",
    handlers=[logging.StreamHandler()]
)
log = logging.getLogger("audit_reformat_worker")

# ─── ENV VALIDATION ────────────────────────────────────────────────────────
required = {
    "AWS_ACCESS_KEY_ID"     : AWS_ACCESS_KEY_ID,
    "AWS_SECRET_ACCESS_KEY" : AWS_SECRET_ACCESS_KEY,
    "AWS_REGION"            : AWS_REGION,
    "S3_TEMP_BUCKET"        : S3_TEMP_BUCKET,
    "S3_UPLOAD_BUCKET"      : S3_UPLOAD_BUCKET,
    "S3_ISSUE_BUCKET"       : S3_ISSUE_BUCKET,
    "BYTESCALE_API_KEY"     : BYTESCALE_API_KEY,
    "BYTESCALE_UPLOAD_URL"  : BYTESCALE_UPLOAD_URL,
    "GEMINI_API_KEY"        : GEMINI_API_KEY,
}
missing = [k for k, v in required.items() if not v]
if missing:
    log.error("Missing required env vars: %s", ", ".join(missing))
    sys.exit(1)

# ─── PERFORMER LOOKUP (optional) ───────────────────────────────────────────
performer_data: Dict[str, Dict[str, str]] = {}
if PERFORMER_CSV_PATH:
    try:
        df = pd.read_csv(
            PERFORMER_CSV_PATH,
            dtype={"performer_id": str},
            usecols=["performer_id", "name_alias", "category_name"],
        )
        performer_data = {
            r.performer_id: {
                "name_alias": r.name_alias,
                "category_name": r.category_name,
            }
            for _, r in df.iterrows()
        }
        log.info("Loaded %d performer records", len(performer_data))
    except Exception as exc:
        log.warning("Unable to read performer CSV (%s): %s – continuing.", PERFORMER_CSV_PATH, exc)

# ─── GEMINI CLIENT ─────────────────────────────────────────────────────────
search_tool   = Tool(google_search=GoogleSearch())
GEN_CONFIG    = GenerateContentConfig(tools=[search_tool])
client        = genai.Client(api_key=GEMINI_API_KEY)

VERDICT_RE = re.compile(r"(?i)^Verdict:\s*(Approve|Reject)\b", re.MULTILINE)

def extract_verdict(text: str | None) -> str:
    if not text:
        return "Unknown"
    m = VERDICT_RE.search(text)
    return m.group(1) if m else "Unknown"

def call_gemini(model: str, prompt: str, img: Image.Image) -> str:
    try:
        resp = client.models.generate_content(
            model   = model,
            contents= [prompt, img],
            config  = GEN_CONFIG,
        )
        return resp.text.strip()
    except Exception as exc:
        return f"API error: {exc}"

def run_audit(file_bytes: bytes, performer_id: str) -> Tuple[bool, Dict[str, str]]:
    rec       = performer_data.get(performer_id, {})
    alias     = rec.get("name_alias", "Unknown performer")
    category  = rec.get("category_name", "Unknown category")

    try:
        img = Image.open(io.BytesIO(file_bytes))
        if img.mode not in ("RGB", "RGBA"):
            img = img.convert("RGB")
    except Exception as exc:
        return False, {"audit_error": f"Image read error: {exc}"}

    # Flash audits
    text_resp = call_gemini(
        MODEL_FLASH_ID,
        TEXT_PROMPT.format(name_alias=alias, category_name=category),
        img,
    )
    likeness_resp = call_gemini(
        MODEL_FLASH_ID,
        LIKENESS_PROMPT.format(name_alias=alias, category_name=category),
        img,
    )

    verdict_text     = extract_verdict(text_resp)
    verdict_likeness = extract_verdict(likeness_resp)

    md: Dict[str, str] = {
        "text_audit"       : text_resp[:1900],
        "likeness_audit"   : likeness_resp[:1900],
        "verdict_text"     : verdict_text,
        "verdict_likeness" : verdict_likeness,
    }

    if verdict_text != "Approve" or verdict_likeness != "Approve":
        md["audit_result"] = "Fail"
        return False, md

    # Pro clipping audit
    clip_resp = call_gemini(
        MODEL_PRO_ID,
        CLIP_PROMPT.format(name_alias=alias, category_name=category),
        img,
    )
    verdict_clip        = extract_verdict(clip_resp)
    md["clip_audit"]    = clip_resp[:1900]
    md["verdict_clip"]  = verdict_clip
    md["audit_result"]  = "Pass"
    return True, md

# ─── AWS S3 CLIENT ─────────────────────────────────────────────────────────
try:
    s3 = boto3.client(
        "s3",
        aws_access_key_id     = AWS_ACCESS_KEY_ID,
        aws_secret_access_key = AWS_SECRET_ACCESS_KEY,
        region_name           = AWS_REGION,
    )
    s3.list_buckets()
    log.info("Connected to S3")
except Exception as exc:
    log.error("S3 init failed: %s", exc)
    sys.exit(1)

# ─── PROCESSING ────────────────────────────────────────────────────────────
IMAGE_EXTS = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".heic", ".heif")

def process_key(key: str) -> None:
    filename = key.split("/")[-1]
    log.info("Processing %s", filename)
    try:
        obj        = s3.get_object(Bucket=S3_TEMP_BUCKET, Key=key)
        file_bytes = obj["Body"].read()
        if not file_bytes:
            log.error("Empty download – skipping.")
            return

        performer_id = filename.split(".")[0]  # before first '.'
        passed, audit_md = run_audit(file_bytes, performer_id)

        if not passed:
            issue_key = f"{S3_ISSUE_PREFIX}{filename.rsplit('.',1)[0]}_auditFail{os.path.splitext(filename)[1]}"
            s3.put_object(
                Bucket     = S3_ISSUE_BUCKET,
                Key        = issue_key,
                Body       = file_bytes,
                Metadata   = audit_md,
                ContentType= obj.get("ContentType", "image/jpeg"),
            )
            log.info("Audit failed – moved to %s/%s", S3_ISSUE_BUCKET, issue_key)
            s3.delete_object(Bucket=S3_TEMP_BUCKET, Key=key)
            return

        # Bytescale reformat
        up_resp = requests.post(
            BYTESCALE_UPLOAD_URL,
            headers={"Authorization": f"Bearer {BYTESCALE_API_KEY}"},
            files={"file": (filename, file_bytes, obj.get("ContentType", "image/jpeg"))},
            timeout=60,
        )
        if up_resp.status_code != 200:
            raise RuntimeError(f"Bytescale upload failed: {up_resp.text[:400]}")

        file_url = next(
            (f["fileUrl"] for f in up_resp.json().get("files", [])
             if f.get("formDataFieldName") == "file"),
            None,
        )
        if not file_url:
            raise RuntimeError("fileUrl missing in Bytescale response")

        proc_url = file_url.replace("/raw/", "/image/") + "?f=webp&w=464&h=510&fit=crop&crop=smart"
        processed_data = requests.get(proc_url, timeout=60).content
        if not processed_data:
            raise RuntimeError("Empty processed Bytescale image")

        base_name, _ = os.path.splitext(filename)
        processed_filename = f"{base_name.replace('-','.')}.webp"
        upload_key         = f"{S3_UPLOAD_PREFIX}{processed_filename}"

        is_dupe = False
        try:
            s3.head_object(Bucket=S3_UPLOAD_BUCKET, Key=upload_key)
            is_dupe = True
        except Exception:
            pass

        dest_bucket = S3_ISSUE_BUCKET if is_dupe else S3_UPLOAD_BUCKET
        dest_key    = (
            f"{S3_ISSUE_PREFIX}{base_name}_dupeUpload.webp" if is_dupe else upload_key
        )

        metadata: Dict[str, str] = {
            **obj.get("Metadata", {}),
            **audit_md,
            "upload_time": datetime.utcnow().isoformat(timespec="seconds"),
        }

        s3.put_object(
            Bucket     = dest_bucket,
            Key        = dest_key,
            Body       = processed_data,
            ContentType= "image/webp",
            Metadata   = metadata,
        )
        log.info("Uploaded to %s/%s", dest_bucket, dest_key)
        s3.delete_object(Bucket=S3_TEMP_BUCKET, Key=key)
        log.info("Deleted original %s", key)

    except Exception as exc:
        log.error("Error processing %s: %s", key, exc)
        traceback.print_exc()

def scan_temp() -> None:
    log.info("Scanning Temp bucket …")
    try:
        resp = s3.list_objects_v2(Bucket=S3_TEMP_BUCKET, Prefix=S3_TEMP_PREFIX)
        keys = [
            o["Key"] for o in resp.get("Contents", [])
            if o["Key"].lower().endswith(IMAGE_EXTS)
        ]
        if not keys:
            log.info("No images found.")
            return
        log.info("Found %d image(s)", len(keys))
        for k in keys:
            process_key(k)
    except Exception as exc:
        log.error("Temp scan failed: %s", exc)
        traceback.print_exc()

# ─── ENTRYPOINT ────────────────────────────────────────────────────────────
def run_scheduler() -> None:
    log.info("Worker started – checks every 30 s")
    scan_temp()
    schedule.every(30).seconds.do(scan_temp)
    while True:
        try:
            schedule.run_pending()
            time.sleep(1)
        except Exception as exc:
            log.error("Scheduler error: %s", exc)
            traceback.print_exc()
            time.sleep(30)

if __name__ == "__main__":
    try:
        run_scheduler()
    except KeyboardInterrupt:
        log.info("Exiting – Ctrl-C")
