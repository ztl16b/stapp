#!/usr/bin/env python3
"""
sync_ids_worker.py
──────────────────────────────────────────────────────────────────────────────
Keeps `completed_performers.txt` in the RESOURCES bucket up-to-date by
scanning *.webp images in the PERFORMERS bucket.  Runs once at start-up
and then on a schedule (default: every 30 min).

• Local dev:  put a .env alongside this file (or any parent dir) and run
      $ python sync_ids_worker.py --once --dry-run
  The loader fills env vars that aren’t already set.

• Heroku / prod: Heroku’s config vars are already in $ENV, so the .env
  (usually absent) is ignored.
"""

from __future__ import annotations
import argparse, os, sys, time, logging
import schedule                     # type: ignore
from pathlib import Path
from botocore.config import Config  # type: ignore
import boto3                        # type: ignore
from botocore.exceptions import ClientError  # type: ignore
from dotenv import load_dotenv, find_dotenv  # type: ignore

# ─── Load .env for local runs (but don’t override existing vars) ────────────
dotenv_path = find_dotenv(usecwd=True)  # walk up from CWD
if dotenv_path:
    load_dotenv(dotenv_path=dotenv_path, override=False)
    print(f"[dotenv] Loaded variables from {Path(dotenv_path).relative_to(Path.cwd())}")

# ─── Configuration ──────────────────────────────────────────────────────────
PERFORMERS_BUCKET   = os.getenv("S3_PERFORMER_BUCKET")
PERFORMERS_PREFIX   = os.getenv("S3_PERFORMER_BUCKET_PREFIX", "").lstrip("/")
RESOURCES_BUCKET    = os.getenv("S3_RESOURCES_BUCKET")
OUTPUT_FILE_KEY     = os.getenv("COMPLETED_IDS_KEY", "temp/completed_performers.txt")
INTERVAL_SEC        = int(os.getenv("SYNC_INTERVAL_SECONDS", "1800"))  # 30 min default

if not (PERFORMERS_BUCKET and RESOURCES_BUCKET):
    sys.exit("ERROR: S3_PERFORMER_BUCKET and S3_RESOURCES_BUCKET must be set")

# ─── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("sync_ids_worker")

# ─── Boto3 client (uses env credentials) ────────────────────────────────────
_s3 = boto3.client(
    "s3",
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    aws_session_token=os.getenv("AWS_SESSION_TOKEN"),
    config=Config(retries={"max_attempts": 10, "mode": "standard"}),
)

# ─── Helpers ────────────────────────────────────────────────────────────────
IMG_EXTS = (".webp",)  # extend if needed

def yield_performer_ids():
    paginator = _s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=PERFORMERS_BUCKET, Prefix=PERFORMERS_PREFIX):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.lower().endswith(IMG_EXTS):
                pid = key.rsplit("/", 1)[-1].rsplit(".", 1)[0]
                if pid.isdigit():
                    yield pid

def load_completed_ids() -> set[str]:
    try:
        obj = _s3.get_object(Bucket=RESOURCES_BUCKET, Key=OUTPUT_FILE_KEY)
        return {ln.strip() for ln in obj["Body"].read().decode().splitlines() if ln.strip()}
    except _s3.exceptions.NoSuchKey:
        log.info("No existing %s/%s (will create).", RESOURCES_BUCKET, OUTPUT_FILE_KEY)
        return set()
    except ClientError as e:
        log.error("Could not read %s/%s: %s", RESOURCES_BUCKET, OUTPUT_FILE_KEY, e)
        return set()

def save_completed_ids(all_ids: set[str]):
    body = "\n".join(sorted(all_ids)) + "\n"
    _s3.put_object(
        Bucket=RESOURCES_BUCKET,
        Key=OUTPUT_FILE_KEY,
        Body=body.encode(),
        ACL="public-read",
        ContentDisposition="inline",
        ContentType="text/plain",
    )
    log.info("Uploaded list (%d IDs) → s3://%s/%s", len(all_ids), RESOURCES_BUCKET, OUTPUT_FILE_KEY)

def sync_once(*, dry_run: bool = False):
    log.info("Scanning s3://%s/%s …", PERFORMERS_BUCKET, PERFORMERS_PREFIX or "")
    existing = load_completed_ids()
    added = 0
    for pid in yield_performer_ids():
        if pid not in existing:
            existing.add(pid)
            added += 1

    if added == 0:
        log.info("Nothing new – list already current (%d IDs).", len(existing))
        return

    log.info("Found %d new IDs (total %d).", added, len(existing))
    if dry_run:
        log.info("--dry-run: not uploading changes.")
    else:
        save_completed_ids(existing)

# ─── Scheduler loop ────────────────────────────────────────────────────────
def run_scheduler():
    log.info("Initial sync …")
    sync_once()
    log.info("Worker up – polling every %d s", INTERVAL_SEC)
    schedule.every(INTERVAL_SEC).seconds.do(sync_once)
    while True:
        schedule.run_pending()
        time.sleep(1)

# ─── CLI ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Sync completed_performers list")
    ap.add_argument("--dry-run", action="store_true", help="scan & diff, but do not write")
    ap.add_argument("--once",    action="store_true", help="run one sync pass and exit")
    args = ap.parse_args()

    try:
        if args.once:
            sync_once(dry_run=args.dry_run)
        else:
            if args.dry_run:
                schedule.every(INTERVAL_SEC).seconds.do(sync_once, dry_run=True)
                log.info("Dry-run mode – no writes will occur.")
            run_scheduler()
    except KeyboardInterrupt:
        log.info("Shutdown.")