#!/usr/bin/env python3
"""
sync_ids_worker.py
──────────────────────────────────────────────────────────────────────────────
1. Scan the PERFORMER bucket for every *.webp key → build a unique ID set.
2. Write that set to completed_performers.txt.
3. Load problem_performers.txt; if any IDs now appear in *completed*,
   remove them from the problem list and upload the shortened file.
4. Repeat every SYNC_INTERVAL_SECONDS (default: 1800 s).

Required env vars
─────────────────
AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY  ( + AWS_SESSION_TOKEN if needed )
S3_PERFORMER_BUCKET          – source bucket to scan
S3_RESOURCES_BUCKET          – bucket that stores the txt files

Optional
────────
S3_PERFORMER_BUCKET_PREFIX   – only consider keys under this prefix
COMPLETED_IDS_KEY            – key for completed list   (default temp/completed_performers.txt)
PROBLEM_IDS_KEY              – key for problem list     (default temp/problem_performers.txt)
SYNC_INTERVAL_SECONDS        – loop period in seconds   (default 1800 = 30 min)
"""

from __future__ import annotations
import os, sys, time, logging, schedule     # type: ignore
import boto3                                # type: ignore
from botocore.config import Config          # type: ignore
from botocore.exceptions import ClientError # type: ignore

# ─── Configuration ─────────────────────────────────────────────────────────
PERFORMERS_BUCKET  = os.getenv("S3_PERFORMER_BUCKET")
PERFORMERS_PREFIX  = os.getenv("S3_PERFORMER_BUCKET_PREFIX", "").lstrip("/")
RESOURCES_BUCKET   = os.getenv("S3_RESOURCES_BUCKET")

COMPLETED_KEY      = os.getenv("COMPLETED_IDS_KEY", "temp/completed_performers.txt")
PROBLEM_KEY        = os.getenv("PROBLEM_IDS_KEY",    "temp/problem_performers.txt")
INTERVAL_SEC       = int(os.getenv("SYNC_INTERVAL_SECONDS", "1800"))  # 30 min

if not (PERFORMERS_BUCKET and RESOURCES_BUCKET):
    sys.exit("ERROR: S3_PERFORMER_BUCKET and S3_RESOURCES_BUCKET must be set")

# ─── Logging ───────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("sync_ids_worker")

# ─── S3 client ─────────────────────────────────────────────────────────────
_s3 = boto3.client(
    "s3",
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    aws_session_token=os.getenv("AWS_SESSION_TOKEN"),
    config=Config(retries={"max_attempts": 10, "mode": "standard"}),
)

# ─── Helpers ───────────────────────────────────────────────────────────────
IMG_EXTS = (".webp",)  # add .jpg/.png if needed

def yield_performer_ids():
    paginator = _s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=PERFORMERS_BUCKET, Prefix=PERFORMERS_PREFIX):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.lower().endswith(IMG_EXTS):
                pid = key.rsplit("/", 1)[-1].rsplit(".", 1)[0]
                if pid.isdigit():
                    yield pid

def load_id_file(key: str) -> set[str]:
    try:
        obj = _s3.get_object(Bucket=RESOURCES_BUCKET, Key=key)
        return {ln.strip() for ln in obj["Body"].read().decode().splitlines() if ln.strip()}
    except _s3.exceptions.NoSuchKey:
        log.info("No existing %s/%s (will create).", RESOURCES_BUCKET, key)
        return set()
    except ClientError as e:
        log.error("Could not read %s/%s: %s", RESOURCES_BUCKET, key, e)
        return set()

def save_id_file(key: str, ids: set[str]):
    body = "\n".join(sorted(ids)) + "\n"
    _s3.put_object(
        Bucket=RESOURCES_BUCKET,
        Key=key,
        Body=body.encode(),
        ACL="public-read",
        ContentDisposition="inline",
        ContentType="text/plain",
    )
    log.info("Uploaded %s IDs → s3://%s/%s", len(ids), RESOURCES_BUCKET, key)

# ─── Sync Routine ──────────────────────────────────────────────────────────
def sync_once():
    # 1 & 2 — completed list
    log.info("Scanning s3://%s/%s …", PERFORMERS_BUCKET, PERFORMERS_PREFIX or "")
    completed_ids = set(yield_performer_ids())
    if not completed_ids:
        log.warning("No performer IDs found — skipping cycle.")
        return
    log.info("Total performer IDs found: %d", len(completed_ids))
    save_id_file(COMPLETED_KEY, completed_ids)

    # 3 — reconcile problem_performers.txt
    problem_ids = load_id_file(PROBLEM_KEY)
    if not problem_ids:
        log.info("No problem_performers list present.")
        return

    intersection = problem_ids & completed_ids
    if not intersection:
        log.info("No overlap with problem_performers (%d entries remain).", len(problem_ids))
        return

    problem_ids -= intersection
    if problem_ids:
        log.info("Removed %d IDs from problem_performers (new size %d).",
                 len(intersection), len(problem_ids))
        save_id_file(PROBLEM_KEY, problem_ids)
    # Always write the file back, even if it's now empty
    save_id_file(PROBLEM_KEY, problem_ids)

# ─── Scheduler loop ────────────────────────────────────────────────────────
def main():
    log.info("Initial sync …")
    sync_once()
    log.info("Worker up – polling every %d s", INTERVAL_SEC)
    schedule.every(INTERVAL_SEC).seconds.do(sync_once)
    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Shutdown.")

if __name__ == "__main__":
    main()
