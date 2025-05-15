#!/usr/bin/env python3
from __future__ import annotations

import os, shlex, subprocess, sys, tempfile, threading, time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

import boto3                 # type: ignore
import pandas as pd          # type: ignore
from dotenv import load_dotenv  # type: ignore

# ─── ENV (Heroku config vars - fallback to .env for local dev) ────────────────
load_dotenv()  # harmless on Heroku, handy for local tests

GOOGLE_CSE_KEY = os.getenv("GOOGLE_CSE_KEY")
GOOGLE_CSE_CX  = os.getenv("GOOGLE_CSE_CX")
if not (GOOGLE_CSE_KEY and GOOGLE_CSE_CX):
    sys.exit("ERROR: GOOGLE_CSE_KEY or GOOGLE_CSE_CX missing.")

S3_BUCKET          = os.getenv("S3_TEMP_BUCKET")
S3_PREFIX          = os.getenv("S3_TEMP_BUCKET_PREFIX", "").rstrip("/")
RESOURCES_BUCKET   = os.getenv("S3_RESOURCES_BUCKET")
PERFORMER_META_KEY = os.getenv("PERFORMER_META_CSV_KEY")

if not (S3_BUCKET and RESOURCES_BUCKET and PERFORMER_META_KEY):
    sys.exit("ERROR: S3_TEMP_BUCKET, S3_RESOURCES_BUCKET or PERFORMER_META_CSV_KEY not defined.")

# ─── AWS clients ─────────────────────────────────────────────────────────────
s3 = boto3.client(
    "s3",
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    aws_session_token=os.getenv("AWS_SESSION_TOKEN"),
)

def upload_to_s3(local_path: Path, s3_key: str) -> None:
    s3.upload_file(str(local_path), S3_BUCKET, s3_key, ExtraArgs={'ACL': 'public-read', 'ContentDisposition': 'inline', 'ContentType': 'image/jpeg'})

def load_performer_meta() -> pd.DataFrame:
    """Download performer-infos CSV from S3 → DataFrame indexed by performer_id"""
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        s3.download_file(RESOURCES_BUCKET, PERFORMER_META_KEY, tmp.name)
        df = pd.read_csv(tmp.name, usecols=["performer_id", "name_alias"]).set_index("performer_id")
    return df

# ─── API-key pool & quotas (unchanged) ───────────────────────────────────────
API_CONFIGS = {
    "ztl": {"key": os.getenv("OPENAI_API_KEY"), "rate_limit": 100},
    # add more keys here …
}
API_CONFIGS = {k: v for k, v in API_CONFIGS.items() if v["key"]}
if not API_CONFIGS:
    sys.exit("ERROR: No OPENAI_API_KEY variables found.")

WINDOW_SECONDS   = 60
TOTAL_RATE_LIMIT = sum(cfg["rate_limit"] for cfg in API_CONFIGS.values())

_key_state = {nick: dict(limit=cfg["rate_limit"], used=0,
                         reset=time.monotonic() + WINDOW_SECONDS, key=cfg["key"])
              for nick, cfg in API_CONFIGS.items()}
_global_state = dict(limit=TOTAL_RATE_LIMIT, used=0, reset=time.monotonic() + WINDOW_SECONDS)
_state_lock = threading.Lock()

def _reset_window(now: float) -> None:
    for st in _key_state.values():
        st["used"] = 0
        st["reset"] = now + WINDOW_SECONDS
    _global_state["used"] = 0
    _global_state["reset"] = now + WINDOW_SECONDS

def acquire_api_key() -> tuple[str, str]:
    while True:
        now = time.monotonic()
        with _state_lock:
            if now >= _global_state["reset"]:
                _reset_window(now)
            if _global_state["used"] < _global_state["limit"]:
                eligible = [(nick, st) for nick, st in _key_state.items()
                            if st["used"] < st["limit"]]
                if eligible:
                    nick, st = min(eligible, key=lambda kv: kv[1]["used"] / kv[1]["limit"])
                    st["used"]  += 1
                    _global_state["used"] += 1
                    return nick, st["key"]
        time.sleep(0.25)

# ─── Worker ──────────────────────────────────────────────────────────────────
TEST_SCRIPT = Path("img.py")   # must exist in your Heroku slug

def run_test_images(performer: str, performer_id: str, out_path: Path) -> None:
    nick, key = acquire_api_key()
    env = os.environ.copy()
    env["OPENAI_API_KEY"] = key
    # GOOGLE_CSE_KEY, GOOGLE_CSE_CX, S3_REF_BUCKET, and S3_REF_BUCKET_PREFIX
    # will be inherited from the current environment via os.environ.copy()
    # if they are set, which is expected.

    cmd = [
        "python", str(TEST_SCRIPT),
        performer,
        "--out", str(out_path),
        "--id",  performer_id,
    ]
    # Enhanced print statement to include performer_id and flush
    print(f"[{nick}:{performer_id}] Starting img.py: {' '.join(shlex.quote(c) for c in cmd)}", flush=True)
    
    # Redirect stderr to stdout for the subprocess
    # This ensures all output from img.py (including errors) is captured in sequence
    # by tasks.py through img_generate.py's stdout.
    subprocess.run(cmd, check=True, env=env, stderr=subprocess.STDOUT)

def process_performer_id(perf_id: int, df: pd.DataFrame) -> str:
    if perf_id not in df.index or pd.isna(df.loc[perf_id, "name_alias"]):
        return f"⚠️  {perf_id} skipped – ID not in CSV"

    performer  = df.loc[perf_id, "name_alias"]
    s3_key     = f"{S3_PREFIX}/{perf_id}.jpg" if S3_PREFIX else f"{perf_id}.jpg"

    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    start = time.perf_counter()
    try:
        run_test_images(performer, str(perf_id), tmp_path)
        upload_to_s3(tmp_path, s3_key)
        tmp_path.unlink(missing_ok=True)
    except subprocess.CalledProcessError as err:
        details = err.stderr or str(err)
        return f"❌ Generation failed for {performer} (ID: {perf_id}): {details}"
    except Exception as err:
        return f"❌ Upload failed for {performer} (ID: {perf_id}): {err}"
    else:
        elapsed = time.perf_counter() - start
        return f"✅ [{performer} 🕒 {elapsed:.2f}s] → s3://{S3_BUCKET}/{s3_key}"

# ─── Main entry - expects performer IDs as CLI args ──────────────────────────
def main(ids: List[int]) -> None:
    if not ids:
        print("Usage: python generate.py <performer_id>")
        sys.exit(1)
    
    if len(ids) > 1:
        print("Warning: This script is now designed to process one ID at a time when called by tasks.py.")
        print(f"Received {len(ids)} IDs, processing only the first: {ids[0]}")
    
    single_performer_id = ids[0]

    df = load_performer_meta()

    try:
        result_message = process_performer_id(single_performer_id, df)
        print(result_message)
    except Exception as e:
        print(f"ERROR: Exception while processing performer ID {single_performer_id}: {e}")

    print(f"\nProcessing completed for submitted ID: {single_performer_id}.")

if __name__ == "__main__":
    try:
        performer_id = int(sys.argv[1])
    except ValueError:
        sys.exit("ERROR: All arguments must be integer performer IDs.")
    main([performer_id])
