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
    s3.upload_file(str(local_path), S3_BUCKET, s3_key, ExtraArgs={'ACL': 'public-read', 'ContentDisposition': 'inline'})

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
        print("Usage: python generate.py 118 106 72 …")
        sys.exit(1)

    df = load_performer_meta()
    problematic_ids = [] # List to store IDs that cause issues

    max_workers = min(len(ids), TOTAL_RATE_LIMIT)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(process_performer_id, pid, df): pid for pid in ids}
        for fut in as_completed(futures):
            original_pid = futures[fut] # Get the original pid associated with this future
            try:
                result_message = fut.result()
                print(result_message) # Keep existing print behavior

                # Check for failure or warning messages
                if (result_message.startswith("❌ Generation failed for") or \
                    result_message.startswith("❌ Upload failed for") or \
                    result_message.startswith("⚠️")):
                    problematic_ids.append(str(original_pid))
            
            except Exception as e:
                # This catches exceptions from the process_performer_id task itself,
                # not just errors reported in its return string.
                print(f"ERROR: Exception while processing performer ID {original_pid}: {e}")
                problematic_ids.append(str(original_pid)) # Log ID if task itself crashes

    print("\nProcessing completed for all submitted IDs.")

    # Convert current run problem IDs to a set for efficient handling
    problematic_ids_current_run_set = set(str(pid) for pid in problematic_ids)

    if not problematic_ids_current_run_set:
        print("\nNo new problematic performer IDs identified in this run.")
    else:
        print(f"\nIdentified {len(problematic_ids_current_run_set)} problematic ID(s) in this run. Attempting to update S3 list...")
        
        s3_key_for_failures = "temp/problem_performers.txt"
        existing_ids_from_s3 = set()

        # Try to fetch existing problematic IDs from S3
        try:
            response = s3.get_object(Bucket=RESOURCES_BUCKET, Key=s3_key_for_failures)
            file_content = response['Body'].read().decode('utf-8')
            if file_content.strip():
                existing_ids_from_s3.update(line.strip() for line in file_content.splitlines() if line.strip())
            print(f"Found {len(existing_ids_from_s3)} existing problematic ID(s) in S3 file.")
        except s3.exceptions.NoSuchKey:
            print(f"No existing '{s3_key_for_failures}' file found in S3. A new file will be created.")
        except Exception as e:
            print(f"ERROR: Could not read existing problematic IDs from S3. Will proceed with current run IDs only. Details: {e}")

        # Combine existing IDs with new IDs from the current run
        all_problem_ids_set = existing_ids_from_s3.union(problematic_ids_current_run_set)

        if not all_problem_ids_set:
            print("No problematic IDs to upload (neither existing nor new).")
        else:
            # Sort for consistency
            final_ids_list = sorted(list(all_problem_ids_set))
            failure_file_content = "\n".join(final_ids_list)
            
            try:
                s3.put_object(
                    Bucket=RESOURCES_BUCKET, 
                    Key=s3_key_for_failures, 
                    Body=failure_file_content,
                    ContentType='text/plain',
                )
                print(f"Successfully updated list of problematic performer IDs ({len(final_ids_list)} total) to: s3://{RESOURCES_BUCKET}/{s3_key_for_failures}")
            except Exception as e:
                print(f"ERROR: Failed to upload updated problematic performer IDs list to S3. Details: {e}")
                print("Current run problematic IDs were:")
                for pid_val in sorted(list(problematic_ids_current_run_set)):
                    print(f"- {pid_val}")

if __name__ == "__main__":
    try:
        performer_ids = [int(arg) for arg in sys.argv[1:]]
    except ValueError:
        sys.exit("ERROR: All arguments must be integer performer IDs.")
    main(performer_ids)
