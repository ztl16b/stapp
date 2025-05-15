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

def get_task_from_queue():
    if not hasattr(get_task_from_queue, "dummy_ids"):
        get_task_from_queue.dummy_ids = [] # Start with an empty list for a clean worker
    
    if get_task_from_queue.dummy_ids:
        next_id = get_task_from_queue.dummy_ids.pop(0)
        print(f"[QueueStub] Dispensing task ID: {next_id}")
        return {"performer_id": next_id}
    print("[QueueStub] No tasks in dummy queue.")
    return None

def run_test_images(performer: str, performer_id: str, out_path: Path) -> None:
    nick, key = acquire_api_key()
    env = os.environ.copy()
    env["OPENAI_API_KEY"] = key

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
        return f"⚠️  {perf_id} skipped – ID not in CSV or name_alias is NaN"

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

# ─── Main entry - Refactored to worker loop ──────────────────────────
# Commenting out the original main function and its S3 problematic ID logic
# def main(ids: List[int]) -> None:
#     if not ids:
#         print("Usage: python generate.py 118 106 72 …")
#         sys.exit(1)
# 
#     df = load_performer_meta()
#     problematic_ids = [] # List to store IDs that cause issues
# 
#     max_workers = min(len(ids), TOTAL_RATE_LIMIT)
#     with ThreadPoolExecutor(max_workers=max_workers) as pool:
#         futures = {pool.submit(process_performer_id, pid, df): pid for pid in ids}
#         for fut in as_completed(futures):
#             original_pid = futures[fut] # Get the original pid associated with this future
#             try:
#                 result_message = fut.result()
#                 print(result_message) # Keep existing print behavior
# 
#                 # Check for failure or warning messages
#                 if (result_message.startswith("❌ Generation failed for") or \
#                     result_message.startswith("❌ Upload failed for") or \
#                     result_message.startswith("⚠️")):
#                     problematic_ids.append(str(original_pid))
#             
#             except Exception as e:
#                 # This catches exceptions from the process_performer_id task itself,
#                 # not just errors reported in its return string.
#                 print(f"ERROR: Exception while processing performer ID {original_pid}: {e}")
#                 problematic_ids.append(str(original_pid)) # Log ID if task itself crashes
# 
#     print("\nProcessing completed for all submitted IDs.")
# 
#     # Convert current run problem IDs to a set for efficient handling
#     problematic_ids_current_run_set = set(str(pid) for pid in problematic_ids)
# 
#     # --- Logic for handling problematic_ids.txt on S3 ---
#     # This logic might need to be re-evaluated in a distributed worker context.
#     # For now, it's commented out as individual workers shouldn't manage this shared file directly.
#     # 
#     s3_key_for_failures = os.getenv("PROBLEMATIC_IDS_S3_KEY", "problematic_performer_ids.txt")
#     existing_problem_ids_content = ""
#     try:
#         response = s3.get_object(Bucket=RESOURCES_BUCKET, Key=s3_key_for_failures)
#         existing_problem_ids_content = response['Body'].read().decode('utf-8')
#         print(f"Successfully downloaded existing problematic IDs list from s3://{RESOURCES_BUCKET}/{s3_key_for_failures}")
#     except s3.exceptions.NoSuchKey:
#         print(f"No existing problematic IDs list found at s3://{RESOURCES_BUCKET}/{s3_key_for_failures}. A new one will be created if needed.")
#     except Exception as e:
#         print(f"WARN: Could not download existing problematic IDs list. Proceeding without it. Error: {e}")
# 
#     all_problem_ids_set = set(existing_problem_ids_content.splitlines())
#     all_problem_ids_set.update(problematic_ids_current_run_set)
#     
#     if not problematic_ids_current_run_set:
#         print("No new problematic IDs in this run.")
#     else:
#         print(f"Newly problematic IDs in this run: {', '.join(sorted(list(problematic_ids_current_run_set)))}")
# 
#     if not all_problem_ids_set:
#         print("No problematic IDs to upload (neither existing nor new).")
#     else:
#         # Sort for consistency
#         final_ids_list = sorted(list(all_problem_ids_set))
#         failure_file_content = "\n".join(final_ids_list)
#         
#         try:
#             s3.put_object(
#                 Bucket=RESOURCES_BUCKET, 
#                 Key=s3_key_for_failures, 
#                 Body=failure_file_content,
#                 ContentType='text/plain',
#             )
#             print(f"Successfully updated list of problematic performer IDs ({len(final_ids_list)} total) to: s3://{RESOURCES_BUCKET}/{s3_key_for_failures}")
#         except Exception as e:
#             print(f"ERROR: Failed to upload updated problematic performer IDs list to S3. Details: {e}")
#             print("Current run problematic IDs were:")
#             for pid_val in sorted(list(problematic_ids_current_run_set)):
#                 print(f"- {pid_val}")

def main_worker_loop() -> None:
    print("Image generation worker started. Polling for tasks...")
    df = load_performer_meta()  # Load metadata once per worker instance

    while True:
        task = get_task_from_queue() # Fetch a single task (e.g., performer ID)

        if task:
            performer_id = task.get("performer_id")
            if performer_id:
                print(f"Processing performer ID: {performer_id}...")
                try:
                    result_message = process_performer_id(int(performer_id), df)
                    print(result_message)
                    # Handle problematic IDs:
                    # If process_performer_id indicates a failure/warning,
                    # you might want to log this or send it to a separate "failed tasks" queue.
                    # The logic for managing a global problematic_ids.txt needs careful thought
                    # in a distributed system (e.g., a separate service or atomic updates).
                    if (result_message.startswith("❌ Generation failed for") or \
                        result_message.startswith("❌ Upload failed for") or \
                        result_message.startswith("⚠️")):
                        # Log problematic ID, perhaps to a different system/queue
                        print(f"Problematic ID encountered: {performer_id}. Details: {result_message}")
                except Exception as e:
                    print(f"ERROR: Unhandled exception while processing performer ID {performer_id}: {e}")
                    # Log this critical failure
            else:
                print("Received task in an unexpected format.")
        else:
            # No task found, wait a bit before polling again
            print("No task in queue. Worker will sleep for 10 seconds.")
            time.sleep(10) # Adjust sleep time as needed; consider exponential backoff for empty queue

if __name__ == "__main__":
    # Commenting out old CLI parsing and main call
    # try:
    #     performer_ids = [int(arg) for arg in sys.argv[1:]]
    # except ValueError:
    #     sys.exit("ERROR: All arguments must be integer performer IDs.")
    # main(performer_ids)
    main_worker_loop()
