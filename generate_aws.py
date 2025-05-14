#!/usr/bin/env python3
from __future__ import annotations

import os, subprocess, shlex, shutil, sys, threading, time, tempfile
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import pandas as pd                   # type: ignore
import boto3                          # type: ignore
from dotenv import load_dotenv        # type: ignore

load_dotenv()

# ─── ENV Setup ───────────────────────────────────────────────────────────────
GOOGLE_CSE_KEY = os.getenv("GOOGLE_CSE_KEY")
GOOGLE_CSE_CX  = os.getenv("GOOGLE_CSE_CX")
if not (GOOGLE_CSE_KEY and GOOGLE_CSE_CX):
    sys.exit("ERROR: GOOGLE_CSE_KEY or GOOGLE_CSE_CX missing.")

S3_BUCKET = os.getenv("S3_TEMP_BUCKET")
S3_PREFIX = os.getenv("S3_TEMP_BUCKET_PREFIX", "").rstrip("/")
if not S3_BUCKET:
    sys.exit("ERROR: S3_TEMP_BUCKET not defined.")

# ─── Local file paths ────────────────────────────────────────────────────────
IMAGE_DIR   = Path("/Users/zacklung/local_files/perfimage_test")
CSV_PATH    = Path("performer-infos.csv")
TEST_SCRIPT = Path("images.py")
ERROR_DIR   = Path("/Users/zacklung/local_files/performer_images_error"); ERROR_DIR.mkdir(parents=True, exist_ok=True)

# ─── AWS S3 Client ───────────────────────────────────────────────────────────
s3 = boto3.client(
    "s3",
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    aws_session_token=os.getenv("AWS_SESSION_TOKEN")
)

def upload_to_s3(local_path: Path, s3_key: str) -> None:
    s3.upload_file(str(local_path), S3_BUCKET, s3_key)

# ─── API-key pool & quotas ───────────────────────────────────────────────────
API_CONFIGS = {
    "ztl": {"key": os.getenv("OPENAI_API_KEY_ZTL"), "rate_limit": 100},
    # "ayp": {"key": os.getenv("OPENAI_API_KEY_AYP"), "rate_limit": 100},
    # "gmy": {"key": os.getenv("OPENAI_API_KEY_GMY"), "rate_limit": 100},
}
API_CONFIGS = {k: v for k, v in API_CONFIGS.items() if v["key"]}
if not API_CONFIGS:
    sys.exit("ERROR: No OPENAI_API_KEY_* variables found.")

WINDOW_SECONDS   = 60
TOTAL_RATE_LIMIT = sum(cfg["rate_limit"] for cfg in API_CONFIGS.values())

_key_state = {
    nick: dict(limit=cfg["rate_limit"], used=0, reset=time.monotonic() + WINDOW_SECONDS, key=cfg["key"])
    for nick, cfg in API_CONFIGS.items()
}
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
                eligible = [
                    (nick, st) for nick, st in _key_state.items()
                    if st["used"] < st["limit"]
                ]
                if eligible:
                    nick, st = min(eligible, key=lambda kv: kv[1]["used"] / kv[1]["limit"])
                    st["used"] += 1
                    _global_state["used"] += 1
                    return nick, st["key"]
        time.sleep(0.25)

# ─── CSV lookup ──────────────────────────────────────────────────────────────
df = pd.read_csv(CSV_PATH, usecols=["performer_id", "name_alias"]).set_index("performer_id")

# ─── Sub-process launcher ────────────────────────────────────────────────────
def run_test_images(performer: str, performer_id: str, out_path: Path) -> None:
    nick, key = acquire_api_key()
    env = os.environ.copy()
    env["OPENAI_API_KEY"] = key
    env["GOOGLE_CSE_KEY"] = GOOGLE_CSE_KEY
    env["GOOGLE_CSE_CX"] = GOOGLE_CSE_CX

    cmd = [
        "python", str(TEST_SCRIPT),
        performer,
        "--out", str(out_path),
        "--id", performer_id
    ]
    print(f"[{nick}] →", " ".join(shlex.quote(c) for c in cmd))
    subprocess.run(cmd, check=True, env=env)

# ─── Per-file worker ─────────────────────────────────────────────────────────
def process_webp(webp: Path) -> str:
    perf_id_str = webp.stem
    try:
        perf_id = int(perf_id_str)
    except ValueError:
        return f"⚠️  {webp.name} skipped – filename isn't numeric"

    if perf_id not in df.index or pd.isna(df.loc[perf_id, "name_alias"]):
        return f"⚠️  {webp.name} skipped – ID not in CSV"

    performer = df.loc[perf_id, "name_alias"]
    s3_key = f"{S3_PREFIX}/{perf_id_str}.jpg" if S3_PREFIX else f"{perf_id_str}.jpg"

    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    start = time.perf_counter()
    try:
        run_test_images(performer, perf_id_str, tmp_path)
        upload_to_s3(tmp_path, s3_key)
        tmp_path.unlink(missing_ok=True)
    except subprocess.CalledProcessError as err:
        dst = ERROR_DIR / webp.name
        shutil.copy2(webp, dst)
        return (f"❌  Generation failed for {performer}: {err.stderr or err}\n"
                f"   📂 Copied {webp.name} → {dst}")
    except Exception as err:
        return f"❌  Upload failed for {performer}: {err}"
    else:
        elapsed = time.perf_counter() - start
        return f"✅ [{performer} 🕒 {elapsed:.2f}s] → s3://{S3_BUCKET}/{s3_key}"

# ─── Launch pool ─────────────────────────────────────────────────────────────
print(f"Scanning {IMAGE_DIR} …")
webp_files = list(IMAGE_DIR.glob("*.webp"))
if not webp_files:
    print("No .webp files found – exiting.")
    sys.exit()

MAX_WORKERS = min(len(webp_files), TOTAL_RATE_LIMIT)
with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
    futures = {pool.submit(process_webp, w): w for w in webp_files}
    for fut in as_completed(futures):
        print(fut.result())

print("Completed")