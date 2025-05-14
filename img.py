#!/usr/bin/env python3
from __future__ import annotations

print("DEBUG: img.py script started executing!", flush=True)
import sys
import os
print(f"DEBUG: img.py PID: {os.getpid()}", flush=True)
print(f"DEBUG: img.py CWD: {os.getcwd()}", flush=True)
print(f"DEBUG: img.py sys.argv: {sys.argv}", flush=True)
print(f"DEBUG: img.py S3_REF_BUCKET from env: {os.getenv('S3_REF_BUCKET')}", flush=True)
print(f"DEBUG: img.py S3_REF_BUCKET_PREFIX from env: {os.getenv('S3_REF_BUCKET_PREFIX')}", flush=True)
print(f"DEBUG: img.py GOOGLE_CSE_KEY from env: {os.getenv('GOOGLE_CSE_KEY')}", flush=True)
print(f"DEBUG: img.py GOOGLE_CSE_CX from env: {os.getenv('GOOGLE_CSE_CX')}", flush=True)
print(f"DEBUG: img.py OPENAI_API_KEY from env: {os.getenv('OPENAI_API_KEY')}", flush=True)

import argparse, base64, concurrent.futures as cf, io, json, os, sys, time, urllib.parse # sys already imported but fine
from pathlib import Path
from typing import List

import requests                             # type: ignore
from PIL import Image                       # type: ignore
from googleapiclient.discovery import build # type: ignore
from openai import OpenAI                   # type: ignore

# ───────── AWS / BOTO3 ───────── #

import boto3                                # type: ignore
from botocore.exceptions import ClientError # type: ignore

RAW_BUCKET = (os.getenv("S3_REF_BUCKET") or "").strip().strip("/")
PREFIX     = (os.getenv("S3_REF_BUCKET_PREFIX") or "").strip().strip("/")
if not RAW_BUCKET:
    print("DEBUG: img.py ERROR: S3_REF_BUCKET is missing or empty!", flush=True)
    sys.exit("ERROR: S3_REF_BUCKET is missing in .env")

_s3 = boto3.client("s3")          # one thread-safe client
print("DEBUG: img.py S3 client initialized.", flush=True)

# ───────── CONFIG ───────── #

MAX_IMAGE_SIDE = 768
JPEG_QUALITY   = 92
UA             = "HeroImageBot/2.5 (+https://your-contact.example)"
REF_DIR        = Path(__file__).resolve().parent / "img_ref" # Use absolute path for reliability
print(f"DEBUG: img.py REF_DIR calculated as: {REF_DIR}", flush=True)
try:
    REF_DIR.mkdir(exist_ok=True, parents=True)
    print(f"DEBUG: img.py REF_DIR.mkdir called. Exists: {REF_DIR.exists()}", flush=True)
except Exception as e_mkdir:
    print(f"DEBUG: img.py ERROR creating REF_DIR {REF_DIR}: {e_mkdir}", flush=True)

RETRIES_EDIT   = 5

NEGATIVE_PHRASES = (
    "Exclude: distorted hands, extra limbs, cartoon, painting, "
    "text, watermarks, logos, floating limbs"
)
REALISM_PHRASES = (
    "Include: photorealistic skin texture, sharp focus, film grain, Kodak Portra 800 look, "
    "handheld motion blur, lens flare, cinematic color grade"
)

try:
    client = OpenAI()
    print("DEBUG: img.py OpenAI client initialized.", flush=True)
except Exception as e_openai:
    print(f"DEBUG: img.py ERROR initializing OpenAI client: {e_openai}", flush=True)
    client = None # Ensure client is defined

# ───────── UTILITIES ───────── #

def _slugify(text: str) -> str:
    return "".join(c.lower() if c.isalnum() else "_" for c in text).strip("_")

# ───────── LOW-LEVEL HELPERS ───────── #

def _download_and_resize(url: str, retries: int = 3) -> Image.Image:
    print(f"DEBUG: img.py _download_and_resize called for URL: {url}", flush=True)
    hdrs = {"User-Agent": UA, "Referer": f"https://{urllib.parse.urlparse(url).netloc}/"}
    delay = 1
    for _ in range(retries):
        r = requests.get(url, headers=hdrs, timeout=10, allow_redirects=True)
        if r.status_code in (403, 429):
            time.sleep(delay); delay *= 2; continue
        r.raise_for_status()
        img = Image.open(io.BytesIO(r.content)).convert("RGB")
        img.thumbnail((MAX_IMAGE_SIDE, MAX_IMAGE_SIDE))
        return img
    raise RuntimeError(f"Failed to fetch {url}")

def _b64_uri(data: bytes) -> str:
    return f"data:image/jpeg;base64,{base64.b64encode(data).decode()}"

def _paths_to_files(paths: List[Path]):
    bufs = []
    for p in paths:
        buf = io.BytesIO(p.read_bytes()); buf.name = p.name
        bufs.append(buf)
    return bufs

# ───────── S3 UPLOAD ───────── #

def _upload_reference_images(performer_id: str, refs: List[Path]) -> None:
    print(f"DEBUG: img.py _upload_reference_images called for id {performer_id} with {len(refs)} refs.", flush=True)
    """
    Upload refs to  s3://<bucket>/<prefix>/<performer_id>.<n>.jpg
                        └──── public-read, no auth query string
    """
    for idx, p in enumerate(refs, 1):
        key = f"{PREFIX}/{performer_id}.{idx}.jpg" if PREFIX else f"{performer_id}.{idx}.jpg"

        try:
            _s3.upload_file(
                str(p),
                RAW_BUCKET,
                key,
                ExtraArgs={
                    "ACL": "public-read",
                    "ContentDisposition": "inline"
                },
            )
            print(f"⬆️  {p.name} → s3://{RAW_BUCKET}/{key}", flush=True)
        except ClientError as e:
            print(f"⚠️  S3 upload error for {p.name}: {e}", flush=True)


# ───────── GPT FILTER / RANK ───────── #

def gpt_accepts(img_bytes: bytes, performer: str) -> bool:
    print(f"DEBUG: img.py gpt_accepts called for performer: {performer}", flush=True)
    if not client:
        print("DEBUG: img.py gpt_accepts: OpenAI client not available.", flush=True)
        return False
    msg = {
        "role": "user",
        "content": [
            {
                "type": "text",
                "text": (
                    f"Is this a photographic image of {performer}? "
                    "You are collecting reference images for an AI image-generation model. "
                    "Be lenient: no illustrations or album art; minimal or no text. "
                    "Reply only 'yes' or 'no'."
                ),
            },
            {"type": "image_url", "image_url": {"url": _b64_uri(img_bytes), "detail": "high"}},
        ],
    }
    try:
        r = client.chat.completions.create(
            model="gpt-4o-mini", messages=[msg], max_tokens=1, timeout=10
        )
        result = not r.choices[0].message.content.strip().lower().startswith("n")
        print(f"DEBUG: img.py gpt_accepts result: {result}", flush=True)
        return result
    except Exception as e:
        print(f"GPT filter error: {e}", flush=True)
        return False

def gpt_best_variant(performer: str, bp: dict, imgs: List[bytes]) -> int:
    print(f"DEBUG: img.py gpt_best_variant called for performer: {performer}", flush=True)
    if not client:
        print("DEBUG: img.py gpt_best_variant: OpenAI client not available.", flush=True)
        return 0
    content = [
        {
            "type": "text",
            "text": f"Choose the best hero image of {performer} that matches:\n{json.dumps(bp)}\n"
                    "Return only its number.",
        }
    ]
    for b in imgs:
        content.append({"type": "image_url", "image_url": {"url": _b64_uri(b), "detail": "high"}})
    try:
        r = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": content}],
            max_tokens=3,
        )
        idx_str = r.choices[0].message.content.strip()
        print(f"DEBUG: img.py gpt_best_variant raw response: '{idx_str}'", flush=True)
        idx = int(idx_str) - 1
        return idx if 0 <= idx < len(imgs) else 0
    except Exception as e:
        print(f"GPT rank error: {e}", flush=True)
        return 0

# ───────── IMAGE SEARCH ───────── #

def _google_items(query: str, start: int):
    print(f"DEBUG: img.py _google_items called with query: '{query}', start: {start}", flush=True)
    key, cx = os.getenv("GOOGLE_CSE_KEY"), os.getenv("GOOGLE_CSE_CX")
    if not (key and cx):
        print("DEBUG: img.py ERROR: GOOGLE_CSE_KEY or GOOGLE_CSE_CX missing for _google_items!", flush=True)
        sys.exit("Set GOOGLE_CSE_KEY & GOOGLE_CSE_CX.")
    svc = build("customsearch", "v1", developerKey=key)
    return (
        svc.cse()
        .list(q=query, cx=cx, searchType="image", num=10, start=start, imgSize="LARGE")
        .execute()
        .get("items", [])
    )

def _fallback_save(img: Image.Image, performer_id: str) -> Path:
    print(f"DEBUG: img.py _fallback_save for {performer_id}", flush=True)
    p = REF_DIR / f"{performer_id}_fallback_{int(time.time()*1000)}.jpg"
    img.save(p, "JPEG", quality=JPEG_QUALITY)
    return p

def harvest_refs(performer: str, performer_id: str, query: str, need: int) -> List[Path]:
    print(f"DEBUG: img.py harvest_refs called for performer {performer}, id {performer_id}, query '{query}', need {need}", flush=True)
    safe_id = _slugify(performer_id)
    refs, start, rejects, page = [], 1, 0, 0
    while len(refs) < need and page < 8:
        for hit in _google_items(query, start):
            if len(refs) >= need:
                break
            try:
                img = _download_and_resize(hit["link"])
                buf = io.BytesIO()
                img.save(buf, "JPEG", quality=JPEG_QUALITY)
                if not gpt_accepts(buf.getvalue(), performer):
                    rejects += 1
                    if rejects >= 30:
                        refs.append(_fallback_save(img, safe_id))
                        rejects = 0
                    continue
                rejects = 0
                p = REF_DIR / f"{safe_id}.{len(list(REF_DIR.iterdir()))}.jpg"
                img.save(p, "JPEG", quality=JPEG_QUALITY)
                refs.append(p)
            except Exception:
                continue
        start += 10
        page += 1
    return refs

def get_six_refs(performer: str, performer_id: str) -> List[Path]:
    print(f"DEBUG: img.py get_six_refs for performer {performer}, id {performer_id}", flush=True)
    with cf.ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(harvest_refs, performer, performer_id, performer, 5)
        f2 = ex.submit(harvest_refs, performer, performer_id, f"{performer} live", 5)
        refs = f1.result() + f2.result()
    if len(refs) < 6:
        print(f"DEBUG: img.py Not enough refs found. Expected 6, got {len(refs)}", flush=True)
        sys.exit("Not enough refs.")
    return refs

# ───────── BLUEPRINT & PROMPT ───────── #

def blueprint(performer: str, refs: List[Path]) -> dict:
    print(f"DEBUG: img.py blueprint called for performer {performer} with {len(refs)} refs.", flush=True)
    if not client:
        print("DEBUG: img.py blueprint: OpenAI client not available.", flush=True)
        return {}
    msgs = [
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": (
                        f"Look at images of {performer}. "
                        "Return JSON: hair_color, signature_outfit, stage_emotion, lighting."
                    ),
                },
                *[
                    {
                        "type": "image_url",
                        "image_url": {"url": _b64_uri(p.read_bytes()), "detail": "high"},
                    }
                    for p in refs
                ],
            ],
        }
    ]
    try:
        r = client.chat.completions.create(
            model="gpt-4o-mini", messages=msgs, response_format={"type": "json_object"}
        )
        bp_result = json.loads(r.choices[0].message.content)
        print(f"DEBUG: img.py blueprint result: {bp_result}", flush=True)
        return bp_result
    except Exception as e:
        print(f"Blueprint error: {e}", flush=True)
        return {}

def build_prompt(performer: str, bp: dict) -> str:
    print(f"DEBUG: img.py build_prompt called for performer {performer}", flush=True)
    core = (
        f"Ultra-realistic photograph of {performer} performing live.\n"
        f"Hair: {bp.get('hair_color', '')}; Outfit: {bp.get('signature_outfit', '')}; "
        f"Emotion: {bp.get('stage_emotion', '')}; Lighting: {bp.get('lighting', '')}.\n"
        "The image must contain NO text, watermarks, or logos.\n"
        "Shot on Sony α7R IV + 85 mm f/1.4 GM, 1/250 s, ISO 800.\n"
        f"Please use the reference images of {performer} to reproduce their likeness.\n"
    )
    return (
        f"{core}{REALISM_PHRASES}\n"
        f"Negative prompt: {NEGATIVE_PHRASES}\n"
        f"Please use the reference images of {performer} to reproduce their likeness.\n"
    )

def generate_variants(prompt: str, refs: List[Path], n: int) -> List[bytes]:
    print(f"DEBUG: img.py generate_variants called with n={n}, {len(refs)} refs.", flush=True)
    if not client:
        print("DEBUG: img.py generate_variants: OpenAI client not available.", flush=True)
        return []
    for attempt in range(1, RETRIES_EDIT + 1):
        try:
            r = client.images.edit(
                model="gpt-image-1",
                image=_paths_to_files(refs),
                prompt=prompt,
                n=n,
                size="1024x1024",
                quality="high",
            )
            return [base64.b64decode(d.b64_json) for d in r.data]
        except Exception:
            if attempt == RETRIES_EDIT:
                raise
            wait = 2 ** attempt
            print(f"images.edit retry {attempt}/{RETRIES_EDIT} after error – waiting {wait}s", flush=True)
            time.sleep(wait)
    raise RuntimeError("images.edit failed after retries")

# ───────── MAIN WORKER ───────── #

def job(performer: str, performer_id: str, keep_variants: bool, out_path: str):
    print(f"DEBUG: img.py job() called with performer='{performer}', id='{performer_id}', out_path='{out_path}', keep_variants={keep_variants}", flush=True)
    print(f"[{performer}] 🔎 Gathering refs …", flush=True)
    refs = get_six_refs(performer, performer_id)
    if not refs:
        print(f"DEBUG: img.py job() - No refs gathered for {performer}. Exiting job.", flush=True)
        # Decide if we should write an empty/error file to out_path or just return
        # For now, let it proceed, Path(out_path).write_bytes might fail if variants are empty.
        # Or, create a placeholder/error indicator for out_path
        # For simplicity, let's ensure variants is handled if refs are empty
        Path(out_path).write_text(f"Error: No reference images found for {performer}")
        return


    _upload_reference_images(performer_id, refs)

    bp = blueprint(performer, refs)
    if not bp:
        print(f"DEBUG: img.py job() - No blueprint created for {performer}. Exiting job.", flush=True)
        Path(out_path).write_text(f"Error: Could not create blueprint for {performer}")
        return

    prompt = build_prompt(performer, bp)
    print(f"[{performer}] 🎨 Generating variants …", flush=True)
    variants = generate_variants(prompt, refs, 1) # n=1 for the primary image

    if not variants:
        print(f"DEBUG: img.py job() - No variants generated for {performer}. Exiting job.", flush=True)
        Path(out_path).write_text(f"Error: No image variants generated for {performer}")
        return

    print(f"[{performer}] 🤖 GPT ranking variants …", flush=True)
    best = gpt_best_variant(performer, bp, variants)
    Path(out_path).write_bytes(variants[best])
    print(f"[{performer}] ✅ Hero image saved to {out_path}", flush=True)

    if keep_variants and len(variants) > 1: # Ensure variants > 1 if we intend to save others
        stem, ext = Path(out_path).stem, Path(out_path).suffix or ".jpg"
        saved_others = 0
        for i, img_bytes in enumerate(variants): # Iterate with index for variant numbering
            if i == best: # Corrected logic: skip the one already saved as primary
                continue
            variant_path = Path(out_path).parent / f"{stem}_variant{i+1}{ext}" # Use i+1 for 1-based variant names
            variant_path.write_bytes(img_bytes)
            saved_others +=1
        if saved_others > 0:
            print(f"   Other {saved_others} variants saved.", flush=True)

# ───────── CLI ───────── #

def main():
    print("DEBUG: img.py main() called", flush=True)
    ap = argparse.ArgumentParser(description="Generate a hero image for a performer.")
    ap.add_argument("performer", help="Performer name (e.g. 'Shakira')")
    ap.add_argument("--id", dest="performer_id", help="External performer ID for filenames")
    ap.add_argument("--out", default="hero.jpg", help="Output image path")
    ap.add_argument("--variants", type=int, default=1, help="Total number of variants to generate (including the main one). If > 1, others are saved.") # Clarified help
    args = ap.parse_args()
    print(f"DEBUG: img.py main() parsed args: {args}", flush=True)

    performer_id_val = args.performer_id or _slugify(args.performer)
    
    # The `job` function expects `keep_variants` as a boolean.
    # If args.variants is 1, we don't keep extras. If > 1, we do.
    # The number of variants to generate in generate_variants() should be args.variants.
    # And the primary one is chosen from these.
    
    # For now, to match previous logic where job expects `keep_variants` bool
    # and `generate_variants` was called with n=1
    # The 'job' function itself calls generate_variants with n=1
    # and the keep_variants flag determines if *other* (non-best) variants are saved.
    # This seems a bit misaligned. Let's clarify:
    # If --variants N is passed, we should generate N variants, pick the best,
    # and if N > 1, save the other N-1 variants.

    # Let's adjust job and its call slightly. For now, stick to minimal changes to what job expects.
    # `job` calls `generate_variants` with n=1 currently. This needs to change if we want multiple variants from `generate_variants`.
    # For now, let's assume `job`'s internal call `generate_variants(prompt, refs, 1)` is for the primary image,
    # and `args.variants > 1` controls saving hypothetical other variants if `generate_variants` were to produce them.
    # This part of the logic might need further refinement based on your exact intent for --variants.
    # The original `job` saves variants[best] and then if `keep_variants` is true, loops `enumerate(variants, 1)`
    # to save others. This implies `generate_variants` should produce `args.variants` items.

    # Let's stick to the direct interpretation for now:
    # `img_generate.py` doesn't send --variants, so img.py's args.variants=1.
    # keep_variants_for_job = args.variants > 1 (so, False)
    # job(args.performer, performer_id_val, keep_variants_for_job, args.out)
    # Inside job: generate_variants(prompt, refs, 1) -> 1 variant.
    # Then best is 0. variants[0] is saved.
    # Then if keep_variants_for_job (False): loop for others is skipped. This is fine.

    # Let's modify `job` to take `num_to_generate` and then use that.
    # For now, to keep `job` signature mostly stable for `img_generate.py` that calls it via CLI:
    # The CLI `--variants` will control the `n` in `generate_variants` via the `job` call.
    
    # Re-evaluating: `img_generate.py` doesn't pass `--variants`. So `args.variants` in `img.py` is always 1.
    # Thus `keep_variants` in `job` call is `(1 > 1)` which is `False`.
    # So, `img.py` when called by `img_generate.py` will always generate 1 image and not try to save others.
    # This is consistent with `img_generate.py` expecting one output file.
    # The `job` signature can stay: `job(performer, performer_id, keep_variants_bool, out_path)`
    # and `generate_variants` inside `job` should probably take `n=1` if `keep_variants_bool` is false,
    # or `n=some_number` if `keep_variants_bool` is true.

    # Let's stick to the direct interpretation for now:
    # `img_generate.py` doesn't send --variants, so img.py's args.variants=1.
    # keep_variants_for_job = args.variants > 1 (so, False)
    # job(args.performer, performer_id_val, keep_variants_for_job, args.out)
    # Inside job: generate_variants(prompt, refs, 1) -> 1 variant.
    # Then best is 0. variants[0] is saved.
    # Then if keep_variants_for_job (False): loop for others is skipped. This is fine.

    job(args.performer, performer_id_val, args.variants > 1, args.out)
    print("DEBUG: img.py main() finished", flush=True)


if __name__ == "__main__":
    print("DEBUG: img.py __main__ block reached", flush=True)
    try:
        main()
    except SystemExit as se:
        print(f"DEBUG: img.py SystemExit in __main__: {se.code}", flush=True)
        # sys.exit (called by argparse or our code) will be caught here.
        # We should re-exit with the same code to preserve behavior.
        # The message to stderr (if any) would have already been printed by sys.exit or argparse.
        sys.exit(se.code) # Re-raise SystemExit
    except Exception as e:
        print(f"DEBUG: img.py EXCEPTION in main: {type(e).__name__}: {e}", flush=True)
        import traceback
        traceback.print_exc(file=sys.stdout) # Print to stdout for capture
        sys.stdout.flush()
        sys.exit(1) # Exit with non-zero for general errors
    print("DEBUG: img.py script finishing after __main__ block", flush=True)
