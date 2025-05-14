#!/usr/bin/env python3
"""
hero_image_generator.py
────────────────────────
Generates hero images for performers and uploads reference JPEGs to S3.

ENV EXPECTED
────────────
S3_REF_BUCKET          = my-content-bucket          (⚠ no slash!)
S3_REF_BUCKET_PREFIX   = ref_images                 (optional, no leading slash)
GOOGLE_CSE_KEY, GOOGLE_CSE_CX  → Google CSE creds
"""

import argparse, base64, concurrent.futures as cf, io, json, os, sys, time, urllib.parse
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
    sys.exit("ERROR: S3_REF_BUCKET is missing in .env")

_s3 = boto3.client("s3")          # one thread-safe client

# ───────── CONFIG ───────── #

MAX_IMAGE_SIDE = 768
JPEG_QUALITY   = 92
UA             = "HeroImageBot/2.5 (+https://your-contact.example)"
REF_DIR        = Path(__file__).with_name("img_ref"); REF_DIR.mkdir(exist_ok=True)
RETRIES_EDIT   = 5

NEGATIVE_PHRASES = (
    "Exclude: distorted hands, extra limbs, cartoon, painting, "
    "text, watermarks, logos, floating limbs"
)
REALISM_PHRASES = (
    "Include: photorealistic skin texture, sharp focus, film grain, Kodak Portra 800 look, "
    "handheld motion blur, lens flare, cinematic color grade"
)

client = OpenAI()

# ───────── UTILITIES ───────── #

def _slugify(text: str) -> str:
    return "".join(c.lower() if c.isalnum() else "_" for c in text).strip("_")

# ───────── LOW-LEVEL HELPERS ───────── #

def _download_and_resize(url: str, retries: int = 3) -> Image.Image:
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
            print(f"⬆️  {p.name} → s3://{RAW_BUCKET}/{key}")
        except ClientError as e:
            print(f"⚠️  S3 upload error for {p.name}: {e}")


# ───────── GPT FILTER / RANK ───────── #

def gpt_accepts(img_bytes: bytes, performer: str) -> bool:
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
        return not r.choices[0].message.content.strip().lower().startswith("n")
    except Exception as e:
        print(f"GPT filter error: {e}")
        return False

def gpt_best_variant(performer: str, bp: dict, imgs: List[bytes]) -> int:
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
        idx = int(r.choices[0].message.content.strip()) - 1
        return idx if 0 <= idx < len(imgs) else 0
    except Exception as e:
        print(f"GPT rank error: {e}")
        return 0

# ───────── IMAGE SEARCH ───────── #

def _google_items(query: str, start: int):
    key, cx = os.getenv("GOOGLE_CSE_KEY"), os.getenv("GOOGLE_CSE_CX")
    if not (key and cx):
        sys.exit("Set GOOGLE_CSE_KEY & GOOGLE_CSE_CX.")
    svc = build("customsearch", "v1", developerKey=key)
    return (
        svc.cse()
        .list(q=query, cx=cx, searchType="image", num=10, start=start, imgSize="LARGE")
        .execute()
        .get("items", [])
    )

def _fallback_save(img: Image.Image, performer_id: str) -> Path:
    p = REF_DIR / f"{performer_id}_fallback_{int(time.time()*1000)}.jpg"
    img.save(p, "JPEG", quality=JPEG_QUALITY)
    return p

def harvest_refs(performer: str, performer_id: str, query: str, need: int) -> List[Path]:
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
    with cf.ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(harvest_refs, performer, performer_id, performer, 5)
        f2 = ex.submit(harvest_refs, performer, performer_id, f"{performer} live", 5)
        refs = f1.result() + f2.result()
    if len(refs) < 6:
        sys.exit("Not enough refs.")
    return refs

# ───────── BLUEPRINT & PROMPT ───────── #

def blueprint(performer: str, refs: List[Path]) -> dict:
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
        return json.loads(r.choices[0].message.content)
    except Exception as e:
        print(f"Blueprint error: {e}")
        return {}

def build_prompt(performer: str, bp: dict) -> str:
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
            print(f"images.edit retry {attempt}/{RETRIES_EDIT} after error – waiting {wait}s")
            time.sleep(wait)
    raise RuntimeError("images.edit failed after retries")

# ───────── MAIN WORKER ───────── #

def job(performer: str, performer_id: str, keep_variants: bool, out_path: str):
    print(f"[{performer}] 🔎 Gathering refs …")
    refs = get_six_refs(performer, performer_id)

    _upload_reference_images(performer_id, refs)

    bp = blueprint(performer, refs)

    prompt = build_prompt(performer, bp)
    print(f"[{performer}] 🎨 Generating variants …")
    variants = generate_variants(prompt, refs, 1)

    print(f"[{performer}] 🤖 GPT ranking variants …")
    best = gpt_best_variant(performer, bp, variants)
    Path(out_path).write_bytes(variants[best])
    print(f"[{performer}] ✅ Hero image saved to {out_path}")

    if keep_variants:
        stem, ext = Path(out_path).stem, Path(out_path).suffix or ".jpg"
        for i, img in enumerate(variants, 1):
            if i - 1 == best:
                continue
            Path(f"{stem}_variant{i}{ext}").write_bytes(img)
        print("   Other variants saved.")

# ───────── CLI ───────── #

def main():
    ap = argparse.ArgumentParser(description="Generate a hero image for a performer.")
    ap.add_argument("performer", help="Performer name (e.g. 'Shakira')")
    ap.add_argument("--id", dest="performer_id", help="External performer ID for filenames")
    ap.add_argument("--out", default="hero.jpg", help="Output image path")
    ap.add_argument("--variants", type=int, default=1, help="Number of image variants to keep")
    args = ap.parse_args()

    performer_id = args.performer_id or _slugify(args.performer)
    job(args.performer, performer_id, args.variants > 1, args.out)

if __name__ == "__main__":
    main()
