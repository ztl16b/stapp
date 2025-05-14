#!/usr/bin/env python3
"""
RQ task wrapper for image generation.

Enqueue with:
    from rq import Queue
    from redis import Redis
    from tasks import generate_performers

    q = Queue(connection=Redis.from_url(os.environ["REDIS_URL"]))
    job = q.enqueue(generate_performers, [118, 106, 72])
"""

from subprocess import run
from typing import List

def generate_performers(ids: List[int]) -> None:
    """
    Call your existing generate.py exactly as you would on the CLI:

        $ python generate.py 118 106 72
    """
    if not ids:
        raise ValueError("No performer IDs supplied")

    cmd = ["python", "generate.py", *map(str, ids)]
    print("→", " ".join(cmd), flush=True)
    run(cmd, check=True)