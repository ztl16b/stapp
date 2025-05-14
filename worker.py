#!/usr/bin/env python3
"""
Starts an RQ worker that consumes the default queue.

Procfile entry:
    worker: python worker.py
"""

import os
from redis import Redis
from rq import Worker, Queue, Connection

redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
listen_queues = ["default"]           # change if you use a custom queue name

with Connection(Redis.from_url(redis_url)):
    worker = Worker(map(Queue, listen_queues))
    print(f"RQ worker listening on {listen_queues} (redis: {redis_url})")
    worker.work()