#!/usr/bin/env python3
import os
from redis import Redis #type:ignore
from rq import Worker, Queue, Connection #type:ignore

redis_url = os.getenv("REDIS_URL")
listen_queues = ["default"]           # change if you use a custom queue name

with Connection(Redis.from_url(redis_url)):
    worker = Worker(map(Queue, listen_queues))
    print(f"RQ worker listening on {listen_queues} (redis: {redis_url})")
    worker.work()