#!/usr/bin/env python3
import os
from redis import Redis #type:ignore
from rq import Worker, Queue #type:ignore
import sys # Add sys import for sys.exit

# Get REDIS_URL, default to local Redis for development if not set
redis_url_env = os.getenv("REDIS_URL")
worker_redis_url = redis_url_env if redis_url_env else "redis://localhost:6379/0"

if not worker_redis_url:
    print("ERROR: REDIS_URL not set and no default. Worker cannot start.")
    sys.exit(1)

listen_queues = ["default"]           # change if you use a custom queue name

try:
    # For redis-py 4.2+, passing ssl_cert_reqs=None is safe for rediss:// URLs
    # and will be ignored for non-SSL (redis://) URLs.
    redis_connection = Redis.from_url(worker_redis_url, ssl_cert_reqs=None)
    redis_connection.ping() # Test connection
    print(f"Worker successfully connected to Redis at {worker_redis_url}")
except Exception as e:
    print(f"ERROR: Worker failed to connect to Redis at {worker_redis_url}: {e}")
    sys.exit(1)

# Create Queue instances with the explicit connection
queues_to_listen = [Queue(name, connection=redis_connection) for name in listen_queues]

# Create Worker with the explicit list of Queue objects and the connection
worker = Worker(queues_to_listen, connection=redis_connection)

print(f"RQ worker listening on {listen_queues} (redis: {worker_redis_url})")
worker.work()