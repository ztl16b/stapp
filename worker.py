import os
import redis
from rq import Worker, Queue, Connection
from dotenv import load_dotenv

load_dotenv()

# Get Redis connection from environment
redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
redis_conn = redis.from_url(redis_url)

# Set up worker with specified queues
listen = ['uploads', 'default']

if __name__ == '__main__':
    # Set up worker and start processing jobs
    with Connection(redis_conn):
        worker = Worker(list(map(Queue, listen)))
        print(f"Worker starting, listening to queues: {', '.join(listen)}")
        worker.work() 