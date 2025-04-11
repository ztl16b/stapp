import os
import requests
import boto3
from celery import Celery
from dotenv import load_dotenv
import ssl

load_dotenv()

app = Celery('image_interface')

broker_url = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
result_backend = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')

broker_use_ssl = {
    'ssl_cert_reqs': ssl.CERT_NONE
} if broker_url.startswith('rediss://') else None

result_backend_use_ssl = {
    'ssl_cert_reqs': ssl.CERT_NONE
} if result_backend.startswith('rediss://') else None

app.conf.update(
    broker_url=broker_url,
    result_backend=result_backend,
    broker_use_ssl=broker_use_ssl,
    redis_backend_use_ssl=result_backend_use_ssl,
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    broker_connection_retry_on_startup=True,
    broker_connection_max_retries=10,
    broker_connection_timeout=30,
    task_time_limit=300,
    task_soft_time_limit=240,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=100,
)

app.autodiscover_tasks(['tasks'])

if __name__ == '__main__':
    app.start() 