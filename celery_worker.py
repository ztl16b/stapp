import os
import requests
import boto3
from celery import Celery
from dotenv import load_dotenv
import ssl

# Load environment variables
load_dotenv()

# Initialize Celery
app = Celery('image_interface')

# Configure Celery
broker_url = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
result_backend = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')

# Configure SSL for Redis if using rediss://
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
)

# Import tasks module to ensure tasks are registered
app.autodiscover_tasks(['tasks'])

if __name__ == '__main__':
    app.start() 