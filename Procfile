web: gunicorn app:app --log-file=- --timeout 60
worker: celery -A celery_worker worker --loglevel=info
