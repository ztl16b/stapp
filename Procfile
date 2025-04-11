web: gunicorn app:app --log-file=-
worker: celery -A celery_worker worker --loglevel=info
