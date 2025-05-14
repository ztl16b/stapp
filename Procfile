web: WEB_CONCURRENCY=1 gunicorn app:app --log-file=- --timeout 300
transfer_worker: python w_transfer.py
worker: python worker.py

