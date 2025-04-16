web: gunicorn app:app --log-file=- --timeout 300
bytescale_worker: python w_bytescale.py
dupe_worker: python w_dupe_check.py
perf_worker: python w_performers.py