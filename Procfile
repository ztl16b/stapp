web: gunicorn app:app --log-file=- --timeout 300
bytescale_worker: python w_bytescale.py
new_worker: python w_new.py
worker: python worker.py
# dupe_worker: python w_dupe_check.py
# perf_worker: python w_performers.py
