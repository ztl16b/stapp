web: gunicorn app:app --log-file=- --timeout 300
image_worker: python image_processor.py
bytescale_worker: python bytescale.py

