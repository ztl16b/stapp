web: gunicorn app:app --log-file=- --timeout 300
image_worker: python image_processor.py
validation_worker: python filename_validator.py
# dupe_worker: python dupe_check.py
