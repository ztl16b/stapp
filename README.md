# Image Interface with Celery

This application allows users to upload images, process them through Bytescale, and store them in S3 buckets. It uses Celery for background task processing to handle timeouts and improve performance.

## Setup

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Set up environment variables in a `.env` file:
   ```
   AWS_ACCESS_KEY_ID=your_aws_access_key
   AWS_SECRET_ACCESS_KEY=your_aws_secret_key
   AWS_REGION=your_aws_region
   S3_UPLOAD_BUCKET=your_upload_bucket
   S3_GOOD_BUCKET=your_good_bucket
   S3_BAD_BUCKET=your_bad_bucket
   S3_INCREDIBLE_BUCKET=your_incredible_bucket
   BYTESCALE_API_KEY=your_bytescale_api_key
   BYTESCALE_UPLOAD_URL=your_bytescale_upload_url
   ADMIN_PASSWORD=your_admin_password
   BROWSE_PASSWORD=your_browse_password
   CELERY_BROKER_URL=redis://localhost:6379/0
   CELERY_RESULT_BACKEND=redis://localhost:6379/0
   ```

3. Install and start Redis (required for Celery):
   ```
   # On macOS with Homebrew
   brew install redis
   brew services start redis
   
   # On Ubuntu/Debian
   sudo apt-get install redis-server
   sudo systemctl start redis-server
   ```

## Running the Application

1. Start the Flask application:
   ```
   python app.py
   ```

2. Start the Celery worker in a separate terminal:
   ```
   celery -A celery_worker.celery worker --loglevel=info
   ```

3. Access the application at http://localhost:5000

## Features

- Upload images and process them in the background
- Track upload status and progress
- Browse and manage images in different S3 buckets
- Review and categorize images

## Troubleshooting

If you encounter issues with Celery:

1. Make sure Redis is running:
   ```
   redis-cli ping
   ```
   Should return "PONG"

2. Check Celery worker logs for errors

3. Restart both the Flask application and Celery worker if needed 