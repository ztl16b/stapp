# Image Interface with Celery

This application allows users to upload, process, and manage images using Flask, Celery, and AWS S3.

## Features

- User authentication
- Image upload and processing
- Background task processing with Celery
- Image review and categorization
- Browse and manage images in different S3 buckets

## Local Development Setup

1. Clone the repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Set up environment variables in a `.env` file:
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
   ```
4. Start Redis (required for Celery):
   ```
   redis-server
   ```
5. Start the Celery worker:
   ```
   celery -A celery_worker worker --loglevel=info
   ```
6. Run the Flask application:
   ```
   python app.py
   ```

## Heroku Deployment

1. Create a new Heroku app:
   ```
   heroku create your-app-name
   ```

2. Add Heroku Redis addon:
   ```
   heroku addons:create heroku-redis:mini
   ```

3. Set environment variables:
   ```
   heroku config:set AWS_ACCESS_KEY_ID=your_aws_access_key
   heroku config:set AWS_SECRET_ACCESS_KEY=your_aws_secret_key
   heroku config:set AWS_REGION=your_aws_region
   heroku config:set S3_UPLOAD_BUCKET=your_upload_bucket
   heroku config:set S3_GOOD_BUCKET=your_good_bucket
   heroku config:set S3_BAD_BUCKET=your_bad_bucket
   heroku config:set S3_INCREDIBLE_BUCKET=your_incredible_bucket
   heroku config:set BYTESCALE_API_KEY=your_bytescale_api_key
   heroku config:set BYTESCALE_UPLOAD_URL=your_bytescale_upload_url
   heroku config:set ADMIN_PASSWORD=your_admin_password
   heroku config:set BROWSE_PASSWORD=your_browse_password
   ```

4. Deploy to Heroku:
   ```
   git push heroku main
   ```

5. Scale the worker dyno:
   ```
   heroku ps:scale worker=1
   ```

## How It Works

1. **Image Upload**: Users upload images through the web interface.
2. **Background Processing**: Celery workers process the images in the background:
   - Upload to Bytescale API for processing
   - Download the processed image
   - Upload to S3 bucket
3. **Status Tracking**: Users can track the status of their uploads in real-time.
4. **Image Review**: Users can review and categorize images as good, bad, or incredible.
5. **Browse**: Users can browse images in different S3 buckets.

## Troubleshooting

- If the Celery worker is not processing tasks, check the worker logs:
  ```
  heroku logs --tail --app your-app-name
  ```
- If you're experiencing timeouts, consider increasing the worker concurrency:
  ```
  celery -A celery_worker worker --loglevel=info --concurrency=4
  ``` 