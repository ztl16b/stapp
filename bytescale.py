#!/usr/bin/env python3
import os
import time
import boto3
import logging
import traceback
import sys
import requests
from io import BytesIO
from dotenv import load_dotenv
import schedule
from datetime import datetime

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('bytescale_worker')

# Get environment variables
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")
S3_TEMP_BUCKET = os.getenv("S3_TEMP_BUCKET")
S3_TEMP_BUCKET_PREFIX = os.getenv("S3_TEMP_BUCKET_PREFIX", "")
S3_GOOD_BUCKET = os.getenv("S3_GOOD_BUCKET")
S3_GOOD_BUCKET_PREFIX = os.getenv("S3_GOOD_BUCKET_PREFIX", "")
S3_UPLOAD_BUCKET = os.getenv("S3_UPLOAD_BUCKET")
S3_UPLOAD_BUCKET_PREFIX = os.getenv("S3_UPLOAD_BUCKET_PREFIX", "")
BYTESCALE_API_KEY = os.getenv("BYTESCALE_API_KEY")
BYTESCALE_UPLOAD_URL = os.getenv("BYTESCALE_UPLOAD_URL")

logger.info(f"Using S3 bucket: {S3_TEMP_BUCKET}")
if S3_TEMP_BUCKET_PREFIX:
    logger.info(f"Using prefix: {S3_TEMP_BUCKET_PREFIX}")
else:
    logger.info("No prefix specified, will check entire bucket")

logger.info(f"Using Good bucket: {S3_GOOD_BUCKET}")
if S3_GOOD_BUCKET_PREFIX:
    logger.info(f"Using Good bucket prefix: {S3_GOOD_BUCKET_PREFIX}")

logger.info(f"Using Upload bucket: {S3_UPLOAD_BUCKET}")
if S3_UPLOAD_BUCKET_PREFIX:
    logger.info(f"Using Upload bucket prefix: {S3_UPLOAD_BUCKET_PREFIX}")

# Validate required environment variables
missing_vars = []
if not AWS_ACCESS_KEY_ID: missing_vars.append("AWS_ACCESS_KEY_ID")
if not AWS_SECRET_ACCESS_KEY: missing_vars.append("AWS_SECRET_ACCESS_KEY")
if not AWS_REGION: missing_vars.append("AWS_REGION")
if not S3_TEMP_BUCKET: missing_vars.append("S3_TEMP_BUCKET")
if not S3_GOOD_BUCKET: missing_vars.append("S3_GOOD_BUCKET")
if not S3_UPLOAD_BUCKET: missing_vars.append("S3_UPLOAD_BUCKET")
if not BYTESCALE_API_KEY: missing_vars.append("BYTESCALE_API_KEY")
if not BYTESCALE_UPLOAD_URL: missing_vars.append("BYTESCALE_UPLOAD_URL")

if missing_vars:
    error_msg = f"ERROR: Missing required environment variables: {', '.join(missing_vars)}"
    logger.error(error_msg)
    sys.exit(1)

try:
    s3_client = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )
    
    # Test S3 connection
    s3_client.list_buckets()
    logger.info("S3 connection successful!")
    
except Exception as e:
    logger.error(f"ERROR: Failed to initialize S3 client: {e}")
    traceback.print_exc()
    sys.exit(1)

def process_image(s3_key):
    try:
        filename = s3_key.split('/')[-1]
        base_name, extension = os.path.splitext(filename)
        logger.info(f"Processing image: {filename}")
        
        # Download image from S3
        logger.info(f"Downloading {filename} from {S3_TEMP_BUCKET}")
        response = s3_client.get_object(Bucket=S3_TEMP_BUCKET, Key=s3_key)
        file_data = response['Body'].read()
        content_type = response.get('ContentType', 'image/jpeg')
        
        # Extract metadata from the original image
        metadata = response.get('Metadata', {})
        uploader_initials = metadata.get('uploader-initials', '')
        review_status = metadata.get('review_status', 'FALSE')
        
        if uploader_initials:
            logger.info(f"Found uploader initials metadata: {uploader_initials}")
        else:
            logger.info("No uploader initials found in metadata")
            
        logger.info(f"Using review_status: {review_status}")
        
        if len(file_data) == 0:
            logger.error(f"Downloaded file has zero bytes. Skipping.")
            return False
        
        # Upload to Bytescale
        headers = {
            'Authorization': f'Bearer {BYTESCALE_API_KEY}'
        }
        files_data = {
            'file': (filename, file_data, content_type)
        }
        
        logger.info(f"Uploading {filename} to Bytescale for processing")
        with requests.Session() as session:
            # Upload to Bytescale
            upload_response = session.post(
                BYTESCALE_UPLOAD_URL, 
                headers=headers, 
                files=files_data, 
                timeout=60
            )
            
            if upload_response.status_code != 200:
                logger.error(f"Bytescale upload returned status code {upload_response.status_code}")
                logger.error(f"Response content: {upload_response.text[:500]}")
                return False
            
            upload_response.raise_for_status()
            json_response = upload_response.json()
            logger.info(f"Bytescale upload successful")
            
            # Extract file URL from response
            file_url = None
            for file_obj in json_response.get("files", []):
                if file_obj.get("formDataFieldName") == "file":
                    file_url = file_obj.get("fileUrl")
                    break
            
            if not file_url:
                logger.error("Could not find file URL in Bytescale response")
                return False
            
            logger.info(f"Bytescale file URL: {file_url}")
            
            # Free up memory
            del file_data
            del files_data
            
            # Apply image transformations using Bytescale Image Processing API
            # Converting to WebP format with 80% quality, width 800px, maintaining aspect ratio
            processed_url = file_url.replace("/raw/", "/image/") + "?f=webp&w=464&h=510&fit=crop&crop=smart"
            logger.info(f"Downloading processed image from: {processed_url}")
            
            # Download processed image
            download_response = session.get(processed_url, stream=True, timeout=60)
            if download_response.status_code != 200:
                logger.error(f"Bytescale transformation returned status code {download_response.status_code}")
                return False
            
            download_response.raise_for_status()
            
            # Upload processed image back to S3
            # Replace hyphens with dots in the base filename
            base_name_with_dots = base_name.replace('-', '.')
            
            # Create the new filename with webp extension
            processed_filename = f"{base_name_with_dots}.webp"
            
            # Create the upload path for the Good bucket
            good_bucket_path = f"{S3_GOOD_BUCKET_PREFIX}{processed_filename}" if S3_GOOD_BUCKET_PREFIX else processed_filename
            
            # Create the upload path for the Upload bucket
            upload_bucket_path = f"{S3_UPLOAD_BUCKET_PREFIX}{processed_filename}" if S3_UPLOAD_BUCKET_PREFIX else processed_filename
            
            # Check if image already exists in Good bucket
            image_exists = False
            try:
                s3_client.head_object(
                    Bucket=S3_GOOD_BUCKET,
                    Key=good_bucket_path
                )
                # If no exception is raised, the image exists
                image_exists = True
                logger.info(f"Duplicate detected: {good_bucket_path} already exists in {S3_GOOD_BUCKET}")
            except Exception:
                # If an exception is raised, the image doesn't exist
                pass
                
            # Prepare metadata for upload
            extra_args = {
                'ContentType': 'image/webp',
                'Metadata': {
                    'review_status': review_status,
                    'upload_time': datetime.utcnow().isoformat()
                }
            }
            
            # Add uploader initials to metadata if available
            if uploader_initials:
                extra_args['Metadata']['uploader-initials'] = uploader_initials
            
            if image_exists:
                # If image already exists, upload to Issue bucket instead
                issue_bucket_path = f"{os.getenv('S3_ISSUE_BUCKET_PREFIX', '')}{processed_filename}"
                issue_bucket = os.getenv('S3_ISSUE_BUCKET')
                
                logger.info(f"Uploading duplicate image to {issue_bucket}/{issue_bucket_path}")
                s3_client.put_object(
                    Bucket=issue_bucket,
                    Key=issue_bucket_path,
                    Body=download_response.content,
                    **extra_args
                )
            else:
                # Upload to Good bucket only if it doesn't already exist
                logger.info(f"Uploading processed image to {S3_GOOD_BUCKET}/{good_bucket_path}")
                s3_client.put_object(
                    Bucket=S3_GOOD_BUCKET,
                    Key=good_bucket_path,
                    Body=download_response.content,
                    **extra_args
                )
            
            # Upload to Upload bucket
            logger.info(f"Uploading processed image to {S3_UPLOAD_BUCKET}/{upload_bucket_path}")
            s3_client.put_object(
                Bucket=S3_UPLOAD_BUCKET,
                Key=upload_bucket_path,
                Body=download_response.content,
                **extra_args
            )
            
            # Delete the original image from Temp bucket
            logger.info(f"Deleting original image from {S3_TEMP_BUCKET}/{s3_key}")
            s3_client.delete_object(
                Bucket=S3_TEMP_BUCKET,
                Key=s3_key
            )
            
            logger.info(f"Successfully processed {filename} and uploaded to Good and Upload buckets")
            return True
    
    except Exception as e:
        logger.error(f"Error processing image {s3_key}: {str(e)}")
        traceback.print_exc()
        return False

def check_temp_bucket():
    """Check the Temp bucket for images and process them if found"""
    try:
        if S3_TEMP_BUCKET_PREFIX:
            logger.info(f"Checking for images in {S3_TEMP_BUCKET}/{S3_TEMP_BUCKET_PREFIX}")
        else:
            logger.info(f"Checking for images in {S3_TEMP_BUCKET}")
        
        list_params = {
            'Bucket': S3_TEMP_BUCKET
        }
        
        if S3_TEMP_BUCKET_PREFIX:
            list_params['Prefix'] = S3_TEMP_BUCKET_PREFIX
            
        response = s3_client.list_objects_v2(**list_params)
        
        # Check if there are any objects
        if 'Contents' in response:
            # Filter for image files
            image_extensions = ('.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp')
            
            # All images in the Temp bucket need processing
            images = [
                obj for obj in response['Contents']
                if any(obj['Key'].lower().endswith(ext) for ext in image_extensions)
            ]
            
            # Process found images
            if images:
                logger.info(f"image found - {len(images)} images in the Temp bucket")
                
                # Process each image
                for img in images:
                    img_key = img['Key']
                    logger.info(f"Found image: {img_key} ({img['Size']} bytes)")
                    result = process_image(img_key)
                    if result:
                        logger.info(f"Successfully processed: {img_key}")
                    else:
                        logger.error(f"Failed to process: {img_key}")
            else:
                logger.info("No images found in the Temp bucket")
                
        else:
            logger.info("No objects found in the Temp bucket")
            
    except Exception as e:
        logger.error(f"Error checking Temp bucket: {e}")
        traceback.print_exc()

def run_scheduler():
    """Run the scheduler to check for images periodically"""
    logger.info("Starting bytescale worker service")
    
    schedule.every(30).seconds.do(check_temp_bucket)
    check_temp_bucket()
    
    while True:
        try:
            schedule.run_pending()
            time.sleep(1)
        except Exception as e:
            logger.error(f"Error in scheduler loop: {e}")
            traceback.print_exc()
            time.sleep(60)

if __name__ == "__main__":
    try:
        run_scheduler()
    except Exception as e:
        logger.error(f"Fatal error in main: {e}")
        traceback.print_exc() 