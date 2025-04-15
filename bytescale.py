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
BYTESCALE_API_KEY = os.getenv("BYTESCALE_API_KEY")
BYTESCALE_UPLOAD_URL = os.getenv("BYTESCALE_UPLOAD_URL")

# Validate required environment variables
missing_vars = []
if not AWS_ACCESS_KEY_ID: missing_vars.append("AWS_ACCESS_KEY_ID")
if not AWS_SECRET_ACCESS_KEY: missing_vars.append("AWS_SECRET_ACCESS_KEY")
if not AWS_REGION: missing_vars.append("AWS_REGION")
if not S3_TEMP_BUCKET: missing_vars.append("S3_TEMP_BUCKET")
if not BYTESCALE_API_KEY: missing_vars.append("BYTESCALE_API_KEY")
if not BYTESCALE_UPLOAD_URL: missing_vars.append("BYTESCALE_UPLOAD_URL")

if missing_vars:
    error_msg = f"ERROR: Missing required environment variables: {', '.join(missing_vars)}"
    logger.error(error_msg)
    sys.exit(1)

logger.info(f"Using S3 bucket: {S3_TEMP_BUCKET}")
if S3_TEMP_BUCKET_PREFIX:
    logger.info(f"Using prefix: {S3_TEMP_BUCKET_PREFIX}")
else:
    logger.info("No prefix specified, will check entire bucket")

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
    """
    Process an image through Bytescale:
    1. Download from S3
    2. Upload to Bytescale
    3. Process using Bytescale Image API
    4. Download processed image
    5. Upload processed image back to S3
    """
    try:
        filename = s3_key.split('/')[-1]
        base_name, extension = os.path.splitext(filename)
        logger.info(f"Processing image: {filename}")
        
        # Download image from S3
        logger.info(f"Downloading {filename} from {S3_TEMP_BUCKET}")
        response = s3_client.get_object(Bucket=S3_TEMP_BUCKET, Key=s3_key)
        file_data = response['Body'].read()
        content_type = response.get('ContentType', 'image/jpeg')
        
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
            processed_filename = f"{base_name}_processed.webp"
            processed_key = f"{S3_TEMP_BUCKET_PREFIX}processed/{processed_filename}" if S3_TEMP_BUCKET_PREFIX else f"processed/{processed_filename}"
            
            logger.info(f"Uploading processed image to {S3_TEMP_BUCKET}/{processed_key}")
            s3_client.put_object(
                Bucket=S3_TEMP_BUCKET,
                Key=processed_key,
                Body=download_response.content,
                ContentType='image/webp'
            )
            
            logger.info(f"Successfully processed {filename} and uploaded as {processed_filename}")
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
        
        # List all objects in the bucket with specified prefix
        list_params = {
            'Bucket': S3_TEMP_BUCKET
        }
        
        # Only add prefix if it's set
        if S3_TEMP_BUCKET_PREFIX:
            list_params['Prefix'] = S3_TEMP_BUCKET_PREFIX
            
        response = s3_client.list_objects_v2(**list_params)
        
        # Check if there are any objects
        if 'Contents' in response:
            # Filter for image files
            image_extensions = ('.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp')
            images = [
                obj for obj in response['Contents']
                if obj['Key'].lower().endswith(image_extensions) and 
                "processed/" not in obj['Key']  # Skip already processed images
            ]
            
            # Process found images
            if images:
                logger.info(f"image found - {len(images)} images in the Temp bucket")
                
                # Create processed directory if it doesn't exist
                processed_dir = f"{S3_TEMP_BUCKET_PREFIX}processed/" if S3_TEMP_BUCKET_PREFIX else "processed/"
                # This is just to log the directory name, no actual file is created
                logger.info(f"Will store processed images in: {processed_dir}")
                
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
    
    # Schedule the check to run every 30 seconds
    schedule.every(30).seconds.do(check_temp_bucket)
    
    # Run the first check immediately
    check_temp_bucket()
    
    # Keep the scheduler running
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