#!/usr/bin/env python3
import os
import time
import boto3
import logging
import traceback
import sys
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
S3_TEMP_BUCKET_PREFIX = os.getenv("S3_TEMP_BUCKET_PREFIX")

# Validate required environment variables
missing_vars = []
if not AWS_ACCESS_KEY_ID: missing_vars.append("AWS_ACCESS_KEY_ID")
if not AWS_SECRET_ACCESS_KEY: missing_vars.append("AWS_SECRET_ACCESS_KEY")
if not AWS_REGION: missing_vars.append("AWS_REGION")
if not S3_TEMP_BUCKET: missing_vars.append("S3_TEMP_BUCKET")

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

def check_temp_bucket():
    """Check the Temp bucket for images"""
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
                if obj['Key'].lower().endswith(image_extensions)
            ]
            
            # Log found images
            if images:
                logger.info(f"image found - {len(images)} images in the Temp bucket")
                for img in images[:5]:  # Show details of first 5 images
                    logger.info(f"Image: {img['Key']} ({img['Size']} bytes)")
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