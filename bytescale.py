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
        prefix = 'tmp_bucket/'
        logger.info(f"Checking for images in {S3_TEMP_BUCKET} with prefix '{prefix}'")
        
        # List objects in the bucket using the specified prefix
        response = s3_client.list_objects_v2(
            Bucket=S3_TEMP_BUCKET,
            Prefix=prefix
        )
        
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
                logger.info(f"image found - {len(images)} images in the Temp bucket with prefix '{prefix}'")
                for img in images[:5]:  # Show details of first 5 images
                    logger.info(f"Image: {img['Key']} ({img['Size']} bytes)")
            else:
                logger.info(f"No images found in the Temp bucket with prefix '{prefix}'")
                
        else:
            logger.info(f"No objects found in the Temp bucket with prefix '{prefix}'")
            
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