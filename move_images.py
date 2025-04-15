#!/usr/bin/env python3
import os
import boto3
import logging
from dotenv import load_dotenv
import sys

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
logger = logging.getLogger('move_images')

# Get environment variables
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")
S3_GOOD_BUCKET = os.getenv("S3_GOOD_BUCKET")
S3_GOOD_BUCKET_PREFIX = os.getenv("S3_GOOD_BUCKET_PREFIX", "")
S3_UPLOAD_BUCKET = os.getenv("S3_UPLOAD_BUCKET")
S3_UPLOAD_BUCKET_PREFIX = os.getenv("S3_UPLOAD_BUCKET_PREFIX", "")

logger.info(f"Source: {S3_UPLOAD_BUCKET}/{S3_UPLOAD_BUCKET_PREFIX}")
logger.info(f"Destination: {S3_GOOD_BUCKET}/{S3_GOOD_BUCKET_PREFIX}")

# Validate required environment variables
missing_vars = []
if not AWS_ACCESS_KEY_ID: missing_vars.append("AWS_ACCESS_KEY_ID")
if not AWS_SECRET_ACCESS_KEY: missing_vars.append("AWS_SECRET_ACCESS_KEY")
if not AWS_REGION: missing_vars.append("AWS_REGION")
if not S3_GOOD_BUCKET: missing_vars.append("S3_GOOD_BUCKET")
if not S3_UPLOAD_BUCKET: missing_vars.append("S3_UPLOAD_BUCKET")

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
    sys.exit(1)

def move_images():
    """Move all images from Upload bucket to Good bucket"""
    try:
        logger.info(f"Looking for images in {S3_UPLOAD_BUCKET}/{S3_UPLOAD_BUCKET_PREFIX}")
        
        list_params = {
            'Bucket': S3_UPLOAD_BUCKET
        }
        
        if S3_UPLOAD_BUCKET_PREFIX:
            list_params['Prefix'] = S3_UPLOAD_BUCKET_PREFIX
            
        response = s3_client.list_objects_v2(**list_params)
        
        if 'Contents' not in response:
            logger.info("No objects found in the Upload bucket")
            return
            
        # Filter for image files
        image_extensions = ('.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp')
        images = [
            obj for obj in response['Contents']
            if any(obj['Key'].lower().endswith(ext) for ext in image_extensions)
        ]
        
        if not images:
            logger.info("No images found in the Upload bucket")
            return
            
        logger.info(f"Found {len(images)} images to move")
        
        # Process each image
        moved_count = 0
        for img in images:
            source_key = img['Key']
            
            # Get the filename from the key
            filename = source_key.split('/')[-1]
            
            # Construct destination key
            destination_key = f"{S3_GOOD_BUCKET_PREFIX}{filename}" if S3_GOOD_BUCKET_PREFIX else filename
            
            logger.info(f"Moving {source_key} to {S3_GOOD_BUCKET}/{destination_key}")
            
            try:
                # Get the object and its metadata
                response = s3_client.get_object(
                    Bucket=S3_UPLOAD_BUCKET,
                    Key=source_key
                )
                
                # Copy the object to the destination
                s3_client.put_object(
                    Body=response['Body'].read(),
                    Bucket=S3_GOOD_BUCKET,
                    Key=destination_key,
                    ContentType=response.get('ContentType', 'image/jpeg'),
                    Metadata=response.get('Metadata', {})
                )
                
                # Delete the original object
                s3_client.delete_object(
                    Bucket=S3_UPLOAD_BUCKET,
                    Key=source_key
                )
                
                logger.info(f"Successfully moved {filename}")
                moved_count += 1
                
            except Exception as e:
                logger.error(f"Error moving {filename}: {str(e)}")
                
        logger.info(f"Successfully moved {moved_count} of {len(images)} images")
        
    except Exception as e:
        logger.error(f"Error moving images: {str(e)}")

if __name__ == "__main__":
    move_images() 