#!/usr/bin/env python3
import os
import time
import boto3
import logging
import traceback
import redis
import hashlib
from datetime import datetime
from botocore.exceptions import ClientError
from dotenv import load_dotenv
import schedule

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('filename_validator')

# AWS Configuration
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")
S3_UPLOAD_BUCKET = os.getenv("S3_UPLOAD_BUCKET")
S3_ISSUE_BUCKET = os.getenv("S3_ISSUE_BUCKET")
S3_GOOD_BUCKET = os.getenv("S3_GOOD_BUCKET")

# Redis Configuration
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')

# Debug variables
DEBUG_FILE = "validator_debug.txt"
LAST_RUN_FILE = "validator_last_run.txt"

# Redis prefixes
REDIS_FILENAME_PREFIX = "filename:"
REDIS_CACHE_EXPIRY = 60 * 60 * 24 * 7  # 7 days

# Initialize Redis
try:
    redis_client = redis.from_url(REDIS_URL)
    # Test connection
    redis_client.ping()
    print("Connected to Redis successfully")
except Exception as e:
    print(f"Warning: Redis connection failed: {e}")
    redis_client = None

# Print configuration for debugging
print(f"Starting filename validator with configuration:")
print(f"AWS_REGION: {AWS_REGION}")
print(f"S3_UPLOAD_BUCKET: {S3_UPLOAD_BUCKET}")
print(f"S3_ISSUE_BUCKET: {S3_ISSUE_BUCKET}")
print(f"S3_GOOD_BUCKET: {S3_GOOD_BUCKET}")
print(f"REDIS_URL: {REDIS_URL}")
print(f"Redis Connected: {redis_client is not None}")

def write_debug_info(message):
    """Write debug information to S3 bucket"""
    try:
        timestamp = datetime.now().isoformat()
        debug_message = f"[{timestamp}] {message}\n"
        
        # First, try to read existing debug file
        try:
            response = s3_client.get_object(Bucket=S3_ISSUE_BUCKET, Key=DEBUG_FILE)
            existing_content = response['Body'].read().decode('utf-8')
            # Keep only the last 50 lines to prevent the file from growing too large
            lines = existing_content.splitlines()[-50:]
            existing_content = '\n'.join(lines) + '\n'
        except:
            existing_content = ""
        
        # Write updated content
        s3_client.put_object(
            Bucket=S3_ISSUE_BUCKET,
            Key=DEBUG_FILE,
            Body=existing_content + debug_message
        )
    except Exception as e:
        print(f"Failed to write debug info: {e}")

def update_last_run():
    """Update the last run timestamp file"""
    try:
        timestamp = datetime.now().isoformat()
        s3_client.put_object(
            Bucket=S3_ISSUE_BUCKET,
            Key=LAST_RUN_FILE,
            Body=f"Last run: {timestamp}"
        )
    except Exception as e:
        print(f"Failed to update last run timestamp: {e}")

try:
    # Initialize S3 client
    s3_client = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )
    
    # Make sure required prefixes/directories exist
    try:
        # Create an empty object to ensure the issue_files/ prefix exists
        if S3_ISSUE_BUCKET:
            s3_client.put_object(
                Bucket=S3_ISSUE_BUCKET,
                Key="issue_files/.placeholder",
                Body="Placeholder to ensure directory exists"
            )
            print(f"Ensured issue_files/ prefix exists in {S3_ISSUE_BUCKET}")
    except Exception as e:
        print(f"Warning: Could not initialize issue_files/ prefix: {e}")
    
    # Write initial startup message
    write_debug_info("Filename validator started")
    
except Exception as e:
    print(f"Failed to initialize S3 client: {e}")
    traceback.print_exc()

def check_filename_format(filename):
    """
    Check if a filename matches the required format: {perf_id}.{ven_id}.webp
    where perf_id and ven_id are numeric.
    
    Returns True if the format is correct, False otherwise.
    """
    if not filename.lower().endswith('.webp'):
        return False
        
    # Remove the .webp extension
    base_name = filename[:-5] if filename.lower().endswith('.webp') else filename
    
    # Split by dot and check if we have exactly two parts
    parts = base_name.split('.')
    if len(parts) != 2:
        return False
        
    # Check if both parts are numeric
    try:
        int(parts[0])  # perf_id should be a number
        int(parts[1])  # ven_id should be a number
        return True
    except ValueError:
        return False

def refresh_good_images_cache():
    """
    Refresh the Redis cache with all images in the good bucket
    """
    if not redis_client:
        write_debug_info("Redis not available, skipping cache refresh")
        return
        
    try:
        write_debug_info("Refreshing Redis cache with good bucket images")
        
        # List all objects in the good bucket
        paginator = s3_client.get_paginator('list_objects_v2')
        good_prefix = 'images/performer-at-venue/detail/'
        
        # Start with a clean cache
        pattern = f"{REDIS_FILENAME_PREFIX}*"
        cursor = '0'
        while cursor != 0:
            cursor, keys = redis_client.scan(cursor=cursor, match=pattern, count=1000)
            if keys:
                redis_client.delete(*keys)
            cursor = int(cursor)
        
        # Fill cache with good bucket files
        count = 0
        # Dictionary to store normalized base filenames (without extension)
        good_files = set()
        
        for page in paginator.paginate(Bucket=S3_GOOD_BUCKET, Prefix=good_prefix):
            if 'Contents' in page:
                for item in page['Contents']:
                    filename = item['Key'].split('/')[-1]
                    if filename.lower().endswith('.webp'):
                        # Extract base name without extension and folder
                        base_name = os.path.splitext(filename)[0]
                        
                        # Cache the full filename for exact matching
                        redis_key = f"{REDIS_FILENAME_PREFIX}{filename}"
                        redis_client.set(redis_key, item['Key'], ex=REDIS_CACHE_EXPIRY)
                        
                        # Also cache just the IDs part for base comparison
                        if '.' in base_name:  # If it has performer.venue format
                            good_files.add(base_name)
                            cache_key = f"{REDIS_FILENAME_PREFIX}base:{base_name}"
                            redis_client.set(cache_key, "1", ex=REDIS_CACHE_EXPIRY)
                        
                        count += 1
        
        write_debug_info(f"Refreshed Redis cache with {count} images from good bucket")
    except Exception as e:
        error_msg = f"Error refreshing good images cache: {str(e)}"
        write_debug_info(error_msg)
        logger.error(error_msg)
        traceback.print_exc()

def is_duplicate(filename):
    """
    Check if a filename already exists in the good bucket.
    Checks both exact filename match and ID-based match.
    
    Returns True if it's a duplicate, False otherwise
    """
    if not redis_client:
        return False
        
    try:
        # First check exact filename match
        redis_key = f"{REDIS_FILENAME_PREFIX}{filename}"
        if redis_client.exists(redis_key) == 1:
            write_debug_info(f"Found exact duplicate: {filename}")
            return True
            
        # Then check ID-based match by extracting base name (without extension)
        base_name = os.path.splitext(filename)[0]
        if '.' in base_name:  # If it has performer.venue format
            base_key = f"{REDIS_FILENAME_PREFIX}base:{base_name}"
            if redis_client.exists(base_key) == 1:
                write_debug_info(f"Found ID-based duplicate: {base_name}")
                return True
                
        return False
    except Exception as e:
        write_debug_info(f"Error checking Redis for duplicate: {str(e)}")
        return False

def move_to_issue_bucket(object_key, reason="improperly formatted"):
    """
    Move a file from the Upload bucket to the Issue bucket.
    If it's a duplicate, add "_dupe" to the filename.
    """
    try:
        # Keep the same filename in the issue bucket
        filename = object_key.split('/')[-1]
        
        # If it's a duplicate, add "_dupe" to the filename
        if reason == "duplicate":
            name_part, ext_part = os.path.splitext(filename)
            filename = f"{name_part}_dupe{ext_part}"
        
        dest_key = f"issue_files/{filename}"
        
        write_debug_info(f"Moving {reason} file {object_key} to issue bucket as {dest_key}")
        
        # Copy to issue bucket
        copy_source = {'Bucket': S3_UPLOAD_BUCKET, 'Key': object_key}
        
        s3_client.copy_object(
            CopySource=copy_source,
            Bucket=S3_ISSUE_BUCKET,
            Key=dest_key
        )
        
        # Delete from upload bucket
        s3_client.delete_object(
            Bucket=S3_UPLOAD_BUCKET,
            Key=object_key
        )
        
        write_debug_info(f"Successfully moved {object_key} to issue bucket as {dest_key}")
        return True
    except Exception as e:
        error_msg = f"Error moving {object_key} to issue bucket: {str(e)}"
        write_debug_info(error_msg)
        logger.error(error_msg)
        return False

def check_upload_bucket_filenames():
    """
    Check all files in the Upload bucket for proper naming format and duplicates.
    Move improperly formatted files to the Issue bucket.
    """
    try:
        write_debug_info("===== Starting new validation cycle =====")
        update_last_run()
        
        # Step 1: Refresh Redis cache with good bucket images
        if redis_client:
            refresh_good_images_cache()
        
        write_debug_info("Checking upload bucket for improperly formatted filenames and duplicates")
        
        # List objects in the upload bucket
        prefix = 'temp_performer_at_venue_images/'
        response = s3_client.list_objects_v2(
            Bucket=S3_UPLOAD_BUCKET,
            Prefix=prefix
        )
        
        if 'Contents' not in response:
            write_debug_info("No files found in upload bucket")
            return
            
        webp_files = [obj for obj in response['Contents'] if obj['Key'].lower().endswith('.webp')]
        issue_count = 0
        duplicate_count = 0
        
        write_debug_info(f"Found {len(webp_files)} webp files in upload bucket to check")
        
        for obj in webp_files:
            object_key = obj['Key']
            filename = object_key.split('/')[-1]
            
            # First check if the filename matches the required format
            if not check_filename_format(filename):
                write_debug_info(f"Found improperly formatted filename: {filename}")
                if move_to_issue_bucket(object_key, "improperly formatted"):
                    issue_count += 1
                continue
                
            # Then check if it's a duplicate
            if redis_client and is_duplicate(filename):
                write_debug_info(f"Found duplicate filename: {filename}")
                if move_to_issue_bucket(object_key, "duplicate"):
                    duplicate_count += 1
        
        write_debug_info(f"Moved {issue_count} improperly formatted files to issue bucket")
        write_debug_info(f"Moved {duplicate_count} duplicate files to issue bucket")
        write_debug_info("===== Completed validation cycle =====")
        
    except Exception as e:
        error_msg = f"Error checking upload bucket filenames: {str(e)}"
        write_debug_info(error_msg)
        traceback.print_exc()
        logger.error(error_msg)

def run_scheduler():
    """Run the scheduler to validate filenames periodically"""
    print("Starting filename validation service")
    write_debug_info("Scheduler started - will run every 30 seconds")
    
    # Schedule the validation job to run every 30 seconds
    schedule.every(30).seconds.do(check_upload_bucket_filenames)
    
    # Run once immediately on startup
    try:
        check_upload_bucket_filenames()
    except Exception as e:
        print(f"Error in initial run: {e}")
        write_debug_info(f"Error in initial run: {e}")
        traceback.print_exc()
    
    # Keep the script running
    while True:
        try:
            schedule.run_pending()
            time.sleep(1)
        except Exception as e:
            print(f"Error in scheduler loop: {e}")
            write_debug_info(f"Error in scheduler loop: {e}")
            traceback.print_exc()
            time.sleep(60)  # Wait a bit longer if there's an error

if __name__ == "__main__":
    try:
        run_scheduler()
    except Exception as e:
        print(f"Fatal error in main: {e}")
        write_debug_info(f"Fatal error in main: {e}")
        traceback.print_exc() 