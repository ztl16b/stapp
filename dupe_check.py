#!/usr/bin/env python3
import os
import boto3
import logging
import redis
import time
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('duplicate_checker')

# AWS Configuration
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")
S3_UPLOAD_BUCKET = os.getenv("S3_UPLOAD_BUCKET")
S3_ISSUE_BUCKET = os.getenv("S3_ISSUE_BUCKET")
S3_GOOD_BUCKET = os.getenv("S3_GOOD_BUCKET")

# Redis Configuration
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')
REDIS_FILENAME_PREFIX = "filename:"
REDIS_CACHE_EXPIRY = 60 * 60 * 24  # 1 day

# Initialize S3 client
s3_client = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION
)

# Initialize Redis
try:
    redis_client = redis.from_url(REDIS_URL)
    redis_client.ping()
    logger.info("Connected to Redis successfully")
except Exception as e:
    logger.error(f"Redis connection failed: {e}")
    redis_client = None
    logger.info("Running without Redis cache - will use direct S3 comparison (slower)")

def load_good_bucket_filenames():
    """
    Load all filenames from the good bucket into a set for quick lookups.
    Returns both a set of full filenames and a set of base filenames (without extensions).
    """
    logger.info("Loading filenames from Good bucket...")
    start_time = time.time()
    
    good_filenames = set()
    good_base_filenames = set()
    good_prefix = 'images/performer-at-venue/detail/'
    
    # If Redis is available, first try to use it
    if redis_client:
        logger.info("Loading good bucket filenames into Redis...")
        
        paginator = s3_client.get_paginator('list_objects_v2')
        file_count = 0
        
        # Use pipeline for batch Redis operations
        pipeline = redis_client.pipeline()
        
        for page in paginator.paginate(Bucket=S3_GOOD_BUCKET, Prefix=good_prefix):
            if 'Contents' in page:
                for item in page['Contents']:
                    key = item['Key']
                    if not key.lower().endswith('.webp'):
                        continue
                        
                    filename = key.split('/')[-1]
                    good_filenames.add(filename)
                    
                    # Also extract base name (without extension)
                    base_name = os.path.splitext(filename)[0]
                    if '.' in base_name:  # If it has performer.venue format
                        good_base_filenames.add(base_name)
                        
                    # Add to Redis
                    redis_key = f"{REDIS_FILENAME_PREFIX}{filename}"
                    pipeline.set(redis_key, "1", ex=REDIS_CACHE_EXPIRY)
                    
                    # Also cache base name
                    if '.' in base_name:
                        base_key = f"{REDIS_FILENAME_PREFIX}base:{base_name}"
                        pipeline.set(base_key, "1", ex=REDIS_CACHE_EXPIRY)
                    
                    file_count += 1
                    
                    # Execute pipeline in batches to avoid memory issues
                    if file_count % 1000 == 0:
                        pipeline.execute()
                        pipeline = redis_client.pipeline()
                        logger.info(f"Processed {file_count} files so far...")
        
        # Execute any remaining commands
        pipeline.execute()
    else:
        # No Redis, just load into memory
        paginator = s3_client.get_paginator('list_objects_v2')
        file_count = 0
        
        for page in paginator.paginate(Bucket=S3_GOOD_BUCKET, Prefix=good_prefix):
            if 'Contents' in page:
                for item in page['Contents']:
                    key = item['Key']
                    if not key.lower().endswith('.webp'):
                        continue
                        
                    filename = key.split('/')[-1]
                    good_filenames.add(filename)
                    
                    # Also extract base name (without extension)
                    base_name = os.path.splitext(filename)[0]
                    if '.' in base_name:  # If it has performer.venue format
                        good_base_filenames.add(base_name)
                    
                    file_count += 1
                    if file_count % 1000 == 0:
                        logger.info(f"Processed {file_count} files so far...")
    
    elapsed = time.time() - start_time
    logger.info(f"Loaded {len(good_filenames)} filenames from Good bucket in {elapsed:.2f} seconds")
    
    return good_filenames, good_base_filenames

def is_duplicate(filename, good_filenames, good_base_filenames):
    """Check if a file is a duplicate based on filename or base name"""
    # First try Redis for faster lookups
    if redis_client:
        # Check exact filename match
        redis_key = f"{REDIS_FILENAME_PREFIX}{filename}"
        if redis_client.exists(redis_key) == 1:
            return True
            
        # Check base name match
        base_name = os.path.splitext(filename)[0]
        if '.' in base_name:
            base_key = f"{REDIS_FILENAME_PREFIX}base:{base_name}"
            if redis_client.exists(base_key) == 1:
                return True
        
        return False
    else:
        # Check in memory sets
        if filename in good_filenames:
            return True
            
        # Check base name
        base_name = os.path.splitext(filename)[0]
        if base_name in good_base_filenames:
            return True
            
        return False

def process_file(obj, good_filenames, good_base_filenames):
    """Process a single file and check if it's a duplicate"""
    object_key = obj['Key']
    filename = object_key.split('/')[-1]
    
    if is_duplicate(filename, good_filenames, good_base_filenames):
        return {
            'key': object_key,
            'filename': filename,
            'is_duplicate': True
        }
    else:
        return {
            'key': object_key,
            'filename': filename,
            'is_duplicate': False
        }

def move_duplicate_to_issue(object_key):
    """Move a duplicate file from Upload bucket to Issue bucket"""
    try:
        filename = object_key.split('/')[-1]
        name_part, ext_part = os.path.splitext(filename)
        dest_key = f"issue_files/{name_part}_dupe{ext_part}"
        
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
        
        logger.info(f"Moved duplicate file: {filename} to Issue bucket")
        return True
    except Exception as e:
        logger.error(f"Error moving {object_key} to Issue bucket: {e}")
        return False

def check_duplicates():
    """
    Main function to check for duplicates between Upload and Good buckets
    """
    logger.info("Starting quick duplicate check...")
    start_time = time.time()
    
    # First load all good bucket filenames
    good_filenames, good_base_filenames = load_good_bucket_filenames()
    
    # Now check the upload bucket
    prefix = 'temp_performer_at_venue_images/'
    
    try:
        # List all webp files in the upload bucket
        response = s3_client.list_objects_v2(
            Bucket=S3_UPLOAD_BUCKET,
            Prefix=prefix
        )
        
        if 'Contents' not in response:
            logger.info("No files found in Upload bucket")
            return
        
        webp_files = [obj for obj in response['Contents'] if obj['Key'].lower().endswith('.webp')]
        logger.info(f"Found {len(webp_files)} webp files in Upload bucket")
        
        # Use thread pool for parallel processing
        duplicate_count = 0
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Process files in parallel
            results = list(executor.map(
                lambda obj: process_file(obj, good_filenames, good_base_filenames), 
                webp_files
            ))
            
            # Process duplicates
            duplicates = [r for r in results if r['is_duplicate']]
            logger.info(f"Found {len(duplicates)} duplicate files")
            
            if duplicates:
                logger.info("Moving duplicate files to Issue bucket...")
                for dup in duplicates:
                    if move_duplicate_to_issue(dup['key']):
                        duplicate_count += 1
        
        elapsed = time.time() - start_time
        logger.info(f"Duplicate check completed in {elapsed:.2f} seconds")
        logger.info(f"Moved {duplicate_count} duplicate files to Issue bucket")
        
    except Exception as e:
        logger.error(f"Error checking duplicates: {e}")

if __name__ == "__main__":
    logger.info("=== Quick Duplicate Checker ===")
    check_duplicates()
    logger.info("Done!") 