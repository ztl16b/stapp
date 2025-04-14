#!/usr/bin/env python3
import os
import time
import boto3
import logging
import traceback
import sys
import re
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    print("WARNING: Redis package not available, using in-memory cache instead")
import urllib.parse
from datetime import datetime, timedelta
from botocore.exceptions import ClientError
from dotenv import load_dotenv
import schedule

# Configuration
MAX_WORKERS = 5
BATCH_SIZE = 50
REDIS_CACHE_TTL = 3600  # Cache TTL in seconds (1 hour)
CACHE_KEY_PREFIX = "good_bucket_files:"
USE_IN_MEMORY_CACHE = False
in_memory_cache = {}
in_memory_cache_timestamp = None

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
logger = logging.getLogger('dupe_checker')

# Load AWS configuration
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")
S3_GOOD_BUCKET = os.getenv("S3_GOOD_BUCKET")
S3_UPLOAD_BUCKET = os.getenv("S3_UPLOAD_BUCKET")
S3_ISSUE_BUCKET = os.getenv("S3_ISSUE_BUCKET")

# Redis configuration
REDIS_URL = os.getenv("REDIS_URL")

# Debug files
DEBUG_FILE = "dupe_check_debug.txt"
LAST_RUN_FILE = "dupe_check_last_run.txt"
GOOD_PREFIX = "images/performer-at-venue/detail/"
UPLOAD_PREFIX = "temp_performer_at_venue_images/"
ISSUE_PREFIX = "issue_files/"

# Validate environment variables
missing_vars = []
if not AWS_ACCESS_KEY_ID: missing_vars.append("AWS_ACCESS_KEY_ID")
if not AWS_SECRET_ACCESS_KEY: missing_vars.append("AWS_SECRET_ACCESS_KEY")
if not AWS_REGION: missing_vars.append("AWS_REGION")
if not S3_GOOD_BUCKET: missing_vars.append("S3_GOOD_BUCKET")
if not S3_UPLOAD_BUCKET: missing_vars.append("S3_UPLOAD_BUCKET")
if not S3_ISSUE_BUCKET: missing_vars.append("S3_ISSUE_BUCKET")

# Make Redis optional
if not REDIS_URL and REDIS_AVAILABLE:
    print("WARNING: REDIS_URL not set, using in-memory cache instead")
    USE_IN_MEMORY_CACHE = True
elif not REDIS_AVAILABLE:
    USE_IN_MEMORY_CACHE = True

if missing_vars:
    error_msg = f"ERROR: Missing required environment variables: {', '.join(missing_vars)}"
    print(error_msg)
    logger.error(error_msg)
    sys.exit(1)

def write_debug_info(message):
    """Write debug information to S3 bucket and console"""
    timestamp = datetime.now().isoformat()
    debug_message = f"[{timestamp}] {message}"
    print(debug_message)
    
    try:
        try:
            response = s3_client.get_object(Bucket=S3_UPLOAD_BUCKET, Key=DEBUG_FILE)
            existing_content = response['Body'].read().decode('utf-8')
            lines = existing_content.splitlines()[-50:]
            existing_content = '\n'.join(lines) + '\n'
        except Exception as e:
            existing_content = ""
        
        s3_client.put_object(
            Bucket=S3_UPLOAD_BUCKET,
            Key=DEBUG_FILE,
            Body=existing_content + debug_message + "\n"
        )
    except Exception as e:
        print(f"Failed to write debug info to S3: {e}")

def update_last_run():
    """Update the last run timestamp file"""
    try:
        timestamp = datetime.now().isoformat()
        s3_client.put_object(
            Bucket=S3_UPLOAD_BUCKET,
            Key=LAST_RUN_FILE,
            Body=f"Last run: {timestamp}"
        )
    except Exception as e:
        print(f"Failed to update last run timestamp: {e}")

# Initialize S3 client and Redis client
try:
    s3_client = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )
    
    s3_upload_config = boto3.s3.transfer.TransferConfig(
        multipart_threshold=8 * 1024 * 1024,
        max_concurrency=10,
        multipart_chunksize=8 * 1024 * 1024,
        use_threads=True
    )
    
    # Initialize Redis client with SSL certificate verification disabled
    redis_client = None
    if not USE_IN_MEMORY_CACHE and REDIS_AVAILABLE:
        try:
            print("Attempting to connect to Redis...")
            import ssl
            import redis.connection
            
            # Monkey patch the Redis client to disable SSL certificate verification globally
            redis.connection.ssl._create_default_https_context = ssl._create_unverified_context
            
            # Create Redis connection with SSL verification disabled
            redis_client = redis.from_url(
                REDIS_URL,
                ssl_cert_reqs=None,
                ssl_ca_certs=None
            )
            
            # Test connection
            redis_client.ping()
            print("Redis connection successful!")
            
        except Exception as e:
            error_msg = f"WARNING: Failed to connect to Redis: {str(e)}, using in-memory cache instead"
            print(error_msg)
            traceback.print_exc()  
            USE_IN_MEMORY_CACHE = True
    else:
        print("Using in-memory cache for file storage")
    
    try:
        s3_client.list_buckets()
        print("S3 connection successful!")
        write_debug_info("Duplicate checker started successfully")
    except Exception as e:
        error_msg = f"ERROR: Failed to connect to S3: {str(e)}"
        print(error_msg)
        traceback.print_exc()
        sys.exit(1)
    
except Exception as e:
    print(f"ERROR: Failed to initialize services: {str(e)}")
    traceback.print_exc()
    sys.exit(1)

def extract_base_filename(s3_key):
    """Extract just the base filename without path and extension"""
    filename = s3_key.split('/')[-1]
    # Strip extension
    base_name = os.path.splitext(filename)[0]
    return base_name

def cache_good_bucket_files():
    """
    Cache all files from the GOOD bucket in Redis or in-memory
    Returns a set of base filenames (without extension)
    """
    global in_memory_cache_timestamp, in_memory_cache
    
    # Check if we can use the in-memory cache
    if USE_IN_MEMORY_CACHE and in_memory_cache_timestamp:
        cache_age = datetime.now() - in_memory_cache_timestamp
        if cache_age.total_seconds() < REDIS_CACHE_TTL:
            write_debug_info("Using in-memory cache for good bucket file list")
            return in_memory_cache
    
    # Check if we have a recent Redis cache
    if not USE_IN_MEMORY_CACHE and redis_client:
        cache_key = f"{CACHE_KEY_PREFIX}all"
        cached_files = redis_client.get(cache_key)
        if cached_files:
            write_debug_info("Using Redis cache for good bucket file list")
            return set(cached_files.decode('utf-8').splitlines())
    
    write_debug_info(f"Caching files from {S3_GOOD_BUCKET} with prefix {GOOD_PREFIX}")
    good_files = set()
    
    try:
        paginator = s3_client.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=S3_GOOD_BUCKET, Prefix=GOOD_PREFIX)
        
        file_count = 0
        for page in pages:
            if 'Contents' in page:
                for obj in page['Contents']:
                    base_name = extract_base_filename(obj['Key'])
                    good_files.add(base_name)
                    file_count += 1
        
        # Cache the list
        if good_files:
            if USE_IN_MEMORY_CACHE:
                in_memory_cache = good_files
                in_memory_cache_timestamp = datetime.now()
                write_debug_info(f"Cached {file_count} files in memory")
            elif redis_client:
                # Store as newline-separated string in Redis
                redis_client.setex(
                    f"{CACHE_KEY_PREFIX}all",
                    REDIS_CACHE_TTL,
                    '\n'.join(good_files)
                )
                write_debug_info(f"Cached {file_count} files in Redis")
        
        return good_files
    
    except Exception as e:
        error_msg = f"Error caching good bucket files: {e}"
        write_debug_info(error_msg)
        logger.error(error_msg)
        traceback.print_exc()
        return set()

def list_upload_bucket_files():
    """List all files in the upload bucket sorted by last modified date (newest first)"""
    try:
        write_debug_info(f"Listing files in {S3_UPLOAD_BUCKET} with prefix {UPLOAD_PREFIX}")
        
        all_files = []
        
        paginator = s3_client.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=S3_UPLOAD_BUCKET, Prefix=UPLOAD_PREFIX)
        
        for page in pages:
            if 'Contents' in page:
                all_files.extend(page['Contents'])
        
        # Sort files by last modified date, newest first
        all_files.sort(key=lambda x: x['LastModified'], reverse=True)
        
        write_debug_info(f"Found {len(all_files)} files in the upload bucket")
        
        return all_files
    except Exception as e:
        error_msg = f"Error listing objects in upload bucket: {e}"
        write_debug_info(error_msg)
        logger.error(error_msg)
        traceback.print_exc()
        return []

def move_to_issue_bucket(s3_key, reason):
    """Move a file from upload bucket to issue bucket"""
    try:
        filename = s3_key.split('/')[-1]
        write_debug_info(f"Moving duplicate file: {filename}, Reason: {reason}")
        
        # Get file metadata to preserve
        try:
            response = s3_client.head_object(Bucket=S3_UPLOAD_BUCKET, Key=s3_key)
            metadata = response.get('Metadata', {})
            content_type = response.get('ContentType', 'image/webp')
            
            # Add duplicate reason to metadata
            metadata['duplicate-reason'] = reason
        except Exception as e:
            write_debug_info(f"Error getting metadata for {s3_key}: {e}")
            metadata = {'duplicate-reason': reason}
            content_type = 'image/webp'
        
        # Prepare for copy operation
        destination_key = f"{ISSUE_PREFIX}{filename}"
        write_debug_info(f"Moving file to issue bucket: {S3_ISSUE_BUCKET}/{destination_key}")
        
        # Copy file to issue bucket
        copy_source = {'Bucket': S3_UPLOAD_BUCKET, 'Key': s3_key}
        extra_args = {'Metadata': metadata, 'MetadataDirective': 'REPLACE', 'ContentType': content_type}
        
        s3_client.copy_object(
            CopySource=copy_source,
            Bucket=S3_ISSUE_BUCKET,
            Key=destination_key,
            **extra_args
        )
        
        # Delete file from upload bucket
        s3_client.delete_object(Bucket=S3_UPLOAD_BUCKET, Key=s3_key)
        
        write_debug_info(f"Successfully moved {filename} to issue bucket")
        return {
            'status': 'moved',
            'key': s3_key,
            'destination': destination_key,
            'reason': reason
        }
    except Exception as e:
        error_msg = f"Error moving file {s3_key}: {str(e)}"
        write_debug_info(f"ERROR: {error_msg}")
        traceback.print_exc()
        logger.error(error_msg)
        return {
            'status': 'error',
            'key': s3_key,
            'error': str(e)
        }

def check_duplicates():
    """Process all files to check for duplicates"""
    try:
        write_debug_info("\n===== Starting new duplicate check cycle =====")
        update_last_run()
        
        # First, cache the good bucket files
        good_files = cache_good_bucket_files()
        if not good_files:
            write_debug_info("No files found in good bucket or failed to cache")
        
        # Get files from upload bucket
        upload_files = list_upload_bucket_files()
        
        if not upload_files:
            write_debug_info("No files found in upload bucket")
            return
        
        total_files = len(upload_files)
        write_debug_info(f"Found {total_files} files to check for duplicates")
        
        not_duplicate_count = 0
        duplicate_count = 0
        error_count = 0
        
        # Process files in batches but continue until all are processed
        for i in range(0, total_files, BATCH_SIZE):
            current_batch = upload_files[i:i+BATCH_SIZE]
            batch_num = (i // BATCH_SIZE) + 1
            total_batches = (total_files + BATCH_SIZE - 1) // BATCH_SIZE
            
            write_debug_info(f"Processing batch {batch_num} of {total_batches} ({len(current_batch)} files)")
            
            for file in current_batch:
                file_key = file['Key']
                base_name = extract_base_filename(file_key)
                
                # Check if this file exists in the good bucket
                if base_name in good_files:
                    # This is a duplicate
                    result = move_to_issue_bucket(file_key, "Duplicate of file in good bucket")
                    if result['status'] == 'moved':
                        duplicate_count += 1
                    else:
                        error_count += 1
                else:
                    # Not a duplicate
                    not_duplicate_count += 1
                    write_debug_info(f"Not a duplicate: {file_key.split('/')[-1]}")
                    
            # Log progress after each batch
            write_debug_info(f"Progress: {i + len(current_batch)}/{total_files} files processed")
        
        write_debug_info(f"Duplicate check complete:")
        write_debug_info(f"  - Not duplicates: {not_duplicate_count}")
        write_debug_info(f"  - Duplicates moved to issue bucket: {duplicate_count}")
        write_debug_info(f"  - Errors: {error_count}")
        write_debug_info("===== Completed duplicate check cycle =====\n")
        
    except Exception as e:
        error_msg = f"Error in check_duplicates: {str(e)}"
        write_debug_info(f"ERROR: {error_msg}")
        traceback.print_exc()
        logger.error(error_msg)

def run_scheduler():
    """Run the scheduler to check for duplicates periodically"""
    print("Starting duplicate check service")
    write_debug_info("Scheduler started - will run every 5 minutes")
    
    # Run every 5 minutes
    schedule.every(5).minutes.do(check_duplicates)
    
    try:
        # Run immediately on startup
        check_duplicates()
    except Exception as e:
        print(f"Error in initial run: {e}")
        write_debug_info(f"Error in initial run: {e}")
        traceback.print_exc()
    
    while True:
        try:
            schedule.run_pending()
            time.sleep(1)
        except Exception as e:
            print(f"Error in scheduler loop: {e}")
            write_debug_info(f"Error in scheduler loop: {e}")
            traceback.print_exc()
            time.sleep(60)

if __name__ == "__main__":
    try:
        run_scheduler()
    except Exception as e:
        print(f"Fatal error in main: {e}")
        write_debug_info(f"Fatal error in main: {e}")
        traceback.print_exc()
