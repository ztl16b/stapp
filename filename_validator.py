\#!/usr/bin/env python3
import os
import time
import boto3
import logging
import traceback
import redis
from datetime import datetime
import re
import sys
from botocore.exceptions import ClientError
from dotenv import load_dotenv
import schedule
from concurrent.futures import ThreadPoolExecutor

# Add a simple console output for debugging
print("Starting filename_validator.py script")

# Load environment variables
try:
    load_dotenv()
    print("Environment variables loaded")
except Exception as e:
    print(f"Error loading environment variables: {e}")

# Set up logging to output to stdout (needed for Heroku)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger('filename_validator')
logger.info("Logger initialized")

# Check required environment variables
required_env_vars = [
    "AWS_ACCESS_KEY_ID", 
    "AWS_SECRET_ACCESS_KEY", 
    "AWS_REGION", 
    "S3_UPLOAD_BUCKET", 
    "S3_ISSUE_BUCKET", 
    "S3_GOOD_BUCKET"
]

missing_vars = []
for var in required_env_vars:
    if not os.getenv(var):
        missing_vars.append(var)
        print(f"Missing required environment variable: {var}")

if missing_vars:
    error_msg = f"Missing required environment variables: {', '.join(missing_vars)}"
    print(error_msg)
    logger.error(error_msg)
    sys.exit(1)

# AWS Configuration
print("Setting up AWS configuration")
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")
S3_UPLOAD_BUCKET = os.getenv("S3_UPLOAD_BUCKET")
S3_ISSUE_BUCKET = os.getenv("S3_ISSUE_BUCKET")
S3_GOOD_BUCKET = os.getenv("S3_GOOD_BUCKET")

# Redis Configuration
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')
print(f"Redis URL: {REDIS_URL}")

# Debug variables
DEBUG_FILE = "validator_debug.txt"
LAST_RUN_FILE = "validator_last_run.txt"

# Redis prefixes
REDIS_FILENAME_PREFIX = "filename:"
REDIS_CACHE_EXPIRY = 60 * 60 * 24 * 7  # 7 days

# Maximum number of worker threads
MAX_WORKERS = 5  # Reduced from 10 to avoid memory issues on Heroku

# Initialize Redis
redis_client = None
try:
    print("Attempting to connect to Redis...")
    redis_client = redis.from_url(REDIS_URL)
    # Test connection
    redis_client.ping()
    print("Connected to Redis successfully")
    logger.info("Connected to Redis successfully")
except Exception as e:
    error_msg = f"Warning: Redis connection failed: {e}"
    print(error_msg)
    logger.warning(error_msg)
    redis_client = None

# Print configuration for debugging
logger.info(f"Starting filename validator with configuration:")
logger.info(f"AWS_REGION: {AWS_REGION}")
logger.info(f"S3_UPLOAD_BUCKET: {S3_UPLOAD_BUCKET}")
logger.info(f"S3_ISSUE_BUCKET: {S3_ISSUE_BUCKET}")
logger.info(f"S3_GOOD_BUCKET: {S3_GOOD_BUCKET}")
logger.info(f"REDIS_URL: {REDIS_URL}")
logger.info(f"Redis Connected: {redis_client is not None}")
logger.info(f"Using {MAX_WORKERS} worker threads for parallel processing")

# Initialize S3 client with error handling
s3_client = None
try:
    print("Initializing S3 client...")
    s3_client = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )
    
    # Test S3 connection by listing buckets
    print("Testing S3 connection...")
    s3_client.list_buckets()
    print("S3 connection successful")
    
    # Make sure required prefixes/directories exist
    if S3_ISSUE_BUCKET:
        try:
            print(f"Creating placeholder in {S3_ISSUE_BUCKET}/issue_files/...")
            s3_client.put_object(
                Bucket=S3_ISSUE_BUCKET,
                Key="issue_files/.placeholder",
                Body="Placeholder to ensure directory exists"
            )
            print(f"Successfully created placeholder in issue bucket")
            logger.info(f"Ensured issue_files/ prefix exists in {S3_ISSUE_BUCKET}")
        except Exception as e:
            error_msg = f"Warning: Could not create placeholder in issue bucket: {e}"
            print(error_msg)
            logger.warning(error_msg)
            # Continue anyway, this is non-fatal
    
except Exception as e:
    error_msg = f"Failed to initialize S3 client: {e}"
    print(error_msg)
    print(traceback.format_exc())
    logger.error(error_msg)
    logger.error(traceback.format_exc())
    sys.exit(1)

def write_debug_info(message):
    """Write debug information to S3 bucket and log"""
    try:
        timestamp = datetime.now().isoformat()
        debug_message = f"[{timestamp}] {message}\n"
        
        # First log to console/stdout
        print(f"DEBUG: {message}")
        logger.info(message)
        
        # Try to write to S3 if available
        if s3_client:
            try:
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
                logger.error(f"Failed to write debug info to S3: {e}")
                # Continue execution even if S3 write fails
    except Exception as e:
        logger.error(f"Failed in write_debug_info: {e}")

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
        logger.error(f"Failed to update last run timestamp: {e}")

def check_filename_format(filename):
    """
    Check if a filename matches the required format: {numeric}.{numeric}.webp
    where both parts are numeric.
    
    Returns True if the format is correct, False otherwise.
    """
    # Define pattern for {numbers}.{numbers}.webp
    pattern = r'^(\d+)\.(\d+)\.webp$'
    
    # Check if filename matches the pattern (case insensitive)
    match = re.match(pattern, filename, re.IGNORECASE)
    
    return match is not None

def load_good_bucket_filenames_to_memory():
    """
    Load all filenames from the good bucket directly into memory.
    This is a fallback method when Redis is not available.
    """
    try:
        write_debug_info("Loading good bucket filenames directly to memory (Redis not available)")
        start_time = time.time()
        
        good_filenames = set()
        good_base_filenames = set()
        good_prefix = 'images/performer-at-venue/detail/'
        
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
                        write_debug_info(f"Loaded {file_count} filenames to memory so far...")
        
        elapsed = time.time() - start_time
        write_debug_info(f"Loaded {len(good_filenames)} filenames from Good bucket to memory in {elapsed:.2f} seconds")
        
        return good_filenames, good_base_filenames
    except Exception as e:
        error_msg = f"Error loading good bucket filenames to memory: {str(e)}"
        write_debug_info(error_msg)
        logger.error(error_msg)
        traceback.print_exc()
        return set(), set()

def refresh_good_images_cache():
    """
    Refresh the Redis cache with all images in the good bucket.
    This is a critical function for ensuring duplicates are identified.
    """
    if not redis_client:
        write_debug_info("Redis not available, skipping cache refresh")
        return None, None
        
    try:
        write_debug_info("Starting Redis cache refresh with good bucket images")
        start_time = time.time()
        
        # For in-memory fallback if Redis has issues
        good_filenames = set()
        good_base_filenames = set()
        
        # List all objects in the good bucket
        paginator = s3_client.get_paginator('list_objects_v2')
        good_prefix = 'images/performer-at-venue/detail/'
        
        # Clear existing cache for a fresh start
        pattern = f"{REDIS_FILENAME_PREFIX}*"
        cursor = '0'
        while cursor != 0:
            cursor, keys = redis_client.scan(cursor=cursor, match=pattern, count=1000)
            if keys:
                redis_client.delete(*keys)
            cursor = int(cursor)
            
        write_debug_info("Cleared existing Redis cache, now rebuilding")
        
        # Fill cache with good bucket files
        count = 0
        
        for page in paginator.paginate(Bucket=S3_GOOD_BUCKET, Prefix=good_prefix):
            if 'Contents' in page:
                batch_size = len(page['Contents'])
                write_debug_info(f"Processing batch of {batch_size} files from good bucket")
                
                # Prepare batch operations
                pipeline = redis_client.pipeline()
                
                for item in page['Contents']:
                    filename = item['Key'].split('/')[-1]
                    if filename.lower().endswith('.webp'):
                        # Extract base name without extension
                        base_name = os.path.splitext(filename)[0]
                        
                        # Add to in-memory sets as fallback
                        good_filenames.add(filename)
                        if '.' in base_name:
                            good_base_filenames.add(base_name)
                        
                        # Cache the full filename for exact matching
                        redis_key = f"{REDIS_FILENAME_PREFIX}{filename}"
                        pipeline.set(redis_key, item['Key'], ex=REDIS_CACHE_EXPIRY)
                        
                        # Also cache just the IDs part for base comparison
                        if '.' in base_name:  # If it has performer.venue format
                            cache_key = f"{REDIS_FILENAME_PREFIX}base:{base_name}"
                            pipeline.set(cache_key, "1", ex=REDIS_CACHE_EXPIRY)
                        
                        count += 1
                
                # Execute batch redis operations
                pipeline.execute()
                write_debug_info(f"Added batch of {batch_size} files to Redis cache")
        
        elapsed = time.time() - start_time
        write_debug_info(f"Completed Redis cache refresh with {count} images from good bucket in {elapsed:.2f} seconds")
        return good_filenames, good_base_filenames
        
    except Exception as e:
        error_msg = f"Error refreshing good images cache: {str(e)}"
        write_debug_info(error_msg)
        logger.error(error_msg)
        traceback.print_exc()
        return None, None

def is_duplicate(filename, good_filenames=None, good_base_filenames=None):
    """
    Check if a filename already exists in the good bucket.
    Checks both exact filename match and ID-based match.
    
    Returns True if it's a duplicate, False otherwise
    """
    if redis_client:
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
            error_msg = f"Error checking Redis for duplicate: {str(e)}"
            write_debug_info(error_msg)
            logger.error(error_msg)
            # Fall back to in-memory check if Redis fails
            if good_filenames is not None and good_base_filenames is not None:
                return check_duplicate_in_memory(filename, good_filenames, good_base_filenames)
            return False
    elif good_filenames is not None and good_base_filenames is not None:
        # Use in-memory check if Redis is not available
        return check_duplicate_in_memory(filename, good_filenames, good_base_filenames)
    else:
        logger.warning("Cannot check for duplicates: Redis not available and no in-memory sets provided")
        return False

def check_duplicate_in_memory(filename, good_filenames, good_base_filenames):
    """Check for duplicates using in-memory sets (fallback method)"""
    try:
        # Check exact filename match
        if filename in good_filenames:
            write_debug_info(f"Found exact duplicate in memory: {filename}")
            return True
            
        # Check base name match
        base_name = os.path.splitext(filename)[0]
        if base_name in good_base_filenames:
            write_debug_info(f"Found ID-based duplicate in memory: {base_name}")
            return True
            
        return False
    except Exception as e:
        error_msg = f"Error checking in-memory for duplicate: {str(e)}"
        write_debug_info(error_msg)
        logger.error(error_msg)
        return False

def move_to_issue_bucket(object_key, reason="improperly formatted"):
    """
    Move a file from the Upload bucket to the Issue bucket.
    If it's a duplicate, add "_dupe" to the filename.
    Returns True on success, False on failure.
    """
    try:
        filename = object_key.split('/')[-1]
        original_filename = filename # Keep original for logging if needed
        
        # Modify filename if it's a duplicate
        if reason == "duplicate":
            name_part, ext_part = os.path.splitext(filename)
            filename = f"{name_part}_dupe{ext_part}"
        
        dest_key = f"issue_files/{filename}"
        
        write_debug_info(f"Attempting to move [{reason}] file '{object_key}' to '{dest_key}'")
        
        copy_source = {'Bucket': S3_UPLOAD_BUCKET, 'Key': object_key}
        copy_success = False
        delete_success = False

        # Copy to issue bucket
        try:
            write_debug_info(f"  Copying {object_key} from {S3_UPLOAD_BUCKET} to {S3_ISSUE_BUCKET}/{dest_key}...")
            s3_client.copy_object(
                CopySource=copy_source,
                Bucket=S3_ISSUE_BUCKET,
                Key=dest_key
            )
            copy_success = True
            write_debug_info(f"  Copy successful: {object_key} to {dest_key}")
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code')
            error_msg = e.response.get('Error', {}).get('Message')
            write_debug_info(f"  COPY FAILED for {object_key} to {dest_key}: {error_code} - {error_msg}")
            logger.error(f"ClientError during copy of {object_key}: {e}")
            return False # Exit if copy fails
        except Exception as e:
            write_debug_info(f"  COPY FAILED for {object_key} to {dest_key} with unexpected error: {str(e)}")
            logger.error(f"Unexpected error during copy of {object_key}: {e}")
            traceback.print_exc()
            return False # Exit if copy fails
        
        # Delete from upload bucket ONLY if copy was successful
        if copy_success:
            try:
                write_debug_info(f"  Deleting original {object_key} from {S3_UPLOAD_BUCKET}...")
                s3_client.delete_object(
                    Bucket=S3_UPLOAD_BUCKET,
                    Key=object_key
                )
                delete_success = True
                write_debug_info(f"  Delete successful: {object_key}")
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code')
                error_msg = e.response.get('Error', {}).get('Message')
                write_debug_info(f"  DELETE FAILED for {object_key}: {error_code} - {error_msg}. File was copied but original remains.")
                logger.error(f"ClientError during delete of {object_key} (after copy): {e}")
                # Logged error, but return True as copy succeeded.
            except Exception as e:
                write_debug_info(f"  DELETE FAILED for {object_key} with unexpected error: {str(e)}. File was copied but original remains.")
                logger.error(f"Unexpected error during delete of {object_key} (after copy): {e}")
                traceback.print_exc()
                # Logged error, but return True as copy succeeded.

        # Final success requires copy succeeded. Delete failure is logged.
        if copy_success:
            write_debug_info(f"Move operation check: copy_success={copy_success}, delete_success={delete_success} for {object_key}") 
            write_debug_info(f"Successfully processed move for {object_key} (original deleted: {delete_success})")
            return True
        else:
            # This case should not be reached due to early returns on copy failure
            write_debug_info(f"Move failed for {object_key} during copy phase.")
            return False
            
    except Exception as e:
        # Catchall for unexpected errors at the start of the function
        error_msg = f"Error moving {object_key} to issue bucket (outer scope): {str(e)}"
        write_debug_info(error_msg)
        logger.error(error_msg)
        traceback.print_exc()
        return False

def process_file(obj, good_filenames, good_base_filenames):
    """
    Process a single file from the upload bucket:
    1. Check if the base filename format ({numeric}.{numeric}.webp) is valid.
    2. If format is valid, check if it's a duplicate.
    3. Return results indicating format validity, webp status, and duplicate status.
    """
    object_key = obj['Key']
    filename = object_key.split('/')[-1]
    
    # Skip empty filenames or directory placeholders
    if not filename:
        return None # Indicate this object should be skipped
    
    # Check if filename matches required format
    is_valid_format = check_filename_format(filename)
    is_webp = filename.lower().endswith('.webp')
    
    # Only check for duplicates if format is valid
    is_dupe = False
    if is_valid_format:
        is_dupe = is_duplicate(filename, good_filenames, good_base_filenames)
    
    return {
        'key': object_key,
        'filename': filename,
        'is_valid_format': is_valid_format,
        'is_webp': is_webp,
        'is_duplicate': is_dupe
    }

def check_upload_bucket_filenames():
    """
    Check all files in the Upload bucket:
    1. Validate filename format ({numeric}.{numeric}.webp).
    2. If format is valid, check against Good bucket for duplicates.
    3. Move files with invalid format OR duplicates to Issue bucket.
    
    Uses multithreading for improved performance with large numbers of files.
    """
    try:
        write_debug_info("===== Starting new validation cycle =====")
        update_last_run()
        
        # Step 1: Ensure the good bucket cache is up-to-date
        good_filenames, good_base_filenames = None, None
        if redis_client:
            good_filenames, good_base_filenames = refresh_good_images_cache()
        else:
            write_debug_info("WARNING: Redis not available, duplicate detection may not work properly")
            good_filenames, good_base_filenames = load_good_bucket_filenames_to_memory()

        write_debug_info("Checking upload bucket (S3_UPLOAD_BUCKET) for improperly formatted filenames and duplicates")
        
        # List objects in the upload bucket
        prefix = 'temp_performer_at_venue_images/'
        
        # Get ALL files from the upload bucket within the prefix
        try:
            s3 = boto3.client(
                's3',
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                region_name=AWS_REGION
            ) # Ensure we have a client instance
            all_files_in_prefix = []
            paginator = s3.get_paginator('list_objects_v2')
            # Use try-except for pagination to handle potential errors during listing
            try:
                for page in paginator.paginate(Bucket=S3_UPLOAD_BUCKET, Prefix=prefix):
                    if 'Contents' in page:
                        # Filter out the prefix placeholder itself if present
                        all_files_in_prefix.extend([obj for obj in page['Contents'] if obj.get('Key') and obj['Key'] != prefix])
            except ClientError as e:
                write_debug_info(f"Error listing objects in {S3_UPLOAD_BUCKET} prefix {prefix}: {e}")
                logger.error(f"ClientError listing objects: {e}")
                return # Cannot proceed if listing fails
            except Exception as e:
                 write_debug_info(f"Unexpected error listing objects in {S3_UPLOAD_BUCKET} prefix {prefix}: {e}")
                 logger.error(f"Unexpected error listing objects: {e}")
                 return

            if not all_files_in_prefix:
                write_debug_info(f"No files found in upload bucket with prefix {prefix}")
                return
                
            total_files_found = len(all_files_in_prefix)
            write_debug_info(f"Found {total_files_found} total files in upload bucket prefix {prefix} to validate")
            
            # Process files in parallel using ThreadPoolExecutor
            invalid_format_count = 0
            duplicate_count = 0
            processed_count = 0
            skipped_count = 0 # Count skipped items like empty filenames

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                # Process files in parallel
                # Use try-except around the map to catch potential errors during parallel processing
                try:
                    future_results = executor.map(
                        lambda obj: process_file(obj, good_filenames, good_base_filenames),
                        all_files_in_prefix # Process ALL files found
                    )
                    # Filter out None results (e.g., from empty filenames or processing errors)
                    results = [r for r in future_results if r is not None]
                except Exception as e:
                     write_debug_info(f"Error during parallel processing: {e}")
                     logger.error(f"Error in ThreadPoolExecutor map: {e}")
                     results = [] # Prevent further processing if map fails
                
                skipped_count = total_files_found - len(results)
                processed_count = len(results)

                # Handle files with invalid format (not {numeric}.{numeric}.webp)
                invalid_format_files = [r for r in results if not r.get('is_valid_format', True)] # Default to True if key missing to avoid false positive
                write_debug_info(f"Found {len(invalid_format_files)} files with invalid format")
                
                for issue in invalid_format_files:
                    if issue.get('key'):
                        write_debug_info(f"  Processing invalid format file: {issue.get('filename', '[unknown]')}") 
                        move_successful = move_to_issue_bucket(issue['key'], "invalid format")
                        if move_successful:
                            invalid_format_count += 1
                        write_debug_info(f"  Move result for invalid format file {issue.get('filename', '[unknown]')}: {move_successful}") 
                    else:
                        logger.warning(f"Skipping move for invalid format file due to missing key: {issue}")

                # Handle duplicates (must have valid format)
                duplicates = [r for r in results if r.get('is_valid_format') and r.get('is_duplicate')]
                write_debug_info(f"Found {len(duplicates)} duplicate files")
                
                for dup in duplicates:
                    if dup.get('key'):
                        write_debug_info(f"  Processing duplicate file: {dup.get('filename', '[unknown]')}") 
                        move_successful = move_to_issue_bucket(dup['key'], "duplicate")
                        if move_successful:
                            duplicate_count += 1
                        write_debug_info(f"  Move result for duplicate file {dup.get('filename', '[unknown]')}: {move_successful}") 
                    else:
                        logger.warning(f"Skipping move for duplicate file due to missing key: {dup}")
            
            write_debug_info(f"Validation summary: Processed {processed_count} files (skipped {skipped_count}) total from prefix {prefix}")
            write_debug_info(f"Moved {invalid_format_count} files with invalid format to issue bucket")
            write_debug_info(f"Moved {duplicate_count} duplicate files to issue bucket")
            write_debug_info("===== Completed validation cycle =====")
            
        except Exception as e:
            error_msg = f"Error processing upload bucket files: {str(e)}"
            write_debug_info(error_msg)
            logger.error(error_msg)
            traceback.print_exc()
        
    except Exception as e:
        error_msg = f"Error checking upload bucket filenames: {str(e)}"
        write_debug_info(error_msg)
        traceback.print_exc()
        logger.error(error_msg)

def run_scheduler():
    """Run the scheduler to validate filenames periodically"""
    print("Starting filename validation service scheduler")
    logger.info("Starting filename validation service")
    
    # On Heroku, don't use write_debug_info at startup to avoid S3 issues
    print("Scheduler started - will run every 30 seconds")
    
    # Schedule the validation job to run every 30 seconds
    schedule.every(30).seconds.do(check_upload_bucket_filenames)
    
    # Run once immediately on startup
    try:
        print("Running initial validation check...")
        check_upload_bucket_filenames()
        print("Initial validation check completed")
    except Exception as e:
        error_msg = f"Error in initial validation run: {e}"
        print(error_msg)
        print(traceback.format_exc())
        logger.error(error_msg)
        # Continue to scheduler even if first run fails
    
    # Keep the script running
    print("Entering scheduler loop")
    while True:
        try:
            schedule.run_pending()
            time.sleep(1)
        except Exception as e:
            error_msg = f"Error in scheduler loop: {e}"
            print(error_msg)
            logger.error(error_msg)
            # Don't log full traceback to avoid flooding logs
            time.sleep(60)  # Wait a bit longer if there's an error

if __name__ == "__main__":
    try:
        print("Starting main execution")
        run_scheduler()
    except Exception as e:
        error_msg = f"FATAL ERROR in main: {str(e)}"
        print(error_msg)
        print(traceback.format_exc())
        logger.error(error_msg)
        logger.error(traceback.format_exc())
        sys.exit(1)
