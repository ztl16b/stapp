#!/usr/bin/env python3
import os
import time
import boto3
import logging
import traceback
import sys
import re
from datetime import datetime
from botocore.exceptions import ClientError
from dotenv import load_dotenv
import schedule

# Configuration
MAX_WORKERS = 5
BATCH_SIZE = 50

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
logger = logging.getLogger('filename_validator')

# Load AWS configuration
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")
S3_UPLOAD_BUCKET = os.getenv("S3_UPLOAD_BUCKET")
S3_ISSUE_BUCKET = os.getenv("S3_ISSUE_BUCKET")

# Debug files
DEBUG_FILE = "validator_debug.txt"
LAST_RUN_FILE = "validator_last_run.txt"
UPLOAD_PREFIX = "temp_performer_at_venue_images/"
ISSUE_PREFIX = "issue_files/"

# Validate environment variables
missing_vars = []
if not AWS_ACCESS_KEY_ID: missing_vars.append("AWS_ACCESS_KEY_ID")
if not AWS_SECRET_ACCESS_KEY: missing_vars.append("AWS_SECRET_ACCESS_KEY")
if not AWS_REGION: missing_vars.append("AWS_REGION")
if not S3_UPLOAD_BUCKET: missing_vars.append("S3_UPLOAD_BUCKET")
if not S3_ISSUE_BUCKET: missing_vars.append("S3_ISSUE_BUCKET")

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

# Initialize S3 client
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
    
    try:
        s3_client.list_buckets()
        print("S3 connection successful!")
    except Exception as e:
        print(f"ERROR: Failed to connect to S3: {e}")
        sys.exit(1)
    
    write_debug_info("Filename validator started successfully")
    
except Exception as e:
    print(f"ERROR: Failed to initialize S3 client: {e}")
    traceback.print_exc()
    sys.exit(1)

def is_valid_filename(filename):
    """
    Check if the filename matches the pattern {perf_id}.{ven_id}.webp
    where perf_id and ven_id are numbers
    """
    # Regex pattern for {numbers}.{numbers}.webp
    pattern = r'^(\d+)\.(\d+)\.webp$'
    return bool(re.match(pattern, filename))

def list_files_in_upload_bucket():
    """List all files in the upload bucket sorted by last modified date (newest first)"""
    try:
        write_debug_info(f"Listing all files in {S3_UPLOAD_BUCKET} with prefix {UPLOAD_PREFIX}")
        
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

def validate_and_move_file(s3_key):
    """
    Validate filename and move file to issue bucket if invalid
    """
    try:
        filename = s3_key.split('/')[-1]
        write_debug_info(f"Validating filename: {filename}")
        
        if not is_valid_filename(filename):
            write_debug_info(f"Invalid filename detected: {filename}")
            
            # Get file metadata to preserve
            try:
                response = s3_client.head_object(Bucket=S3_UPLOAD_BUCKET, Key=s3_key)
                metadata = response.get('Metadata', {})
                content_type = response.get('ContentType', 'image/webp')
            except Exception as e:
                write_debug_info(f"Error getting metadata for {s3_key}: {e}")
                metadata = {}
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
                'reason': 'Invalid filename format'
            }
        else:
            write_debug_info(f"Valid filename: {filename}")
            return {
                'status': 'valid',
                'key': s3_key
            }
    except Exception as e:
        error_msg = f"Error processing file {s3_key}: {str(e)}"
        write_debug_info(f"ERROR: {error_msg}")
        traceback.print_exc()
        logger.error(error_msg)
        return {
            'status': 'error',
            'key': s3_key,
            'error': str(e)
        }

def validate_next_batch():
    """Process all files to validate their filenames"""
    try:
        write_debug_info("\n===== Starting new validation cycle =====")
        update_last_run()
        
        files = list_files_in_upload_bucket()
        
        if not files:
            write_debug_info("No files found in upload bucket")
            return
        
        total_files = len(files)
        write_debug_info(f"Found {total_files} files to validate")
        
        valid_count = 0
        moved_count = 0
        error_count = 0
        
        # Process files in batches but continue until all are processed
        for i in range(0, total_files, BATCH_SIZE):
            current_batch = files[i:i+BATCH_SIZE]
            batch_num = (i // BATCH_SIZE) + 1
            total_batches = (total_files + BATCH_SIZE - 1) // BATCH_SIZE
            
            write_debug_info(f"Processing batch {batch_num} of {total_batches} ({len(current_batch)} files)")
            
            for file in current_batch:
                result = validate_and_move_file(file['Key'])
                
                if result['status'] == 'valid':
                    valid_count += 1
                elif result['status'] == 'moved':
                    moved_count += 1
                else:
                    error_count += 1
                    
            # Log progress after each batch
            write_debug_info(f"Progress: {i + len(current_batch)}/{total_files} files processed")
        
        write_debug_info(f"Validation complete:")
        write_debug_info(f"  - Valid files: {valid_count}")
        write_debug_info(f"  - Files moved to issue bucket: {moved_count}")
        write_debug_info(f"  - Errors: {error_count}")
        write_debug_info("===== Completed validation cycle =====\n")
        
    except Exception as e:
        error_msg = f"Error in validate_next_batch: {str(e)}"
        write_debug_info(f"ERROR: {error_msg}")
        traceback.print_exc()
        logger.error(error_msg)

def run_scheduler():
    """Run the scheduler to validate filenames periodically"""
    print("Starting filename validation service")
    write_debug_info("Scheduler started - will run every 60 seconds")
    
    schedule.every(60).seconds.do(validate_next_batch)
    
    try:
        validate_next_batch()
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