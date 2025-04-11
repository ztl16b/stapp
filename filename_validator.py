#!/usr/bin/env python3
import os
import time
import boto3
import logging
import traceback
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

# Debug variables
DEBUG_FILE = "validator_debug.txt"
LAST_RUN_FILE = "validator_last_run.txt"

# Print configuration for debugging
print(f"Starting filename validator with configuration:")
print(f"AWS_REGION: {AWS_REGION}")
print(f"S3_UPLOAD_BUCKET: {S3_UPLOAD_BUCKET}")
print(f"S3_ISSUE_BUCKET: {S3_ISSUE_BUCKET}")

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

def move_to_issue_bucket(object_key):
    """
    Move a file from the Upload bucket to the Issue bucket.
    """
    try:
        # Keep the same filename in the issue bucket
        filename = object_key.split('/')[-1]
        dest_key = f"issue_files/{filename}"
        
        write_debug_info(f"Moving improperly formatted file {object_key} to issue bucket as {dest_key}")
        
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
        
        write_debug_info(f"Successfully moved {object_key} to issue bucket")
        return True
    except Exception as e:
        error_msg = f"Error moving {object_key} to issue bucket: {str(e)}"
        write_debug_info(error_msg)
        logger.error(error_msg)
        return False

def check_upload_bucket_filenames():
    """
    Check all files in the Upload bucket for proper naming format.
    Move improperly formatted files to the Issue bucket.
    """
    try:
        write_debug_info("===== Starting new validation cycle =====")
        update_last_run()
        
        write_debug_info("Checking upload bucket for improperly formatted filenames")
        
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
        
        write_debug_info(f"Found {len(webp_files)} webp files in upload bucket to check")
        
        for obj in webp_files:
            object_key = obj['Key']
            filename = object_key.split('/')[-1]
            
            # Check if the filename matches the required format
            if not check_filename_format(filename):
                write_debug_info(f"Found improperly formatted filename: {filename}")
                if move_to_issue_bucket(object_key):
                    issue_count += 1
        
        write_debug_info(f"Moved {issue_count} improperly formatted files to issue bucket")
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