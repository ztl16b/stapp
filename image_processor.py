#!/usr/bin/env python3
import os
import time
import boto3
import requests
import logging
import traceback
from io import BytesIO
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
logger = logging.getLogger('image_processor')

# AWS Configuration
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")
S3_TEMP_BUCKET = os.getenv("S3_TEMP_BUCKET")
S3_UPLOAD_BUCKET = os.getenv("S3_UPLOAD_BUCKET")
S3_ISSUE_BUCKET = os.getenv("S3_ISSUE_BUCKET")
# Bytescale Configuration
BYTESCALE_API_KEY = os.getenv("BYTESCALE_API_KEY")
BYTESCALE_UPLOAD_URL = os.getenv("BYTESCALE_UPLOAD_URL")

# Debug variables
DEBUG_FILE = "processor_debug.txt"
LAST_RUN_FILE = "last_run.txt"

# Print configuration for debugging
print(f"Starting image processor with configuration:")
print(f"AWS_REGION: {AWS_REGION}")
print(f"S3_TEMP_BUCKET: {S3_TEMP_BUCKET}")
print(f"S3_UPLOAD_BUCKET: {S3_UPLOAD_BUCKET}")
print(f"BYTESCALE API KEY set: {'Yes' if BYTESCALE_API_KEY else 'No'}")
print(f"BYTESCALE UPLOAD URL set: {'Yes' if BYTESCALE_UPLOAD_URL else 'No'}")

def write_debug_info(message):
    """Write debug information to S3 bucket"""
    try:
        timestamp = datetime.now().isoformat()
        debug_message = f"[{timestamp}] {message}\n"
        
        # First, try to read existing debug file
        try:
            response = s3_client.get_object(Bucket=S3_TEMP_BUCKET, Key=DEBUG_FILE)
            existing_content = response['Body'].read().decode('utf-8')
            # Keep only the last 50 lines to prevent the file from growing too large
            lines = existing_content.splitlines()[-50:]
            existing_content = '\n'.join(lines) + '\n'
        except:
            existing_content = ""
        
        # Write updated content
        s3_client.put_object(
            Bucket=S3_TEMP_BUCKET,
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
            Bucket=S3_TEMP_BUCKET,
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
    
    # S3 upload configuration
    s3_upload_config = boto3.s3.transfer.TransferConfig(
        multipart_threshold=8 * 1024 * 1024,  # 8MB
        max_concurrency=10,
        multipart_chunksize=8 * 1024 * 1024,  # 8MB
        use_threads=True
    )
    
    # Write initial startup message
    write_debug_info("Image processor started")
    
except Exception as e:
    print(f"Failed to initialize S3 client: {e}")
    traceback.print_exc()

def list_images_in_temp_bucket(prefix="tmp_upload/", max_keys=10):
    """List images in the temporary bucket"""
    try:
        write_debug_info(f"Listing images in {S3_TEMP_BUCKET} with prefix {prefix}")
        
        response = s3_client.list_objects_v2(
            Bucket=S3_TEMP_BUCKET,
            Prefix=prefix,
            MaxKeys=max_keys
        )
        
        write_debug_info(f"List response: {response.get('KeyCount', 0)} objects found")
        
        if 'Contents' in response:
            # Return only files with image extensions
            image_extensions = ('.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp')
            images = [
                obj for obj in response['Contents']
                if obj['Key'].lower().endswith(image_extensions)
            ]
            write_debug_info(f"Found {len(images)} image files")
            
            # Log the first few images found for debugging
            for idx, img in enumerate(images[:3]):
                write_debug_info(f"Image {idx+1}: {img['Key']}")
            
            return images
        
        write_debug_info("No objects found in bucket")
        return []
    except Exception as e:
        error_msg = f"Error listing objects in temp bucket: {e}"
        write_debug_info(error_msg)
        logger.error(error_msg)
        return []

def process_image(s3_key):
    """
    Process a single image from the temp bucket:
    1. Download from S3
    2. Upload to Bytescale for processing
    3. Download processed image
    4. Upload to final destination
    5. Delete original from temp bucket
    """
    try:
        write_debug_info(f"Processing image: {s3_key}")
        
        # Get the original filename without path
        filename = s3_key.split('/')[-1]
        
        # Download the image from S3 temp bucket
        write_debug_info(f"Downloading {filename} from {S3_TEMP_BUCKET}")
        response = s3_client.get_object(Bucket=S3_TEMP_BUCKET, Key=s3_key)
        file_data = response['Body'].read()
        content_type = response.get('ContentType', 'image/jpeg')
        
        # Log the download
        write_debug_info(f"Downloaded {filename} ({len(file_data)} bytes) with content type {content_type}")
        
        # Upload to Bytescale for processing
        headers = {
            'Authorization': f'Bearer {BYTESCALE_API_KEY}'
        }
        files_data = {
            'file': (filename, file_data, content_type)
        }
        
        write_debug_info(f"Uploading {filename} to Bytescale for processing")
        with requests.Session() as session:
            # Upload to Bytescale
            upload_response = session.post(
                BYTESCALE_UPLOAD_URL, 
                headers=headers, 
                files=files_data, 
                timeout=60
            )
            upload_response.raise_for_status()
            
            # Parse response to get file URL
            json_response = upload_response.json()
            file_url = None
            for file_obj in json_response.get("files", []):
                if file_obj.get("formDataFieldName") == "file":
                    file_url = file_obj.get("fileUrl")
                    break
            
            if not file_url:
                raise ValueError("Could not find file URL in Bytescale response")
            
            write_debug_info(f"Bytescale upload successful, got URL: {file_url}")
            
            # We don't need the original file data anymore
            del file_data
            del files_data
            
            # Apply transformations using Bytescale
            processed_url = file_url.replace("/raw/", "/image/") + "?f=webp&w=464&h=510&fit=crop&crop=center"
            write_debug_info(f"Downloading processed image from: {processed_url}")
            
            # Download the processed image
            download_response = session.get(processed_url, stream=True, timeout=60)
            download_response.raise_for_status()
            
            # Upload processed image to final destination
            base_filename = os.path.splitext(filename)[0]
            
            # Transform filename from "perf_id-ven_id" format to "perf_id.ven_id" format
            if '-' in base_filename:
                parts = base_filename.split('-')
                if len(parts) >= 2:
                    # Replace hyphen with dot between IDs
                    base_filename = '.'.join(parts)
            
            upload_path = f"temp_performer_at_venue_images/{base_filename}.webp"
            
            write_debug_info(f"Transformed filename from '{filename}' to '{os.path.basename(upload_path)}'")
            write_debug_info(f"Uploading processed image to {S3_UPLOAD_BUCKET}/{upload_path}")
            s3_client.upload_fileobj(
                download_response.raw,
                S3_UPLOAD_BUCKET,
                upload_path,
                ExtraArgs={'ContentType': 'image/webp'},
                Config=s3_upload_config
            )
            
            # Delete original from temp bucket
            write_debug_info(f"Deleting original image from {S3_TEMP_BUCKET}/{s3_key}")
            s3_client.delete_object(
                Bucket=S3_TEMP_BUCKET,
                Key=s3_key
            )
            
            write_debug_info(f"Successfully processed {filename}")
            return {
                'status': 'success',
                'original_key': s3_key,
                'processed_key': upload_path,
                'message': f'Successfully processed {filename}'
            }
    except Exception as e:
        error_msg = f"Error processing image {s3_key}: {str(e)}"
        write_debug_info(error_msg)
        traceback.print_exc()
        logger.error(error_msg)
        return {
            'status': 'error',
            'original_key': s3_key,
            'message': str(e)
        }

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
    except Exception as e:
        error_msg = f"Error checking upload bucket filenames: {str(e)}"
        write_debug_info(error_msg)
        logger.error(error_msg)

def process_next_batch():
    """Process the next batch of images from the temp bucket"""
    try:
        write_debug_info("===== Starting new processing cycle =====")
        update_last_run()
        
        # Get a list of images (limit to 10 per batch)
        images = list_images_in_temp_bucket(max_keys=10)
        
        if not images:
            write_debug_info("No images found in temp bucket")
            # Even if no new images to process, check existing ones for format issues
            check_upload_bucket_filenames()
            return
        
        write_debug_info(f"Found {len(images)} images in temp bucket")
        
        # Process one image at a time
        for image in images:
            s3_key = image['Key']
            result = process_image(s3_key)
            
            if result['status'] == 'success':
                write_debug_info(f"Successfully processed {s3_key}")
            else:
                write_debug_info(f"Failed to process {s3_key}: {result['message']}")
            
            # Only process one image per run to avoid overloading
            break
        
        # After processing new images, check for improperly formatted filenames
        check_upload_bucket_filenames()
        
        write_debug_info("===== Completed processing cycle =====")
        
    except Exception as e:
        error_msg = f"Error in process_next_batch: {str(e)}"
        write_debug_info(error_msg)
        traceback.print_exc()
        logger.error(error_msg)

def run_scheduler():
    """Run the scheduler to process images periodically"""
    print("Starting image processing service")
    write_debug_info("Scheduler started - will run every 30 seconds")
    
    # Schedule the processing job to run every 30 seconds
    schedule.every(30).seconds.do(process_next_batch)
    
    # Run once immediately on startup
    try:
        process_next_batch()
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