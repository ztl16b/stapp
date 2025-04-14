#!/usr/bin/env python3
import os
import time
import boto3
import requests
import logging
import traceback
import sys
import concurrent.futures
from io import BytesIO
from datetime import datetime
from botocore.exceptions import ClientError
from dotenv import load_dotenv
import schedule


MAX_WORKERS = 10
BATCH_SIZE = 10


load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('image_processor')

AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")
S3_TEMP_BUCKET = os.getenv("S3_TEMP_BUCKET")
S3_UPLOAD_BUCKET = os.getenv("S3_UPLOAD_BUCKET")
S3_ISSUE_BUCKET = os.getenv("S3_ISSUE_BUCKET")
BYTESCALE_API_KEY = os.getenv("BYTESCALE_API_KEY")
BYTESCALE_UPLOAD_URL = os.getenv("BYTESCALE_UPLOAD_URL")

DEBUG_FILE = "processor_debug.txt"
LAST_RUN_FILE = "last_run.txt"
TEMP_PREFIX = "tmp_upload/"
DESTINATION_PREFIX = "temp_performer_at_venue_images/"

missing_vars = []
if not AWS_ACCESS_KEY_ID: missing_vars.append("AWS_ACCESS_KEY_ID")
if not AWS_SECRET_ACCESS_KEY: missing_vars.append("AWS_SECRET_ACCESS_KEY")
if not AWS_REGION: missing_vars.append("AWS_REGION")
if not S3_TEMP_BUCKET: missing_vars.append("S3_TEMP_BUCKET")
if not S3_UPLOAD_BUCKET: missing_vars.append("S3_UPLOAD_BUCKET")
if not BYTESCALE_API_KEY: missing_vars.append("BYTESCALE_API_KEY")
if not BYTESCALE_UPLOAD_URL: missing_vars.append("BYTESCALE_UPLOAD_URL")

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
            response = s3_client.get_object(Bucket=S3_TEMP_BUCKET, Key=DEBUG_FILE)
            existing_content = response['Body'].read().decode('utf-8')
            lines = existing_content.splitlines()[-50:]
            existing_content = '\n'.join(lines) + '\n'
        except Exception as e:
            existing_content = ""
        
        s3_client.put_object(
            Bucket=S3_TEMP_BUCKET,
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
            Bucket=S3_TEMP_BUCKET,
            Key=LAST_RUN_FILE,
            Body=f"Last run: {timestamp}"
        )
    except Exception as e:
        print(f"Failed to update last run timestamp: {e}")

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
    
    write_debug_info("Image processor started successfully")
    
except Exception as e:
    print(f"ERROR: Failed to initialize S3 client: {e}")
    traceback.print_exc()
    sys.exit(1)

def list_all_temp_images():
    """List ALL images in the temporary bucket with any prefix"""
    try:
        write_debug_info(f"Listing ALL images in {S3_TEMP_BUCKET}")
        
        all_images = []
        
        response = s3_client.list_objects_v2(
            Bucket=S3_TEMP_BUCKET,
            Prefix=TEMP_PREFIX
        )
        
        if 'Contents' in response:
            image_extensions = ('.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp')
            images = [
                obj for obj in response['Contents']
                if obj['Key'].lower().endswith(image_extensions)
            ]
            all_images.extend(images)
            write_debug_info(f"Found {len(images)} images with prefix '{TEMP_PREFIX}'")
        else:
            write_debug_info(f"No objects found with prefix '{TEMP_PREFIX}'")
        
        if len(all_images) == 0:
            write_debug_info("Checking bucket root for images")
            response = s3_client.list_objects_v2(
                Bucket=S3_TEMP_BUCKET,
                Prefix=""
            )
            
            if 'Contents' in response:
                image_extensions = ('.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp')
                images = [
                    obj for obj in response['Contents']
                    if obj['Key'].lower().endswith(image_extensions) and not obj['Key'].startswith(DESTINATION_PREFIX)
                ]
                all_images.extend(images)
                write_debug_info(f"Found {len(images)} images at bucket root")
            else:
                write_debug_info("No objects found at bucket root")
        
        for idx, img in enumerate(all_images[:5]):
            write_debug_info(f"Image {idx+1}: {img['Key']} ({img['Size']} bytes)")
        
        if len(all_images) == 0:
            write_debug_info("No images found in any location in the temp bucket")
        
        return all_images
    except Exception as e:
        error_msg = f"Error listing objects in temp bucket: {e}"
        write_debug_info(error_msg)
        logger.error(error_msg)
        traceback.print_exc()
        return []

def file_exists_in_bucket(bucket, key):
    """Check if a file exists in the specified bucket"""
    try:
        s3_client.head_object(Bucket=bucket, Key=key)
        return True
    except Exception:
        return False

def move_to_issue_bucket(file_obj, key, reason, metadata=None, content_type='image/webp'):
    """Move a file to the issue bucket with appropriate metadata"""
    try:
        # Generate a destination key in the issue bucket
        filename = key.split('/')[-1]
        base_name, extension = os.path.splitext(filename)
        new_filename = f"{base_name}_dupeUpload{extension}"
        destination_key = f"issue_files/{new_filename}"
        
        write_debug_info(f"Moving duplicate file: {filename}, Reason: {reason}")
        
        # Prepare metadata
        extra_args = {'ContentType': content_type}
        if metadata:
            # Add duplicate reason to metadata
            metadata_copy = metadata.copy()
            metadata_copy['duplicate-reason'] = reason
            extra_args['Metadata'] = metadata_copy
        else:
            extra_args['Metadata'] = {'duplicate-reason': reason}
        
        # Upload to issue bucket
        write_debug_info(f"Moving file to issue bucket: {S3_ISSUE_BUCKET}/{destination_key}")
        s3_client.upload_fileobj(
            file_obj,
            S3_ISSUE_BUCKET,
            destination_key,
            ExtraArgs=extra_args,
            Config=s3_upload_config
        )
        
        write_debug_info(f"Successfully moved {filename} to issue bucket as {new_filename}")
        return True
    except Exception as e:
        write_debug_info(f"Error moving file to issue bucket: {e}")
        return False

def process_image(s3_key):
    try:
        write_debug_info(f"\n=== Processing image: {s3_key} ===")
        
        filename = s3_key.split('/')[-1]
        
        write_debug_info(f"Downloading {filename} from {S3_TEMP_BUCKET}")
        response = s3_client.get_object(Bucket=S3_TEMP_BUCKET, Key=s3_key)
        file_data = response['Body'].read()
        content_type = response.get('ContentType', 'image/jpeg')
        
        metadata = response.get('Metadata', {})
        uploader_initials = metadata.get('uploader-initials', '')
        if uploader_initials:
            write_debug_info(f"Found uploader initials metadata: {uploader_initials}")
        
        write_debug_info(f"Downloaded {filename} ({len(file_data)} bytes) with content type {content_type}")
        
        if len(file_data) == 0:
            write_debug_info(f"ERROR: Downloaded file has zero bytes. Skipping.")
            return {
                'status': 'error',
                'original_key': s3_key,
                'message': "Downloaded file has zero bytes"
            }
        
        headers = {
            'Authorization': f'Bearer {BYTESCALE_API_KEY}'
        }
        files_data = {
            'file': (filename, file_data, content_type)
        }
        
        write_debug_info(f"Uploading {filename} to Bytescale for processing")
        with requests.Session() as session:
            write_debug_info(f"POST request to {BYTESCALE_UPLOAD_URL}")
            upload_response = session.post(
                BYTESCALE_UPLOAD_URL, 
                headers=headers, 
                files=files_data, 
                timeout=60
            )
            
            if upload_response.status_code != 200:
                error_msg = f"Bytescale upload returned status code {upload_response.status_code}"
                write_debug_info(f"ERROR: {error_msg}")
                write_debug_info(f"Response content: {upload_response.text[:500]}")
                return {
                    'status': 'error',
                    'original_key': s3_key,
                    'message': error_msg
                }
            
            upload_response.raise_for_status()
            
            json_response = upload_response.json()
            write_debug_info(f"Bytescale response: {json_response}")
            
            file_url = None
            for file_obj in json_response.get("files", []):
                if file_obj.get("formDataFieldName") == "file":
                    file_url = file_obj.get("fileUrl")
                    break
            
            if not file_url:
                error_msg = "Could not find file URL in Bytescale response"
                write_debug_info(f"ERROR: {error_msg}")
                return {
                    'status': 'error',
                    'original_key': s3_key,
                    'message': error_msg
                }
            
            write_debug_info(f"Bytescale upload successful, got URL: {file_url}")
            
            del file_data
            del files_data
            
            processed_url = file_url.replace("/raw/", "/image/") + "?f=webp&w=464&h=510&fit=crop&crop=center"
            write_debug_info(f"Downloading processed image from: {processed_url}")
            
            download_response = session.get(processed_url, stream=True, timeout=60)
            if download_response.status_code != 200:
                error_msg = f"Bytescale transformation returned status code {download_response.status_code}"
                write_debug_info(f"ERROR: {error_msg}")
                return {
                    'status': 'error',
                    'original_key': s3_key,
                    'message': error_msg
                }
            
            download_response.raise_for_status()
            
            base_filename = os.path.splitext(filename)[0]
            
            if '-' in base_filename:
                parts = base_filename.split('-')
                if len(parts) >= 2:
                    base_filename = '.'.join(parts)
                    write_debug_info(f"Transformed filename from hyphen to dot format: {base_filename}")
            
            upload_path = f"{DESTINATION_PREFIX}{base_filename}.webp"
            
            write_debug_info(f"Final filename: {os.path.basename(upload_path)}")
            
            # Check if file already exists in upload bucket
            if file_exists_in_bucket(S3_UPLOAD_BUCKET, upload_path):
                write_debug_info(f"File {upload_path} already exists in upload bucket")
                
                # Move to issue bucket instead of overwriting
                extra_args = {'ContentType': 'image/webp'}
                if uploader_initials:
                    extra_args['Metadata'] = {'uploader-initials': uploader_initials}
                
                # Create a rewindable file-like object
                download_buffer = BytesIO()
                download_buffer.write(download_response.content)
                download_buffer.seek(0)  # Rewind to beginning
                
                # Move to issue bucket
                if move_to_issue_bucket(
                    download_buffer, 
                    upload_path, 
                    "Duplicate file in upload bucket",
                    metadata={'uploader-initials': uploader_initials} if uploader_initials else None,
                    content_type='image/webp'
                ):
                    write_debug_info(f"Moved duplicate file to issue bucket")
                else:
                    write_debug_info(f"Failed to move duplicate file to issue bucket")
                
                # Clean up
                download_buffer.close()
                s3_client.delete_object(
                    Bucket=S3_TEMP_BUCKET,
                    Key=s3_key
                )
                
                return {
                    'status': 'success',
                    'original_key': s3_key,
                    'processed_key': None,
                    'message': f'Processed {filename} - duplicate file moved to issue bucket',
                    'uploader_initials': uploader_initials
                }
            
            # If not a duplicate, upload to upload bucket as normal
            write_debug_info(f"Uploading processed image to {S3_UPLOAD_BUCKET}/{upload_path}")
            
            extra_args = {'ContentType': 'image/webp'}
            if uploader_initials:
                extra_args['Metadata'] = {'uploader-initials': uploader_initials}
                write_debug_info(f"Preserving uploader initials metadata: {uploader_initials}")
            
            s3_client.upload_fileobj(
                download_response.raw,
                S3_UPLOAD_BUCKET,
                upload_path,
                ExtraArgs=extra_args,
                Config=s3_upload_config
            )
            
            write_debug_info(f"Deleting original image from {S3_TEMP_BUCKET}/{s3_key}")
            s3_client.delete_object(
                Bucket=S3_TEMP_BUCKET,
                Key=s3_key
            )
            
            write_debug_info(f"Successfully processed {filename}\n")
            return {
                'status': 'success',
                'original_key': s3_key,
                'processed_key': upload_path,
                'message': f'Successfully processed {filename}',
                'uploader_initials': uploader_initials
            }
    except Exception as e:
        error_msg = f"Error processing image {s3_key}: {str(e)}"
        write_debug_info(f"ERROR: {error_msg}")
        traceback.print_exc()
        logger.error(error_msg)
        return {
            'status': 'error',
            'original_key': s3_key,
            'message': str(e)
        }

def process_next_batch():
    """Process multiple images in parallel"""
    try:
        write_debug_info("\n===== Starting new processing cycle =====")
        update_last_run()
        
        images = list_all_temp_images()
        
        if not images:
            write_debug_info("No images found in temp bucket")
            return
        
        batch = images[:BATCH_SIZE]
        write_debug_info(f"Processing batch of {len(batch)} images (from {len(images)} total)")
        
        successful = 0
        failed = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_key = {executor.submit(process_image, image['Key']): image['Key'] for image in batch}
            
            for future in concurrent.futures.as_completed(future_to_key):
                key = future_to_key[future]
                try:
                    result = future.result()
                    if result['status'] == 'success':
                        successful += 1
                        write_debug_info(f"✓ Successfully processed {key}")
                    else:
                        failed += 1
                        write_debug_info(f"✗ Failed to process {key}: {result['message']}")
                except Exception as e:
                    failed += 1
                    write_debug_info(f"✗ Exception processing {key}: {str(e)}")
        
        write_debug_info(f"Batch processing complete: {successful} successful, {failed} failed")
        write_debug_info("===== Completed processing cycle =====\n")
        
    except Exception as e:
        error_msg = f"Error in process_next_batch: {str(e)}"
        write_debug_info(f"ERROR: {error_msg}")
        traceback.print_exc()
        logger.error(error_msg)

def run_scheduler():
    """Run the scheduler to process images periodically"""
    print("Starting image processing service")
    write_debug_info("Scheduler started - will run every 30 seconds")
    
    schedule.every(30).seconds.do(process_next_batch)
    
    try:
        process_next_batch()
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