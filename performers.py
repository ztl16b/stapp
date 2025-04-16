import os
import boto3
import logging
import argparse
import sys
from dotenv import load_dotenv
from botocore.exceptions import NoCredentialsError, ClientError
import time
import concurrent.futures

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('performers_worker')

# Load environment variables
load_dotenv()

# AWS Configuration
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")
S3_GOOD_BUCKET = os.getenv("S3_GOOD_BUCKET")
S3_INCREDIBLE_BUCKET = os.getenv("S3_INCREDIBLE_BUCKET")
S3_BAD_BUCKET = os.getenv("S3_BAD_BUCKET")
S3_PERFORMER_BUCKET = os.getenv("S3_PERFORMER_BUCKET")

# S3 client setup
try:
    s3_client = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )
except NoCredentialsError:
    logger.error("AWS credentials not found. Ensure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set.")
    raise ValueError("AWS credentials not found")
except Exception as e:
    logger.error(f"Error initializing S3 client: {e}")
    raise ValueError(f"Error initializing S3 client: {e}")

def get_performer_ids():
    """
    Retrieves all performer IDs from the Performer bucket.
    
    Returns:
        set: A set of performer IDs
    """
    performer_ids = set()
    prefix = 'images/performers/detail/'
    
    try:
        paginator = s3_client.get_paginator('list_objects_v2')
        
        for page in paginator.paginate(
            Bucket=S3_PERFORMER_BUCKET,
            Prefix=prefix
        ):
            if 'Contents' in page:
                for item in page['Contents']:
                    # Skip the prefix itself or any folder objects
                    if item['Key'] == prefix or item['Key'].endswith('/'):
                        continue
                    
                    # Extract filename without path
                    filename = item['Key'].split('/')[-1]
                    
                    # Skip non-webp files
                    if not filename.lower().endswith('.webp'):
                        continue
                    
                    # Extract performer ID (remove .webp extension)
                    perf_id = filename.split('.')[0]
                    
                    # Ensure it's numeric
                    if perf_id.isdigit():
                        performer_ids.add(perf_id)
        
        logger.info(f"Found {len(performer_ids)} unique performer IDs")
        return performer_ids
        
    except Exception as e:
        logger.error(f"Error retrieving performer IDs: {e}")
        return set()

def get_good_images_with_performer_id(performer_id):
    """
    Finds all images in the Good bucket that match a specific performer ID.
    
    Args:
        performer_id (str): The performer ID to search for
        
    Returns:
        list: List of image keys that match the performer ID
    """
    matching_images = []
    prefix = 'images/performer-at-venue/detail/'
    
    try:
        paginator = s3_client.get_paginator('list_objects_v2')
        
        for page in paginator.paginate(
            Bucket=S3_GOOD_BUCKET,
            Prefix=prefix
        ):
            if 'Contents' in page:
                for item in page['Contents']:
                    # Extract filename without path
                    filename = item['Key'].split('/')[-1]
                    
                    # Skip non-webp files
                    if not filename.lower().endswith('.webp'):
                        continue
                    
                    # Extract first part before the first dot (performer ID)
                    file_perf_id = filename.split('.')[0]
                    
                    # Check if this is the performer ID we're looking for
                    if file_perf_id == performer_id:
                        matching_images.append(item['Key'])
        
        return matching_images
        
    except Exception as e:
        logger.error(f"Error searching for images with performer ID {performer_id}: {e}")
        return []

def get_incredible_images_with_performer_id(performer_id):
    """
    Finds all images in the Incredible bucket that match a specific performer ID.
    
    Args:
        performer_id (str): The performer ID to search for
        
    Returns:
        list: List of image keys that match the performer ID
    """
    matching_images = []
    prefix = 'incredible_images/'
    
    try:
        paginator = s3_client.get_paginator('list_objects_v2')
        
        for page in paginator.paginate(
            Bucket=S3_INCREDIBLE_BUCKET,
            Prefix=prefix
        ):
            if 'Contents' in page:
                for item in page['Contents']:
                    # Extract filename without path
                    filename = item['Key'].split('/')[-1]
                    
                    # Skip non-webp files
                    if not filename.lower().endswith('.webp'):
                        continue
                    
                    # Extract first part before the first dot (performer ID)
                    file_perf_id = filename.split('.')[0]
                    
                    # Check if this is the performer ID we're looking for
                    if file_perf_id == performer_id:
                        matching_images.append(item['Key'])
        
        return matching_images
        
    except Exception as e:
        logger.error(f"Error searching for images with performer ID {performer_id} in Incredible bucket: {e}")
        return []

def get_bad_images_with_performer_id(performer_id):
    """
    Finds all images in the Bad bucket that match a specific performer ID.
    
    Args:
        performer_id (str): The performer ID to search for
        
    Returns:
        list: List of image keys that match the performer ID
    """
    matching_images = []
    prefix = 'bad_images/'
    
    try:
        paginator = s3_client.get_paginator('list_objects_v2')
        
        for page in paginator.paginate(
            Bucket=S3_BAD_BUCKET,
            Prefix=prefix
        ):
            if 'Contents' in page:
                for item in page['Contents']:
                    # Extract filename without path
                    filename = item['Key'].split('/')[-1]
                    
                    # Skip non-webp files
                    if not filename.lower().endswith('.webp'):
                        continue
                    
                    # Extract first part before the first dot (performer ID)
                    file_perf_id = filename.split('.')[0]
                    
                    # Check if this is the performer ID we're looking for
                    if file_perf_id == performer_id:
                        matching_images.append(item['Key'])
        
        return matching_images
        
    except Exception as e:
        logger.error(f"Error searching for images with performer ID {performer_id} in Bad bucket: {e}")
        return []

def update_perfimg_status(image_key, dry_run=False):
    """
    Updates the perfimg_status metadata for a specific image to TRUE.
    
    Args:
        image_key (str): The S3 key of the image to update
        dry_run (bool): If True, only log what would be done without making changes
        
    Returns:
        bool: True if update was successful, False otherwise
    """
    try:
        # Get current metadata
        head_response = s3_client.head_object(
            Bucket=S3_GOOD_BUCKET,
            Key=image_key
        )
        
        # Create a new copy of the metadata to avoid modifying the original response
        current_metadata = dict(head_response.get('Metadata', {}))
        content_type = head_response.get('ContentType', 'image/webp')
        
        # Explicitly save the original upload_time if it exists
        original_upload_time = current_metadata.get('upload_time')
        
        # Check if perfimg_status is already TRUE
        if current_metadata.get('perfimg_status') == 'TRUE':
            logger.debug(f"Image {image_key} already has perfimg_status=TRUE. Skipping.")
            return True
        
        # Ensure all important metadata fields exist with appropriate defaults
        if 'uploader-initials' not in current_metadata:
            current_metadata['uploader-initials'] = 'Unknown'
            
        if 'review_status' not in current_metadata:
            current_metadata['review_status'] = 'FALSE'
        
        # Update perfimg_status to TRUE
        current_metadata['perfimg_status'] = 'TRUE'
        
        # Restore the original upload_time exactly as it was
        if original_upload_time:
            current_metadata['upload_time'] = original_upload_time
        
        if dry_run:
            logger.info(f"DRY RUN: Would update perfimg_status for {image_key} to TRUE")
            return True
        
        # Copy object to itself with updated metadata
        s3_client.copy_object(
            CopySource={'Bucket': S3_GOOD_BUCKET, 'Key': image_key},
            Bucket=S3_GOOD_BUCKET,
            Key=image_key,
            Metadata=current_metadata,
            MetadataDirective='REPLACE',
            ContentType=content_type
        )
        
        logger.info(f"Updated perfimg_status for {image_key} to TRUE")
        return True
        
    except Exception as e:
        logger.error(f"Error updating perfimg_status for {image_key}: {e}")
        return False

def update_incredible_perfimg_status(image_key, dry_run=False):
    """
    Updates the perfimg_status metadata for a specific image in the Incredible bucket to TRUE.
    
    Args:
        image_key (str): The S3 key of the image to update
        dry_run (bool): If True, only log what would be done without making changes
        
    Returns:
        bool: True if update was successful, False otherwise
    """
    try:
        # Get current metadata
        head_response = s3_client.head_object(
            Bucket=S3_INCREDIBLE_BUCKET,
            Key=image_key
        )
        
        # Create a new copy of the metadata to avoid modifying the original response
        current_metadata = dict(head_response.get('Metadata', {}))
        content_type = head_response.get('ContentType', 'image/webp')
        
        # Explicitly save the original upload_time if it exists
        original_upload_time = current_metadata.get('upload_time')
        
        # Check if perfimg_status is already TRUE
        if current_metadata.get('perfimg_status') == 'TRUE':
            logger.debug(f"Image {image_key} already has perfimg_status=TRUE in Incredible bucket. Skipping.")
            return True
        
        # Ensure all important metadata fields exist with appropriate defaults
        if 'uploader-initials' not in current_metadata:
            current_metadata['uploader-initials'] = 'Unknown'
            
        if 'review_status' not in current_metadata:
            current_metadata['review_status'] = 'TRUE'  # Always TRUE for incredible bucket
        
        # Update perfimg_status to TRUE
        current_metadata['perfimg_status'] = 'TRUE'
        
        # Restore the original upload_time exactly as it was
        if original_upload_time:
            current_metadata['upload_time'] = original_upload_time
        
        if dry_run:
            logger.info(f"DRY RUN: Would update perfimg_status for {image_key} to TRUE in Incredible bucket")
            return True
        
        # Copy object to itself with updated metadata
        s3_client.copy_object(
            CopySource={'Bucket': S3_INCREDIBLE_BUCKET, 'Key': image_key},
            Bucket=S3_INCREDIBLE_BUCKET,
            Key=image_key,
            Metadata=current_metadata,
            MetadataDirective='REPLACE',
            ContentType=content_type
        )
        
        logger.info(f"Updated perfimg_status for {image_key} to TRUE in Incredible bucket")
        return True
        
    except Exception as e:
        logger.error(f"Error updating perfimg_status for {image_key} in Incredible bucket: {e}")
        return False

def update_bad_perfimg_status(image_key, dry_run=False):
    """
    Updates the perfimg_status metadata for a specific image in the Bad bucket to TRUE.
    
    Args:
        image_key (str): The S3 key of the image to update
        dry_run (bool): If True, only log what would be done without making changes
        
    Returns:
        bool: True if update was successful, False otherwise
    """
    try:
        # Get current metadata
        head_response = s3_client.head_object(
            Bucket=S3_BAD_BUCKET,
            Key=image_key
        )
        
        # Create a new copy of the metadata to avoid modifying the original response
        current_metadata = dict(head_response.get('Metadata', {}))
        content_type = head_response.get('ContentType', 'image/webp')
        
        # Explicitly save the original upload_time if it exists
        original_upload_time = current_metadata.get('upload_time')
        
        # Check if perfimg_status is already TRUE
        if current_metadata.get('perfimg_status') == 'TRUE':
            logger.debug(f"Image {image_key} already has perfimg_status=TRUE in Bad bucket. Skipping.")
            return True
        
        # Ensure all important metadata fields exist with appropriate defaults
        if 'uploader-initials' not in current_metadata:
            current_metadata['uploader-initials'] = 'Unknown'
            
        if 'review_status' not in current_metadata:
            current_metadata['review_status'] = 'TRUE'  # Usually TRUE for bad bucket too
        
        # Update perfimg_status to TRUE
        current_metadata['perfimg_status'] = 'TRUE'
        
        # Restore the original upload_time exactly as it was
        if original_upload_time:
            current_metadata['upload_time'] = original_upload_time
        
        if dry_run:
            logger.info(f"DRY RUN: Would update perfimg_status for {image_key} to TRUE in Bad bucket")
            return True
        
        # Copy object to itself with updated metadata
        s3_client.copy_object(
            CopySource={'Bucket': S3_BAD_BUCKET, 'Key': image_key},
            Bucket=S3_BAD_BUCKET,
            Key=image_key,
            Metadata=current_metadata,
            MetadataDirective='REPLACE',
            ContentType=content_type
        )
        
        logger.info(f"Updated perfimg_status for {image_key} to TRUE in Bad bucket")
        return True
        
    except Exception as e:
        logger.error(f"Error updating perfimg_status for {image_key} in Bad bucket: {e}")
        return False

def process_performer_id(performer_id, dry_run=False):
    """
    Process a single performer ID - find matching images and update their metadata.
    
    Args:
        performer_id (str): The performer ID to process
        dry_run (bool): If True, only log what would be done without making changes
        
    Returns:
        tuple: (performer_id, count of updated images)
    """
    total_updated = 0
    
    # Process Good bucket
    good_images = get_good_images_with_performer_id(performer_id)
    good_updated = 0
    
    if good_images:
        logger.info(f"Found {len(good_images)} images with performer ID {performer_id} in Good bucket")
        
        for image_key in good_images:
            if update_perfimg_status(image_key, dry_run):
                good_updated += 1
    
    # Process Incredible bucket
    incredible_images = get_incredible_images_with_performer_id(performer_id)
    incredible_updated = 0
    
    if incredible_images:
        logger.info(f"Found {len(incredible_images)} images with performer ID {performer_id} in Incredible bucket")
        
        for image_key in incredible_images:
            if update_incredible_perfimg_status(image_key, dry_run):
                incredible_updated += 1
    
    # Process Bad bucket
    bad_images = get_bad_images_with_performer_id(performer_id)
    bad_updated = 0
    
    if bad_images:
        logger.info(f"Found {len(bad_images)} images with performer ID {performer_id} in Bad bucket")
        
        for image_key in bad_images:
            if update_bad_perfimg_status(image_key, dry_run):
                bad_updated += 1
    
    total_updated = good_updated + incredible_updated + bad_updated
    
    if total_updated > 0:
        logger.info(f"Total updated for performer ID {performer_id}: {total_updated} (Good: {good_updated}, Incredible: {incredible_updated}, Bad: {bad_updated})")
    
    return performer_id, total_updated

def run_worker(dry_run=False):
    """Run a single worker pass."""
    start_time = time.time()
    logger.info(f"Starting performers_worker{'(DRY RUN)' if dry_run else ''}")
    
    # Get all performer IDs
    performer_ids = get_performer_ids()
    
    if not performer_ids:
        logger.warning("No performer IDs found. Exiting.")
        return 0, 0
    
    # Statistics
    total_updated = 0
    processed_ids = 0
    
    # Process performer IDs in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_performer = {executor.submit(process_performer_id, performer_id, dry_run): performer_id for performer_id in performer_ids}
        
        for future in concurrent.futures.as_completed(future_to_performer):
            performer_id = future_to_performer[future]
            processed_ids += 1
            
            try:
                _, updated_count = future.result()
                total_updated += updated_count
                
                # Log progress periodically
                if processed_ids % 50 == 0 or processed_ids == len(performer_ids):
                    logger.info(f"Progress: {processed_ids}/{len(performer_ids)} performer IDs processed")
                
            except Exception as e:
                logger.error(f"Error processing performer ID {performer_id}: {e}")
    
    elapsed_time = time.time() - start_time
    logger.info(f"Completed performers_worker in {elapsed_time:.2f} seconds")
    logger.info(f"Processed {processed_ids} performer IDs")
    logger.info(f"Updated perfimg_status for {total_updated} images")
    
    return processed_ids, total_updated

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Performer image metadata worker')
    parser.add_argument('--dry-run', action='store_true', help='Run without making any changes')
    parser.add_argument('--loop', action='store_true', help='Run continuously every 30 seconds')
    parser.add_argument('--interval', type=int, default=30, help='Interval in seconds for loop mode (default: 30)')
    return parser.parse_args()

def main():
    """Main worker function."""
    args = parse_args()
    
    dry_run = args.dry_run
    loop_mode = args.loop
    interval = args.interval
    
    if loop_mode:
        logger.info(f"Starting performer worker in loop mode (interval: {interval}s)")
        run_count = 0
        try:
            while True:
                run_count += 1
                logger.info(f"Starting run #{run_count}")
                
                processed_ids, total_updated = run_worker(dry_run)
                
                if processed_ids == 0:
                    logger.warning("No performer IDs found. Will retry in {interval} seconds.")
                
                logger.info(f"Sleeping for {interval} seconds...")
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt. Exiting loop mode.")
            return
    else:
        # Run once
        run_worker(dry_run)

if __name__ == "__main__":
    main()
