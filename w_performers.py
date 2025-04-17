import os
import boto3 #type:ignore
import logging
import argparse
import sys
from dotenv import load_dotenv #type:ignore 
from botocore.exceptions import NoCredentialsError, ClientError #type:ignore
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
        str: 'updated' if update was performed, 'skipped' if already had TRUE status, 'failed' on error
    """
    try:
        # Get current metadata
        head_response = s3_client.head_object(
            Bucket=S3_GOOD_BUCKET,
            Key=image_key
        )
        
        # Log original metadata for debugging
        original_metadata = head_response.get('Metadata', {})
        logger.debug(f"ORIGINAL METADATA for {image_key}: {original_metadata}")
        
        # Store the content type
        content_type = head_response.get('ContentType', 'image/webp')
        
        # Check if perfimg_status is already TRUE
        if original_metadata.get('perfimg_status') == 'TRUE':
            logger.info(f"Image {image_key} already has perfimg_status=TRUE. Skipping.")
            return 'skipped'
        
        # Create a new metadata dictionary with only the fields we want to preserve
        new_metadata = {}
        
        # First, copy any existing metadata fields we always want to keep
        for key in ['uploader-initials', 'review_status', 'bad_reason']:
            if key in original_metadata:
                new_metadata[key] = original_metadata[key]
        
        # CRUCIAL: Preserve upload_time exactly as is, only if it exists
        if 'upload_time' in original_metadata:
            new_metadata['upload_time'] = original_metadata['upload_time']
            logger.debug(f"Preserving original upload_time: {new_metadata['upload_time']}")
        
        # Ensure required fields exist with appropriate defaults
        if 'uploader-initials' not in new_metadata:
            new_metadata['uploader-initials'] = 'Unknown'
            
        if 'review_status' not in new_metadata:
            new_metadata['review_status'] = 'FALSE'
        
        # Set the perfimg_status to TRUE - this is the only field we're changing
        new_metadata['perfimg_status'] = 'TRUE'
        
        # Log the new metadata for comparison
        logger.debug(f"NEW METADATA for {image_key}: {new_metadata}")
        
        if dry_run:
            logger.info(f"DRY RUN: Would update perfimg_status for {image_key} to TRUE")
            return 'updated'
        
        # Copy object to itself with new metadata
        s3_client.copy_object(
            CopySource={'Bucket': S3_GOOD_BUCKET, 'Key': image_key},
            Bucket=S3_GOOD_BUCKET,
            Key=image_key,
            Metadata=new_metadata,
            MetadataDirective='REPLACE',
            ContentType=content_type
        )
        
        # Verify the update worked correctly by checking the metadata again
        try:
            verify_response = s3_client.head_object(
                Bucket=S3_GOOD_BUCKET,
                Key=image_key
            )
            updated_metadata = verify_response.get('Metadata', {})
            logger.debug(f"VERIFIED METADATA for {image_key}: {updated_metadata}")
            
            # Check if upload_time is still the same
            if 'upload_time' in original_metadata and 'upload_time' in updated_metadata:
                if original_metadata['upload_time'] != updated_metadata['upload_time']:
                    logger.warning(f"Upload time changed! Original: {original_metadata['upload_time']}, New: {updated_metadata['upload_time']}")
                else:
                    logger.debug(f"Upload time verified unchanged: {updated_metadata['upload_time']}")
        except Exception as e:
            logger.error(f"Error verifying metadata update for {image_key}: {e}")
        
        logger.info(f"Updated perfimg_status for {image_key} to TRUE")
        return 'updated'
        
    except Exception as e:
        logger.error(f"Error updating perfimg_status for {image_key}: {e}")
        return 'failed'

def update_incredible_perfimg_status(image_key, dry_run=False):
    """
    Updates the perfimg_status metadata for a specific image in the Incredible bucket to TRUE.
    
    Args:
        image_key (str): The S3 key of the image to update
        dry_run (bool): If True, only log what would be done without making changes
        
    Returns:
        str: 'updated' if update was performed, 'skipped' if already had TRUE status, 'failed' on error
    """
    try:
        # Get current metadata
        head_response = s3_client.head_object(
            Bucket=S3_INCREDIBLE_BUCKET,
            Key=image_key
        )
        
        # Log original metadata for debugging
        original_metadata = head_response.get('Metadata', {})
        logger.debug(f"ORIGINAL METADATA for {image_key}: {original_metadata}")
        
        # Store the content type
        content_type = head_response.get('ContentType', 'image/webp')
        
        # Check if perfimg_status is already TRUE
        if original_metadata.get('perfimg_status') == 'TRUE':
            logger.info(f"Image {image_key} already has perfimg_status=TRUE in Incredible bucket. Skipping.")
            return 'skipped'
        
        # Create a new metadata dictionary with only the fields we want to preserve
        new_metadata = {}
        
        # First, copy any existing metadata fields we always want to keep
        for key in ['uploader-initials', 'review_status', 'bad_reason']:
            if key in original_metadata:
                new_metadata[key] = original_metadata[key]
        
        # CRUCIAL: Preserve upload_time exactly as is, only if it exists
        if 'upload_time' in original_metadata:
            new_metadata['upload_time'] = original_metadata['upload_time']
            logger.debug(f"Preserving original upload_time: {new_metadata['upload_time']}")
        
        # Ensure required fields exist with appropriate defaults
        if 'uploader-initials' not in new_metadata:
            new_metadata['uploader-initials'] = 'Unknown'
            
        if 'review_status' not in new_metadata:
            new_metadata['review_status'] = 'TRUE'  # Always TRUE for incredible bucket
        
        # Set the perfimg_status to TRUE - this is the only field we're changing
        new_metadata['perfimg_status'] = 'TRUE'
        
        # Log the new metadata for comparison
        logger.debug(f"NEW METADATA for {image_key}: {new_metadata}")
        
        if dry_run:
            logger.info(f"DRY RUN: Would update perfimg_status for {image_key} to TRUE in Incredible bucket")
            return 'updated'
        
        # Copy object to itself with new metadata
        s3_client.copy_object(
            CopySource={'Bucket': S3_INCREDIBLE_BUCKET, 'Key': image_key},
            Bucket=S3_INCREDIBLE_BUCKET,
            Key=image_key,
            Metadata=new_metadata,
            MetadataDirective='REPLACE',
            ContentType=content_type
        )
        
        # Verify the update worked correctly by checking the metadata again
        try:
            verify_response = s3_client.head_object(
                Bucket=S3_INCREDIBLE_BUCKET,
                Key=image_key
            )
            updated_metadata = verify_response.get('Metadata', {})
            logger.debug(f"VERIFIED METADATA for {image_key}: {updated_metadata}")
            
            # Check if upload_time is still the same
            if 'upload_time' in original_metadata and 'upload_time' in updated_metadata:
                if original_metadata['upload_time'] != updated_metadata['upload_time']:
                    logger.warning(f"Upload time changed! Original: {original_metadata['upload_time']}, New: {updated_metadata['upload_time']}")
                else:
                    logger.debug(f"Upload time verified unchanged: {updated_metadata['upload_time']}")
        except Exception as e:
            logger.error(f"Error verifying metadata update for {image_key}: {e}")
        
        logger.info(f"Updated perfimg_status for {image_key} to TRUE in Incredible bucket")
        return 'updated'
        
    except Exception as e:
        logger.error(f"Error updating perfimg_status for {image_key} in Incredible bucket: {e}")
        return 'failed'

def update_bad_perfimg_status(image_key, dry_run=False):
    """
    Updates the perfimg_status metadata for a specific image in the Bad bucket to TRUE.
    
    Args:
        image_key (str): The S3 key of the image to update
        dry_run (bool): If True, only log what would be done without making changes
        
    Returns:
        str: 'updated' if update was performed, 'skipped' if already had TRUE status, 'failed' on error
    """
    try:
        # Get current metadata
        head_response = s3_client.head_object(
            Bucket=S3_BAD_BUCKET,
            Key=image_key
        )
        
        # Log original metadata for debugging
        original_metadata = head_response.get('Metadata', {})
        logger.debug(f"ORIGINAL METADATA for {image_key}: {original_metadata}")
        
        # Store the content type
        content_type = head_response.get('ContentType', 'image/webp')
        
        # Check if perfimg_status is already TRUE
        if original_metadata.get('perfimg_status') == 'TRUE':
            logger.info(f"Image {image_key} already has perfimg_status=TRUE in Bad bucket. Skipping.")
            return 'skipped'
        
        # Create a new metadata dictionary with only the fields we want to preserve
        new_metadata = {}
        
        # First, copy any existing metadata fields we always want to keep
        for key in ['uploader-initials', 'review_status', 'bad_reason']:
            if key in original_metadata:
                new_metadata[key] = original_metadata[key]
        
        # CRUCIAL: Preserve upload_time exactly as is, only if it exists
        if 'upload_time' in original_metadata:
            new_metadata['upload_time'] = original_metadata['upload_time']
            logger.debug(f"Preserving original upload_time: {new_metadata['upload_time']}")
        
        # Ensure required fields exist with appropriate defaults
        if 'uploader-initials' not in new_metadata:
            new_metadata['uploader-initials'] = 'Unknown'
            
        if 'review_status' not in new_metadata:
            new_metadata['review_status'] = 'TRUE'  # Usually TRUE for bad bucket too
        
        # Set the perfimg_status to TRUE - this is the only field we're changing
        new_metadata['perfimg_status'] = 'TRUE'
        
        # Log the new metadata for comparison
        logger.debug(f"NEW METADATA for {image_key}: {new_metadata}")
        
        if dry_run:
            logger.info(f"DRY RUN: Would update perfimg_status for {image_key} to TRUE in Bad bucket")
            return 'updated'
        
        # Copy object to itself with new metadata
        s3_client.copy_object(
            CopySource={'Bucket': S3_BAD_BUCKET, 'Key': image_key},
            Bucket=S3_BAD_BUCKET,
            Key=image_key,
            Metadata=new_metadata,
            MetadataDirective='REPLACE',
            ContentType=content_type
        )
        
        # Verify the update worked correctly by checking the metadata again
        try:
            verify_response = s3_client.head_object(
                Bucket=S3_BAD_BUCKET,
                Key=image_key
            )
            updated_metadata = verify_response.get('Metadata', {})
            logger.debug(f"VERIFIED METADATA for {image_key}: {updated_metadata}")
            
            # Check if upload_time is still the same
            if 'upload_time' in original_metadata and 'upload_time' in updated_metadata:
                if original_metadata['upload_time'] != updated_metadata['upload_time']:
                    logger.warning(f"Upload time changed! Original: {original_metadata['upload_time']}, New: {updated_metadata['upload_time']}")
                else:
                    logger.debug(f"Upload time verified unchanged: {updated_metadata['upload_time']}")
        except Exception as e:
            logger.error(f"Error verifying metadata update for {image_key}: {e}")
        
        logger.info(f"Updated perfimg_status for {image_key} to TRUE in Bad bucket")
        return 'updated'
        
    except Exception as e:
        logger.error(f"Error updating perfimg_status for {image_key} in Bad bucket: {e}")
        return 'failed'

def process_performer_id(performer_id, dry_run=False):
    """
    Process a single performer ID - find matching images and update their metadata.
    
    Args:
        performer_id (str): The performer ID to process
        dry_run (bool): If True, only log what would be done without making changes
        
    Returns:
        tuple: (performer_id, count of updated images, count of skipped images)
    """
    total_updated = 0
    total_skipped = 0
    
    # Process Good bucket
    good_images = get_good_images_with_performer_id(performer_id)
    good_updated = 0
    good_skipped = 0
    
    if good_images:
        logger.info(f"Found {len(good_images)} images with performer ID {performer_id} in Good bucket")
        
        for image_key in good_images:
            result = update_perfimg_status(image_key, dry_run)
            if result == 'updated':
                good_updated += 1
            elif result == 'skipped':
                good_skipped += 1
    
    # Process Incredible bucket
    incredible_images = get_incredible_images_with_performer_id(performer_id)
    incredible_updated = 0
    incredible_skipped = 0
    
    if incredible_images:
        logger.info(f"Found {len(incredible_images)} images with performer ID {performer_id} in Incredible bucket")
        
        for image_key in incredible_images:
            result = update_incredible_perfimg_status(image_key, dry_run)
            if result == 'updated':
                incredible_updated += 1
            elif result == 'skipped':
                incredible_skipped += 1
    
    # Process Bad bucket
    bad_images = get_bad_images_with_performer_id(performer_id)
    bad_updated = 0
    bad_skipped = 0
    
    if bad_images:
        logger.info(f"Found {len(bad_images)} images with performer ID {performer_id} in Bad bucket")
        
        for image_key in bad_images:
            result = update_bad_perfimg_status(image_key, dry_run)
            if result == 'updated':
                bad_updated += 1
            elif result == 'skipped':
                bad_skipped += 1
    
    total_updated = good_updated + incredible_updated + bad_updated
    total_skipped = good_skipped + incredible_skipped + bad_skipped
    
    if total_updated > 0 or total_skipped > 0:
        logger.info(f"Performer ID {performer_id} summary:")
        logger.info(f"  - Updated: {total_updated} (Good: {good_updated}, Incredible: {incredible_updated}, Bad: {bad_updated})")
        logger.info(f"  - Skipped: {total_skipped} (Good: {good_skipped}, Incredible: {incredible_skipped}, Bad: {bad_skipped})")
    
    return performer_id, total_updated, total_skipped

def run_worker(dry_run=False):
    """Run a single worker pass."""
    start_time = time.time()
    logger.info(f"Starting performers_worker{'(DRY RUN)' if dry_run else ''}")
    
    # Get all performer IDs
    performer_ids = get_performer_ids()
    
    if not performer_ids:
        logger.warning("No performer IDs found. Exiting.")
        return 0, 0, 0
    
    # Statistics
    total_updated = 0
    total_skipped = 0
    processed_ids = 0
    
    # Process performer IDs in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_performer = {executor.submit(process_performer_id, performer_id, dry_run): performer_id for performer_id in performer_ids}
        
        for future in concurrent.futures.as_completed(future_to_performer):
            performer_id = future_to_performer[future]
            processed_ids += 1
            
            try:
                _, updated_count, skipped_count = future.result()
                total_updated += updated_count
                total_skipped += skipped_count
                
                # Log progress periodically
                if processed_ids % 50 == 0 or processed_ids == len(performer_ids):
                    logger.info(f"Progress: {processed_ids}/{len(performer_ids)} performer IDs processed")
                
            except Exception as e:
                logger.error(f"Error processing performer ID {performer_id}: {e}")
    
    elapsed_time = time.time() - start_time
    logger.info(f"Completed performers_worker in {elapsed_time:.2f} seconds")
    logger.info(f"Processed {processed_ids} performer IDs")
    logger.info(f"Updated perfimg_status for {total_updated} images")
    logger.info(f"Skipped {total_skipped} images that already had perfimg_status=TRUE")
    
    return processed_ids, total_updated, total_skipped

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
                
                processed_ids, total_updated, total_skipped = run_worker(dry_run)
                
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
