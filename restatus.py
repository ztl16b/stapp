import os
import boto3
import argparse
from dotenv import load_dotenv
import logging

# Run with: python restatus.py --local-folder "/path/to/local/folder" --status "new_status" --bucket GOOD
# Run in dry-run mode: python restatus.py --local-folder "/path/to/local/folder" --status "new_status" --bucket GOOD --dry-run

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# AWS Configuration
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")
S3_UPLOAD_BUCKET = os.getenv("S3_UPLOAD_BUCKET")
S3_GOOD_BUCKET = os.getenv("S3_GOOD_BUCKET")
S3_BAD_BUCKET = os.getenv("S3_BAD_BUCKET")
S3_INCREDIBLE_BUCKET = os.getenv("S3_INCREDIBLE_BUCKET")
S3_TEMP_BUCKET = os.getenv("S3_TEMP_BUCKET")
S3_ISSUE_BUCKET = os.getenv("S3_ISSUE_BUCKET")

# Initialize S3 client
try:
    s3_client = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )
except Exception as e:
    logger.error(f"Error initializing S3 client: {e}")
    exit(1)

# Define bucket prefixes for each bucket
BUCKET_PREFIXES = {
    S3_UPLOAD_BUCKET: 'temp_performer_at_venue_images/',
    S3_GOOD_BUCKET: 'images/performer-at-venue/detail/',
    S3_BAD_BUCKET: 'bad_images/',
    S3_INCREDIBLE_BUCKET: 'incredible_images/',
    S3_TEMP_BUCKET: 'tmp_upload/',
    S3_ISSUE_BUCKET: 'issue_files/'
}

def list_all_objects_in_bucket(bucket_name, prefix):
    """List all objects in the specified bucket with given prefix."""
    try:
        objects = []
        paginator = s3_client.get_paginator('list_objects_v2')
        
        for page in paginator.paginate(Bucket=bucket_name, Prefix=prefix):
            if 'Contents' in page:
                objects.extend(page['Contents'])
        
        return objects
    except Exception as e:
        logger.error(f"Error listing objects in bucket {bucket_name}: {e}")
        return []

def get_local_files(local_folder):
    """Get a list of filenames in the local folder."""
    try:
        if not os.path.exists(local_folder):
            logger.error(f"Local folder does not exist: {local_folder}")
            return []
        
        local_files = []
        for filename in os.listdir(local_folder):
            # Skip hidden files and directories
            if not filename.startswith('.') and os.path.isfile(os.path.join(local_folder, filename)):
                local_files.append(filename)
        
        logger.info(f"Found {len(local_files)} files in local folder: {local_folder}")
        return local_files
    except Exception as e:
        logger.error(f"Error reading local folder {local_folder}: {e}")
        return []

def update_review_status(bucket_name, object_key, new_status, dry_run=False):
    """
    Update the review_status metadata for an S3 object while preserving all other metadata.
    In dry_run mode, only logs what would happen without making changes.
    """
    if dry_run:
        logger.info(f"[DRY RUN] Would update review_status to '{new_status}' for {object_key} in {bucket_name}")
        return True
    
    try:
        # Get object metadata
        response = s3_client.head_object(Bucket=bucket_name, Key=object_key)
        content_type = response.get('ContentType', 'application/octet-stream')
        metadata = response.get('Metadata', {})
        
        # Update review_status field while preserving other metadata
        metadata['review_status'] = new_status
        
        # Copy the object to itself with updated metadata
        s3_client.copy_object(
            CopySource={'Bucket': bucket_name, 'Key': object_key},
            Bucket=bucket_name,
            Key=object_key,
            ContentType=content_type,
            Metadata=metadata,
            MetadataDirective='REPLACE'
        )
        
        logger.info(f"Updated review_status to '{new_status}' for {object_key} in {bucket_name}")
        return True
    except Exception as e:
        logger.error(f"Error updating review_status for {object_key} in {bucket_name}: {e}")
        return False

def find_matching_s3_objects(bucket_name, prefix, local_filenames, dry_run=False, new_status=""):
    """Find S3 objects that match local filenames and update their review_status."""
    all_objects = list_all_objects_in_bucket(bucket_name, prefix)
    
    if not all_objects:
        logger.info(f"No objects found in bucket {bucket_name} with prefix {prefix}")
        return 0, 0
    
    logger.info(f"Found {len(all_objects)} objects in bucket {bucket_name} with prefix {prefix}")
    
    # Create a set of local filenames for faster lookup
    local_filenames_set = set(local_filenames)
    
    success_count = 0
    error_count = 0
    matched_count = 0
    
    for obj in all_objects:
        object_key = obj['Key']
        
        # Extract just the filename from the object key
        _, filename = os.path.split(object_key)
        
        # Check if the filename matches any of our local files
        if filename in local_filenames_set:
            matched_count += 1
            logger.info(f"Found matching file: {filename} -> {object_key}")
            
            # Update the review_status
            if update_review_status(bucket_name, object_key, new_status, dry_run):
                success_count += 1
            else:
                error_count += 1
    
    logger.info(f"Found {matched_count} matching files in bucket {bucket_name}")
    logger.info(f"  - {success_count} files updated successfully")
    logger.info(f"  - {error_count} errors")
    
    return success_count, error_count

def main():
    """Main function to parse arguments and process files."""
    parser = argparse.ArgumentParser(description='Update review_status metadata for S3 objects that match local files.')
    parser.add_argument('--local-folder', required=True, help='Path to local folder containing reference files')
    parser.add_argument('--status', required=True, help='New review_status value to set')
    parser.add_argument('--bucket', required=True, help='Specific bucket to process (UPLOAD, GOOD, BAD, etc.)')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be updated without making changes')
    
    args = parser.parse_args()
    
    logger.info(f"Starting metadata update process with new review_status='{args.status}'")
    if args.dry_run:
        logger.info("DRY RUN MODE - No changes will be made")
    
    # Get local files
    local_files = get_local_files(args.local_folder)
    if not local_files:
        logger.error("No local files found to match against. Exiting.")
        return
    
    # Determine which bucket to process
    bucket_var_name = f"S3_{args.bucket.upper()}_BUCKET"
    bucket_name = globals().get(bucket_var_name)
    
    if not bucket_name:
        logger.error(f"Unknown bucket: {args.bucket}")
        logger.info("Available buckets: UPLOAD, GOOD, BAD, INCREDIBLE, TEMP, ISSUE")
        return
    
    # Get the prefix for the selected bucket
    prefix = BUCKET_PREFIXES.get(bucket_name, '')
    logger.info(f"Processing bucket: {args.bucket} ({bucket_name}) with prefix {prefix}")
    
    # Find matching S3 objects and update their metadata
    success, errors = find_matching_s3_objects(bucket_name, prefix, local_files, args.dry_run, args.status)
    
    logger.info("Metadata update process complete:")
    logger.info(f"  - Total files updated: {success}")
    logger.info(f"  - Total errors: {errors}")
    if args.dry_run:
        logger.info("This was a dry run. No actual changes were made.")

if __name__ == "__main__":
    main() 