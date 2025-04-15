import os
import boto3
import argparse
from dotenv import load_dotenv
import logging

# run a test with: python rename.py --find "text_to_find" --replace "text_to_replace" --dry-run
# run with: python rename.py --find "text_to_find" --replace "text_to_replace"
# run in specified bucket with: python rename.py --find "text_to_find" --replace "text_to_replace" --bucket GOOD

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

def list_objects_in_bucket(bucket_name, prefix):
    """List all objects in the specified bucket with the given prefix."""
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

def rename_file(bucket_name, source_key, dest_key, dry_run=False):
    """
    Rename an S3 object by copying to new key and deleting the old one.
    In dry_run mode, only logs what would happen without making changes.
    """
    if dry_run:
        logger.info(f"[DRY RUN] Would rename {source_key} to {dest_key} in {bucket_name}")
        return True
    
    try:
        # Get object metadata
        response = s3_client.head_object(Bucket=bucket_name, Key=source_key)
        content_type = response.get('ContentType', 'application/octet-stream')
        metadata = response.get('Metadata', {})
        
        # Copy the object to the new key
        s3_client.copy_object(
            CopySource={'Bucket': bucket_name, 'Key': source_key},
            Bucket=bucket_name,
            Key=dest_key,
            ContentType=content_type,
            Metadata=metadata,
            MetadataDirective='REPLACE'
        )
        
        logger.info(f"Copied {source_key} to {dest_key} in {bucket_name}")
        
        # Delete the original
        s3_client.delete_object(Bucket=bucket_name, Key=source_key)
        logger.info(f"Deleted original object {source_key} from {bucket_name}")
        
        return True
    except Exception as e:
        logger.error(f"Error renaming {source_key} to {dest_key} in {bucket_name}: {e}")
        return False

def process_bucket(bucket_name, find_text, replace_text, dry_run=False):
    """Process all objects in the specified bucket to rename files."""
    prefix = BUCKET_PREFIXES.get(bucket_name, '')
    objects = list_objects_in_bucket(bucket_name, prefix)
    
    if not objects:
        logger.info(f"No objects found in bucket {bucket_name} with prefix {prefix}")
        return 0, 0
    
    logger.info(f"Found {len(objects)} objects in bucket {bucket_name} with prefix {prefix}")
    
    success_count = 0
    error_count = 0
    skipped_count = 0
    
    for obj in objects:
        source_key = obj['Key']
        
        # Skip if it's just the prefix itself
        if source_key == prefix:
            continue
        
        # Get directory and filename parts
        path_parts = source_key.rsplit('/', 1)
        if len(path_parts) > 1:
            dir_path, filename = path_parts
            dir_path += '/'  # Re-add the trailing slash
        else:
            dir_path = ''
            filename = path_parts[0]
        
        # Check if the filename contains the text to find
        if find_text in filename:
            # Replace the text in the filename
            new_filename = filename.replace(find_text, replace_text)
            dest_key = dir_path + new_filename
            
            logger.info(f"Found match in {source_key} - will rename to {dest_key}")
            
            # Skip if the source and destination are the same
            if source_key == dest_key:
                logger.info(f"Skipping {source_key} as the name would not change")
                skipped_count += 1
                continue
            
            # Rename the file
            if rename_file(bucket_name, source_key, dest_key, dry_run):
                success_count += 1
            else:
                error_count += 1
        else:
            skipped_count += 1
    
    logger.info(f"Bucket {bucket_name} processing complete:")
    logger.info(f"  - {success_count} files renamed successfully")
    logger.info(f"  - {error_count} errors")
    logger.info(f"  - {skipped_count} files skipped (no match)")
    
    return success_count, error_count

def main():
    """Main function to parse arguments and process buckets."""
    parser = argparse.ArgumentParser(description='Rename files in S3 buckets by replacing text in filenames.')
    parser.add_argument('--find', required=True, help='Text to find in filenames')
    parser.add_argument('--replace', required=True, help='Text to replace with')
    parser.add_argument('--bucket', help='Specific bucket to process (default: process all buckets)')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be renamed without making changes')
    
    args = parser.parse_args()
    
    logger.info(f"Starting rename process with find='{args.find}', replace='{args.replace}'")
    if args.dry_run:
        logger.info("DRY RUN MODE - No changes will be made")
    
    total_success = 0
    total_errors = 0
    
    # Determine which buckets to process
    if args.bucket:
        bucket_var_name = f"S3_{args.bucket.upper()}_BUCKET"
        bucket_name = globals().get(bucket_var_name)
        
        if not bucket_name:
            logger.error(f"Unknown bucket: {args.bucket}")
            logger.info("Available buckets: UPLOAD, GOOD, BAD, INCREDIBLE, TEMP, ISSUE")
            return
        
        buckets_to_process = {bucket_name: args.bucket.upper()}
    else:
        buckets_to_process = {
            S3_UPLOAD_BUCKET: "UPLOAD",
            S3_GOOD_BUCKET: "GOOD",
            S3_BAD_BUCKET: "BAD", 
            S3_INCREDIBLE_BUCKET: "INCREDIBLE",
            S3_TEMP_BUCKET: "TEMP",
            S3_ISSUE_BUCKET: "ISSUE"
        }
    
    # Process each bucket
    for bucket_name, bucket_label in buckets_to_process.items():
        if not bucket_name:
            logger.warning(f"Bucket {bucket_label} is not configured, skipping")
            continue
        
        logger.info(f"Processing bucket: {bucket_label} ({bucket_name})")
        success, errors = process_bucket(bucket_name, args.find, args.replace, args.dry_run)
        total_success += success
        total_errors += errors
    
    logger.info("Rename process complete:")
    logger.info(f"  - Total files renamed: {total_success}")
    logger.info(f"  - Total errors: {total_errors}")
    if args.dry_run:
        logger.info("This was a dry run. No actual changes were made.")

if __name__ == "__main__":
    main() 

# run with python rename.py --find "text_to_find" --replace "text_to_replace" --dry-run