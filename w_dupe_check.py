#!/usr/bin/env python3
import os
import time
import boto3 #type:ignore
import logging
import traceback
import sys
from io import BytesIO
from dotenv import load_dotenv #type:ignore
import schedule #type:ignore
from datetime import datetime
from collections import defaultdict

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('dupe_check_worker')

AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")
S3_GOOD_BUCKET = os.getenv("S3_GOOD_BUCKET")
S3_GOOD_BUCKET_PREFIX = os.getenv("S3_GOOD_BUCKET_PREFIX", "")
S3_ISSUE_BUCKET = os.getenv("S3_ISSUE_BUCKET")
S3_ISSUE_BUCKET_PREFIX = os.getenv("S3_ISSUE_BUCKET_PREFIX", "")

logger.info(f"Using Good bucket: {S3_GOOD_BUCKET}")
if S3_GOOD_BUCKET_PREFIX:
    logger.info(f"Using Good bucket prefix: {S3_GOOD_BUCKET_PREFIX}")

logger.info(f"Using Issue bucket: {S3_ISSUE_BUCKET}")
if S3_ISSUE_BUCKET_PREFIX:
    logger.info(f"Using Issue bucket prefix: {S3_ISSUE_BUCKET_PREFIX}")

missing_vars = []
if not AWS_ACCESS_KEY_ID: missing_vars.append("AWS_ACCESS_KEY_ID")
if not AWS_SECRET_ACCESS_KEY: missing_vars.append("AWS_SECRET_ACCESS_KEY")
if not AWS_REGION: missing_vars.append("AWS_REGION")
if not S3_GOOD_BUCKET: missing_vars.append("S3_GOOD_BUCKET")
if not S3_ISSUE_BUCKET: missing_vars.append("S3_ISSUE_BUCKET")

if missing_vars:
    for var in missing_vars:
        logger.error(f"Missing required environment variable: {var}")
    sys.exit(1)

try:
    s3_client = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )
except Exception as e:
    logger.error(f"Failed to initialize S3 client: {e}")
    sys.exit(1)

def move_to_issue_bucket(key, metadata, content_type='image/webp'):
    """Move an image from the Good bucket to the Issue bucket"""
    try:
        filename = key.split('/')[-1]
        
        issue_dest_key = f"{S3_ISSUE_BUCKET_PREFIX}{filename}" if S3_ISSUE_BUCKET_PREFIX else filename
        
        s3_client.copy_object(
            CopySource={'Bucket': S3_GOOD_BUCKET, 'Key': key},
            Bucket=S3_ISSUE_BUCKET,
            Key=issue_dest_key,
            Metadata=metadata,
            ContentType=content_type
        )
        
        s3_client.delete_object(
            Bucket=S3_GOOD_BUCKET,
            Key=key
        )
        
        logger.info(f"Moved image {key} to issue bucket at {issue_dest_key}")
        return True
    except Exception as e:
        logger.error(f"Failed to move image {key} to issue bucket: {e}")
        return False

def check_duplicates():
    """Check for duplicate images in the Good bucket"""
    try:
        if S3_GOOD_BUCKET_PREFIX:
            logger.info(f"Checking for duplicates in {S3_GOOD_BUCKET}/{S3_GOOD_BUCKET_PREFIX}")
        else:
            logger.info(f"Checking for duplicates in {S3_GOOD_BUCKET}")
        
        list_params = {
            'Bucket': S3_GOOD_BUCKET
        }
        
        if S3_GOOD_BUCKET_PREFIX:
            list_params['Prefix'] = S3_GOOD_BUCKET_PREFIX
            
        response = s3_client.list_objects_v2(**list_params)
        
        if 'Contents' not in response:
            logger.info("No objects found in the Good bucket")
            return
            
        image_dict = defaultdict(list)
        
        for obj in response['Contents']:
            key = obj['Key']
            filename = key.split('/')[-1]
            
            if not filename.lower().endswith('.webp'):
                continue
                
            base_name = os.path.splitext(filename)[0]
            
            try:
                head_response = s3_client.head_object(
                    Bucket=S3_GOOD_BUCKET,
                    Key=key
                )
                metadata = head_response.get('Metadata', {})
                content_type = head_response.get('ContentType', 'image/webp')
                
                image_dict[base_name].append({
                    'key': key,
                    'metadata': metadata,
                    'content_type': content_type,
                    'last_modified': obj['LastModified']
                })
            except Exception as e:
                logger.error(f"Error getting metadata for {key}: {e}")
                
        duplicates_found = 0
        
        for base_name, images in image_dict.items():
            if len(images) > 1:
                logger.info(f"Found {len(images)} duplicates for {base_name}")
                duplicates_found += 1
                
                for img in images:
                    upload_time_str = img['metadata'].get('upload_time')
                    if upload_time_str:
                        try:
                            img['upload_datetime'] = datetime.fromisoformat(upload_time_str)
                        except ValueError:
                            img['upload_datetime'] = img['last_modified']
                    else:
                        img['upload_datetime'] = img['last_modified']
                
                true_reviewed = [img for img in images if img['metadata'].get('review_status', 'FALSE').upper() == 'TRUE']
                false_reviewed = [img for img in images if img['metadata'].get('review_status', 'FALSE').upper() != 'TRUE']
                
                # Case 1: Different review status - keep TRUE, move FALSE to Issue Bucket
                if true_reviewed and false_reviewed:
                    logger.info(f"Duplicates with different review status found for {base_name}")
                    
                    for img in false_reviewed:
                        move_to_issue_bucket(
                            img['key'], 
                            img['metadata'], 
                            img['content_type']
                        )
                
                # Case 2: Same review status - keep oldest, move newer to Issue Bucket
                elif len(true_reviewed) > 1 or len(false_reviewed) > 1:
                    logger.info(f"Duplicates with same review status found for {base_name}")
                    
                    if len(true_reviewed) > 1:
                        true_reviewed.sort(key=lambda x: x['upload_datetime'])
                        
                        for img in true_reviewed[1:]:
                            move_to_issue_bucket(
                                img['key'], 
                                img['metadata'], 
                                img['content_type']
                            )
                    
                    if len(false_reviewed) > 1:
                        false_reviewed.sort(key=lambda x: x['upload_datetime'])
                        
                        for img in false_reviewed[1:]:
                            move_to_issue_bucket(
                                img['key'], 
                                img['metadata'], 
                                img['content_type']
                            )
        
        logger.info(f"Duplicate check done: [{duplicates_found}] duplicates")
                
    except Exception as e:
        logger.error(f"Error checking for duplicates: {e}")
        traceback.print_exc()

def run_scheduler():
    """Run the scheduler to check for duplicates periodically"""
    logger.info("Starting duplicate check worker service")
    schedule.every(5).minutes.do(check_duplicates) # 5 minutes

    # schedule.every(30).seconds.do(check_duplicates) # 30 seconds

    check_duplicates()
    
    while True:
        try:
            schedule.run_pending()
            time.sleep(1)
        except Exception as e:
            logger.error(f"Error in scheduler loop: {e}")
            traceback.print_exc()
            time.sleep(60)

if __name__ == "__main__":
    run_scheduler()
