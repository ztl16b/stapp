#!/usr/bin/env python3
import os
import boto3
from dotenv import load_dotenv
from datetime import datetime
import time

# Load environment variables
load_dotenv()

# AWS Configuration
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")
S3_INCREDIBLE_BUCKET = os.getenv("S3_INCREDIBLE_BUCKET")

# Initialize S3 client
s3_client = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION
)

def update_review_status():
    print(f"Starting update of review_status for all images in {S3_INCREDIBLE_BUCKET}")
    
    # Set the prefix for incredible images
    prefix = "incredible_images/"
    
    # Get all objects in the bucket with the prefix
    paginator = s3_client.get_paginator('list_objects_v2')
    
    # Initialize counters
    total_objects = 0
    updated_count = 0
    already_true_count = 0
    error_count = 0
    
    # Process each page of objects
    for page in paginator.paginate(Bucket=S3_INCREDIBLE_BUCKET, Prefix=prefix):
        if 'Contents' not in page:
            continue
        
        for item in page['Contents']:
            total_objects += 1
            object_key = item['Key']
            
            try:
                # Get current metadata
                head_response = s3_client.head_object(
                    Bucket=S3_INCREDIBLE_BUCKET,
                    Key=object_key
                )
                
                metadata = head_response.get('Metadata', {})
                content_type = head_response.get('ContentType', 'image/webp')
                
                # Check if review_status is already TRUE
                if metadata.get('review_status') == 'TRUE':
                    print(f"[{total_objects}] Already TRUE: {object_key}")
                    already_true_count += 1
                    continue
                
                # Set review_status to TRUE
                metadata['review_status'] = 'TRUE'
                
                # Ensure perfimg_status is preserved or set to FALSE if not already in metadata
                if 'perfimg_status' not in metadata:
                    metadata['perfimg_status'] = 'FALSE'
                
                # Use copy_object to update the metadata
                s3_client.copy_object(
                    CopySource={'Bucket': S3_INCREDIBLE_BUCKET, 'Key': object_key},
                    Bucket=S3_INCREDIBLE_BUCKET,
                    Key=object_key,
                    Metadata=metadata,
                    MetadataDirective='REPLACE',
                    ContentType=content_type
                )
                
                updated_count += 1
                print(f"[{total_objects}] Updated: {object_key}")
                
                # Add a small delay to prevent API throttling
                time.sleep(0.1)
                
            except Exception as e:
                error_count += 1
                print(f"[{total_objects}] Error updating {object_key}: {str(e)}")
    
    # Print summary
    print("\n=== Summary ===")
    print(f"Total objects processed: {total_objects}")
    print(f"Already had review_status=TRUE: {already_true_count}")
    print(f"Successfully updated: {updated_count}")
    print(f"Errors: {error_count}")
    print("===============")

if __name__ == "__main__":
    # Check if the bucket name is configured
    if not S3_INCREDIBLE_BUCKET:
        print("Error: S3_INCREDIBLE_BUCKET environment variable is not set")
        exit(1)
    
    # Run the update process
    start_time = datetime.now()
    print(f"Script started at: {start_time}")
    
    update_review_status()
    
    end_time = datetime.now()
    print(f"Script completed at: {end_time}")
    print(f"Total duration: {end_time - start_time}") 