import boto3
from dotenv import load_dotenv
import os
import sys

load_dotenv()

BUCKETS = {
    '1': {
        'name': 'Good Images',
        'bucket': 'etickets-resources',
        'prefix': 'images/performer-at-venue/detail/'
    },
    '2': {
        'name': 'Bad Images',
        'bucket': 'etickets-content-test-bucket',
        'prefix': 'bad_images/'
    },
    '3': {
        'name': 'Incredible Images',
        'bucket': 'etickets-content-test-bucket',
        'prefix': 'incredible_images/'
    },
    '4': {
        'name': 'Content Images',
        'bucket': 'etickets-resources',
        'prefix': 'content/performer-at-venue/'
    }
}

def display_menu():
    """Display the bucket selection menu"""
    print("\n===== S3 Bucket Image Lister =====")
    print("Select a bucket to list images from:")
    for key, bucket in BUCKETS.items():
        print(f"{key}. {bucket['name']} ({bucket['bucket']})")
    print("q. Quit")
    print("===================================")

def get_s3_list(bucket_name, prefix):
    """Get list of objects from S3 bucket with specified prefix"""
    s3 = boto3.client(
        's3',
        region_name=os.getenv("AWS_REGION"),
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
    )

    paginator = s3.get_paginator('list_objects_v2')
    pages = paginator.paginate(Bucket=bucket_name, Prefix=prefix)

    key_list = []
    count = 0

    print(f"\nListing images from {bucket_name} with prefix {prefix}:")
    print("-" * 80)

    for page in pages:
        if 'Contents' in page:
            for obj in page['Contents']:
                count += 1
                print(f"{count}. {obj['Key']}")
                key_list.append(obj['Key'])
    
    print("-" * 80)
    print(f"Total images found: {count}")
    
    return key_list

def main():
    """Main function to run the bucket selection and listing process"""
    while True:
        display_menu()
        choice = input("\nEnter your choice: ").strip()
        
        if choice.lower() == 'q':
            print("Exiting program. Goodbye!")
            sys.exit(0)
        
        if choice in BUCKETS:
            bucket_info = BUCKETS[choice]
            get_s3_list(bucket_info['bucket'], bucket_info['prefix'])
            
            input("\nPress Enter to continue...")
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()