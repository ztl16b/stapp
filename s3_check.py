import boto3, os
from dotenv import load_dotenv

load_dotenv()

# Get AWS credentials from environment
aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
aws_region = os.environ.get('AWS_REGION')

if aws_access_key and aws_secret_key:
    # Create S3 client
    s3_client = boto3.client(
        's3',
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=aws_region
    )
    
    # Check bucket content
    bucket = 'etickets-content-test-bucket'
    prefix = 'temp/'
    
    print(f'Checking contents of {bucket}/{prefix}')
    
    try:
        response = s3_client.list_objects_v2(
            Bucket=bucket,
            Prefix=prefix,
            MaxKeys=10
        )
        
        if 'Contents' in response:
            print(f'Found {len(response.get("Contents", []))} files:')
            for obj in response.get('Contents', []):
                print(f'- {obj["Key"]} ({obj["Size"]} bytes)')
                
                # If this is the CSV file, try to get content
                if 'performer-infos' in obj['Key'] and '.csv' in obj['Key'].lower():
                    print(f'\nChecking CSV file: {obj["Key"]}')
                    try:
                        obj_response = s3_client.get_object(
                            Bucket=bucket,
                            Key=obj['Key']
                        )
                        content = obj_response['Body'].read(1000).decode('utf-8')
                        print(f'Sample content (first 1000 bytes):\n{content}')
                    except Exception as e:
                        print(f'Error reading file content: {e}')
        else:
            print('No files found with that prefix')
    except Exception as e:
        print(f'Error listing objects: {e}')
else:
    print('AWS credentials not found in environment variables') 