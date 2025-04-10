import os
import requests
import boto3
from celery_worker import app
from botocore.exceptions import NoCredentialsError, ClientError

# Get environment variables
BYTESCALE_API_KEY = os.getenv("BYTESCALE_API_KEY")
BYTESCALE_UPLOAD_URL = os.getenv("BYTESCALE_UPLOAD_URL")
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")
S3_UPLOAD_BUCKET = os.getenv("S3_UPLOAD_BUCKET")

# Initialize S3 client
s3_client = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION
)

@app.task(bind=True, name='process_image')
def process_image(self, file_data, filename, content_type):
    """
    Process an image using Bytescale API and upload to S3.
    
    Args:
        file_data: The file data as bytes
        filename: The original filename
        content_type: The content type of the file
        
    Returns:
        dict: Status information about the task
    """
    try:
        # Update task state
        self.update_state(state='PROCESSING', meta={'status': 'Uploading to Bytescale'})
        
        # Prepare headers and files for Bytescale API
        headers = {
            'Authorization': f'Bearer {BYTESCALE_API_KEY}'
        }
        
        files_data = {
            'file': (filename, file_data, content_type)
        }
        
        # Upload to Bytescale
        upload_response = requests.post(BYTESCALE_UPLOAD_URL, headers=headers, files=files_data)
        
        if not upload_response.ok:
            return {
                'status': 'error',
                'message': f'Bytescale upload failed: {upload_response.text}'
            }
        
        # Parse response to get file URL
        json_response = upload_response.json()
        file_url = None
        
        for file_obj in json_response.get("files", []):
            if file_obj.get("formDataFieldName") == "file":
                file_url = file_obj.get("fileUrl")
                break
        
        if not file_url:
            return {
                'status': 'error',
                'message': 'Could not find file URL in Bytescale response'
            }
        
        # Update task state
        self.update_state(state='PROCESSING', meta={'status': 'Downloading processed image'})
        
        # Create the processed image URL with the required parameters
        processed_url = file_url.replace("/raw/", "/image/") + "?f=webp&w=464&h=510&fit=crop&crop=center"
        
        # Download the processed image
        download_response = requests.get(processed_url, stream=True)
        
        if not download_response.ok:
            return {
                'status': 'error',
                'message': f'Error downloading processed image: {download_response.text}'
            }
        
        # Update task state
        self.update_state(state='PROCESSING', meta={'status': 'Uploading to S3'})
        
        # Upload the processed image to S3
        upload_path = f"temp_performer_at_venue_images/{filename.rsplit('.', 1)[0]}.webp"
        
        # Use streaming upload to S3
        s3_client.upload_fileobj(
            download_response.raw,
            S3_UPLOAD_BUCKET,
            upload_path,
            ExtraArgs={'ContentType': 'image/webp'}
        )
        
        return {
            'status': 'success',
            'message': f'Successfully processed and uploaded {filename}',
            's3_path': upload_path
        }
        
    except ClientError as e:
        return {
            'status': 'error',
            'message': f'S3 Upload Error: {str(e)}'
        }
    except NoCredentialsError:
        return {
            'status': 'error',
            'message': 'AWS credentials not found'
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Unexpected error: {str(e)}'
        } 