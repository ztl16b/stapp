import os
import random
import boto3
import requests
from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify
from dotenv import load_dotenv
from botocore.exceptions import NoCredentialsError, ClientError
from functools import wraps
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from requests.exceptions import RequestException
import uuid
import time
from io import BytesIO
import redis
from rq import Queue
import threading
import json
import base64

load_dotenv()

# Get the absolute path to the templates directory
template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
app = Flask(__name__, template_folder=template_dir)

# Set a fixed secret key for session management
app.secret_key = os.environ.get('SECRET_KEY', 'your-fixed-secret-key-for-development')

# SIMPLIFIED SESSION CONFIGURATION
app.config.update(
    SESSION_COOKIE_SECURE=False,  # Set to False to allow HTTP in development
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),  # 30 days
)

# AWS Configuration
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")
S3_UPLOAD_BUCKET = os.getenv("S3_UPLOAD_BUCKET")
S3_GOOD_BUCKET = os.getenv("S3_GOOD_BUCKET")
S3_BAD_BUCKET = os.getenv("S3_BAD_BUCKET")
S3_INCREDIBLE_BUCKET = os.getenv("S3_INCREDIBLE_BUCKET")
S3_TEMP_BUCKET = os.getenv("S3_TEMP_BUCKET")

BYTESCALE_API_KEY = os.getenv("BYTESCALE_API_KEY")
BYTESCALE_UPLOAD_URL = os.getenv("BYTESCALE_UPLOAD_URL")

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
BROWSE_PASSWORD = os.getenv("BROWSE_PASSWORD")

# Redis connection and queue setup
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')
redis_conn = redis.from_url(REDIS_URL)
upload_queue = Queue('uploads', connection=redis_conn)
results_ttl = 3600  # Results will stay in Redis for 1 hour

# Thread local storage for S3 clients
thread_local = threading.local()

def get_s3_client():
    """Get thread-local S3 client to improve connection reuse"""
    if not hasattr(thread_local, 's3_client'):
        thread_local.s3_client = boto3.client(
            's3',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_REGION
        )
    return thread_local.s3_client

# Main S3 client for non-worker operations
try:
    s3_client = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )
    
    # Create a reusable S3 upload configuration 
    s3_upload_config = boto3.s3.transfer.TransferConfig(
        multipart_threshold=8 * 1024 * 1024,  # 8MB
        max_concurrency=10,
        multipart_chunksize=8 * 1024 * 1024,  # 8MB
        use_threads=True
    )
except NoCredentialsError:
    raise ValueError("AWS credentials not found. Ensure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set.")
except Exception as e:
    raise ValueError(f"Error initializing S3 client: {e}")

# Cache for image format validation
VALID_IMAGE_SIGNATURES = {
    b'\xff\xd8\xff': 'JPEG',    # JPEG
    b'\x89\x50\x4e\x47': 'PNG', # PNG
    b'\x47\x49\x46': 'GIF',     # GIF
    b'\x42\x4d': 'BMP',         # BMP
    b'\x52\x49\x46\x46': 'WEBP' # WEBP
}

# Background processing function for RQ
def process_image_task(file_data_b64, filename, content_type, batch_id):
    """
    Worker function that will be called by RQ worker processes
    """
    try:
        # Decode base64 file data
        file_data = base64.b64decode(file_data_b64)
        
        # Get thread-local S3 client
        s3 = get_s3_client()
        
        # Quick validation of file format using first few bytes
        file_start = file_data[:8]  # First 8 bytes is enough for all formats
        is_valid_image = any(file_start.startswith(sig) for sig in VALID_IMAGE_SIGNATURES)
                
        if not is_valid_image:
            return {
                'status': 'error',
                'message': 'Invalid image format',
                'filename': filename,
                'batch_id': batch_id
            }
        
        # Generate unique upload path to prevent overwrites
        timestamp = int(time.time() * 1000)  # millisecond precision
        random_suffix = str(uuid.uuid4())[:8]
        upload_path = f"tmp_upload/{batch_id}/{timestamp}_{random_suffix}_{filename}"
        
        # Upload to S3 directly from memory
        file_obj = BytesIO(file_data)
        
        s3.upload_fileobj(
            file_obj,
            S3_TEMP_BUCKET,
            upload_path,
            ExtraArgs={'ContentType': content_type},
            Config=s3_upload_config
        )
        
        file_obj.close()
        
        # Update the batch progress in Redis
        update_batch_progress(batch_id)
        
        return {
            'status': 'success',
            'message': 'Upload successful',
            's3_path': upload_path,
            'filename': filename,
            'batch_id': batch_id
        }
    except Exception as e:
        print(f"Error processing {filename}: {str(e)}")
        return {
            'status': 'error',
            'message': str(e),
            'filename': filename,
            'batch_id': batch_id
        }

def update_batch_progress(batch_id):
    """Update the progress counter for a batch"""
    key = f"batch:{batch_id}:progress"
    completed = redis_conn.incr(key)
    total = redis_conn.get(f"batch:{batch_id}:total")
    if total:
        total = int(total)
        if completed >= total:
            redis_conn.set(f"batch:{batch_id}:status", "complete")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            session['next'] = request.url
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        browse_password = os.getenv('BROWSE_PASSWORD')
        admin_password = os.getenv('ADMIN_PASSWORD')
        
        if password == browse_password or password == admin_password:
            # Simple session setup
            session['logged_in'] = True
            session.permanent = True  # Make the session permanent
            
            flash('Login successful!', 'success')
            
            # Handle redirect
            next_url = session.get('next')
            if next_url:
                session.pop('next', None)
                return redirect(next_url)
            return redirect(url_for('browse_buckets'))
            
        flash('Invalid password. Please try again.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

def init_session():
    """Initialize or refresh session data"""
    if 'logged_in' not in session:
        session['logged_in'] = False
    if session.get('logged_in') and 'login_time' not in session:
        session['login_time'] = datetime.now().isoformat()
        session['user_id'] = str(uuid.uuid4())

@app.before_request
def before_request():
    init_session()
    # Log request details for debugging
    app.logger.debug(f"Request path: {request.path}")
    app.logger.debug(f"Session data: {dict(session)}")

@app.route('/')
def index():
    return redirect(url_for('upload'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        # Basic validation for file upload
        if 'files' not in request.files:
            flash('No files part', 'warning')
            return redirect(request.url)
            
        files = request.files.getlist('files')
        if not files or all(file.filename == '' for file in files):
            flash('No selected files', 'warning')
            return redirect(request.url)
        
        # When using client-side sequential uploads, we'll receive just one file at a time
        file = files[0]  # Process just the first file
        
        # Validate file size
        if file.content_length and file.content_length > 5 * 1024 * 1024:
            flash(f'File {file.filename} exceeds 5MB size limit', 'danger')
            return redirect(request.url)
        
        # Read file data
        file_data = file.read()
        if not file_data:
            flash(f'File {file.filename} is empty', 'danger')
            return redirect(request.url)
        
        # Process the file
        filename = secure_filename(file.filename)
        content_type = file.content_type
        
        # Process the single file directly
        result = process_image(file_data, filename, content_type)
        
        if result['status'] == 'success':
            flash(f'Successfully uploaded {filename}', 'success')
        else:
            flash(f'Failed to upload {filename}: {result["message"]}', 'danger')
        
        # For AJAX requests, return a simplified page
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'status': result['status'],
                'message': result['message'],
                'filename': filename
            })
        
        return redirect(request.url)
    
    return render_template('upload.html')

@app.route('/batch-status/<batch_id>')
def batch_status(batch_id):
    # Get batch information from Redis
    total = redis_conn.get(f"batch:{batch_id}:total")
    progress = redis_conn.get(f"batch:{batch_id}:progress")
    status = redis_conn.get(f"batch:{batch_id}:status")
    
    if not total:
        flash('Batch not found or has expired', 'warning')
        return redirect(url_for('upload'))
    
    total = int(total)
    progress = int(progress or 0)
    status = status.decode('utf-8') if status else 'unknown'
    
    percent_complete = (progress / total) * 100 if total > 0 else 0
    
    return render_template(
        'batch_status.html',
        batch_id=batch_id,
        total=total,
        progress=progress,
        percent_complete=percent_complete,
        status=status
    )

@app.route('/api/batch-progress/<batch_id>')
def batch_progress_api(batch_id):
    """API endpoint to check batch progress via AJAX"""
    total = redis_conn.get(f"batch:{batch_id}:total")
    progress = redis_conn.get(f"batch:{batch_id}:progress")
    status = redis_conn.get(f"batch:{batch_id}:status")
    
    if not total:
        return jsonify({
            'error': 'Batch not found or expired'
        }), 404
    
    total = int(total)
    progress = int(progress or 0)
    status = status.decode('utf-8') if status else 'processing'
    
    return jsonify({
        'batch_id': batch_id,
        'total': total,
        'progress': progress,
        'percent_complete': (progress / total) * 100 if total > 0 else 0,
        'status': status,
        'is_complete': status == 'complete'
    })

def process_image(file_data, filename, content_type, timeout=None):
    """
    Upload an image directly to the S3 temp bucket in its original format.
    
    Args:
        file_data: The file data as bytes
        filename: The original filename
        content_type: The content type of the file
        timeout: Kept for backwards compatibility
        
    Returns:
        dict: Status information about the processing
    """
    try:
        # Quick validation of file format using first few bytes
        file_start = file_data[:8]  # First 8 bytes is enough for all formats
        is_valid_image = any(file_start.startswith(sig) for sig in VALID_IMAGE_SIGNATURES)
                
        if not is_valid_image:
            return {
                'status': 'error',
                'message': 'Invalid image format',
                'filename': filename
            }
        
        # Use original filename directly without adding timestamp or UUID
        upload_path = f"tmp_upload/{filename}"
        
        # Upload to S3 using BytesIO for memory efficiency
        file_obj = BytesIO(file_data)
        
        s3_client.upload_fileobj(
            file_obj,
            S3_TEMP_BUCKET,
            upload_path,
            ExtraArgs={'ContentType': content_type},
            Config=s3_upload_config
        )
        
        file_obj.close()
        
        return {
            'status': 'success',
            'message': 'Upload successful',
            's3_path': upload_path,
            'filename': filename
        }
    except Exception as e:
        app.logger.error(f"Error processing {filename}: {str(e)}")
        return {
            'status': 'error',
            'message': str(e),
            'filename': filename
        }

def get_random_image_key(bucket_name):
    """Gets a random object key from the specified bucket."""
    try:
        # Different prefix depending on which bucket we're using
        prefix = None
        if bucket_name == S3_UPLOAD_BUCKET:
            prefix = 'temp_performer_at_venue_images/'
        elif bucket_name == S3_TEMP_BUCKET:
            prefix = 'tmp_upload/'
            
        # Get list of objects with the appropriate prefix
        response = s3_client.list_objects_v2(
            Bucket=bucket_name,
            Prefix=prefix if prefix else ''
        )
            
        if 'Contents' in response and response['Contents']:
            all_objects = response['Contents']
            # For temp bucket, accept all image file types
            if bucket_name == S3_TEMP_BUCKET:
                image_objects = [
                    obj for obj in all_objects
                    if obj['Key'].lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp'))
                ]
            else:
                # For upload bucket, keep original webp filter
                image_objects = [
                    obj for obj in all_objects
                    if obj['Key'].lower().endswith(('.webp'))
                ]
                
            if image_objects:
                return random.choice(image_objects)['Key']
    except ClientError as e:
        app.logger.error(f"Error listing objects in bucket {bucket_name}: {e}")
        flash(f"Error accessing bucket {bucket_name}: {e.response['Error']['Message']}", "danger")
    except Exception as e:
        app.logger.error(f"Unexpected error listing objects: {e}")
        flash("An unexpected error occurred while listing files.", "danger")
    return None

def move_s3_object(source_bucket, dest_bucket, object_key, destination=None):
    """Moves an object from source_bucket to dest_bucket."""
    dest_key = object_key
    original_key = object_key
    
    # Extract the filename from the path, handling both old and new formats
    filename = object_key.split('/')[-1]
    
    # Remove any timestamp prefixes for the destination
    if '_' in filename:
        # Handle new timestamp_uuid_filename.ext format
        parts = filename.split('_', 2)
        if len(parts) >= 3:
            filename = parts[2]  # Get just the original filename part
    
    if destination == 'bad' or (dest_bucket == S3_BAD_BUCKET and destination is None):
        dest_key = f"bad_images/{filename}"
    elif destination == 'good' or (dest_bucket == S3_GOOD_BUCKET and destination is None):
        dest_key = f"images/performer-at-venue/detail/{filename}"
    elif destination == 'incredible' or (dest_bucket == S3_INCREDIBLE_BUCKET and destination is None):
        dest_key = f"incredible_images/{filename}"
    
    copy_source = {'Bucket': source_bucket, 'Key': original_key}
    try:
        # Determine content type based on file extension
        content_type = 'image/jpeg'  # Default
        if filename.lower().endswith('.png'):
            content_type = 'image/png'
        elif filename.lower().endswith('.gif'):
            content_type = 'image/gif'
        elif filename.lower().endswith('.webp'):
            content_type = 'image/webp'
        elif filename.lower().endswith(('.jpg', '.jpeg')):
            content_type = 'image/jpeg'
            
        s3_client.copy_object(
            CopySource=copy_source,
            Bucket=dest_bucket,
            Key=dest_key,
            ContentType=content_type
        )
        app.logger.info(f"Copied {original_key} from {source_bucket} to {dest_bucket} as {dest_key}")

        if dest_bucket != S3_INCREDIBLE_BUCKET or source_bucket == S3_UPLOAD_BUCKET:
            s3_client.delete_object(Bucket=source_bucket, Key=original_key)
            app.logger.info(f"Deleted {original_key} from {source_bucket}")
        return True
    except ClientError as e:
        app.logger.error(f"Error moving object {original_key}: {e}")
        flash(f"Error moving file: {e.response['Error']['Message']}", "danger")
    except Exception as e:
        app.logger.error(f"Unexpected error moving object {original_key}: {e}")
        flash("An unexpected error occurred while moving the file.", "danger")
    return False

def get_presigned_url(bucket_name, object_key, expiration=3600):
    """Generate a presigned URL to share an S3 object."""
    try:
        response = s3_client.generate_presigned_url('get_object',
                                                    Params={'Bucket': bucket_name,
                                                            'Key': object_key},
                                                    ExpiresIn=expiration)
        return response
    except ClientError as e:
        app.logger.error(f"Error generating presigned URL for {object_key}: {e}")
        flash(f"Error generating image URL: {e.response['Error']['Message']}", "danger")
    except Exception as e:
        app.logger.error(f"Unexpected error generating presigned URL: {e}")
        flash("An unexpected error occurred while generating the image URL.", "danger")
    return None

@app.route('/review')
@login_required
def review_image_route():
    # Log session information for debugging
    app.logger.info(f"Review page accessed by user {session.get('user_id', 'unknown')}")
    
    # First check the temp bucket for any images
    image_key = get_random_image_key(S3_TEMP_BUCKET)
    source_bucket = S3_TEMP_BUCKET
    
    # If no images in temp bucket, check the upload bucket
    if not image_key:
        image_key = get_random_image_key(S3_UPLOAD_BUCKET)
        source_bucket = S3_UPLOAD_BUCKET
    
    image_url = None
    if image_key:
        image_url = get_presigned_url(source_bucket, image_key)
        app.logger.info(f"Loading image for review: {image_key} from {source_bucket}")

    return render_template('review.html', image_url=image_url, image_key=image_key, source_bucket=source_bucket)

@app.route('/move/<action>/<path:image_key>', methods=['POST'])
@login_required
def move_image_route(action, image_key):
    if not image_key:
        flash("No image key provided for move operation.", "danger")
        return redirect(url_for('review_image_route'))

    # Get the source bucket from the form data
    source_bucket = request.form.get('source_bucket', S3_UPLOAD_BUCKET)
    
    # Log the action
    app.logger.info(f"Moving image with key: {image_key} from {source_bucket} to {action} bucket")

    success = False
    if action == 'incredible':
        # For incredible images, we need to copy to both buckets without deleting the original
        # until both copies are successful
        
        # First, copy to the good bucket without deleting the original
        if copy_s3_object(source_bucket, S3_GOOD_BUCKET, image_key, destination='good'):
            # If first copy succeeds, copy to incredible bucket
            if copy_s3_object(source_bucket, S3_INCREDIBLE_BUCKET, image_key, destination='incredible'):
                # Now that both copies are successful, delete the original
                try:
                    s3_client.delete_object(Bucket=source_bucket, Key=image_key)
                    app.logger.info(f"Deleted {image_key} from {source_bucket} after successful copies")
                    success = True
                    flash(f"Image '{image_key}' moved to both good and incredible buckets.", "success")
                except Exception as e:
                    app.logger.error(f"Error deleting original file after copies: {e}")
                    flash("Image copied successfully but there was an error deleting the original.", "warning")
                    success = True
    else:
        # For good and bad actions, use the original logic
        destination_bucket = S3_GOOD_BUCKET if action == 'good' else S3_BAD_BUCKET
        if move_s3_object(source_bucket, destination_bucket, image_key, destination=action):
            success = True
            flash(f"Image '{image_key}' moved to {action} bucket.", "success")

    if not success:
        flash(f"Failed to move image '{image_key}' to {action} bucket.", "danger")

    return redirect(url_for('review_image_route'))

def copy_s3_object(source_bucket, dest_bucket, object_key, destination=None):
    """Copies an object from source_bucket to dest_bucket without deleting the original."""
    dest_key = object_key
    original_key = object_key
    
    # Extract the filename from the path, handling both old and new formats
    filename = object_key.split('/')[-1]
    
    # Remove any timestamp prefixes for the destination
    if '_' in filename:
        # Handle new timestamp_uuid_filename.ext format
        parts = filename.split('_', 2)
        if len(parts) >= 3:
            filename = parts[2]  # Get just the original filename part
    
    if destination == 'bad' or (dest_bucket == S3_BAD_BUCKET and destination is None):
        dest_key = f"bad_images/{filename}"
    elif destination == 'good' or (dest_bucket == S3_GOOD_BUCKET and destination is None):
        dest_key = f"images/performer-at-venue/detail/{filename}"
    elif destination == 'incredible' or (dest_bucket == S3_INCREDIBLE_BUCKET and destination is None):
        dest_key = f"incredible_images/{filename}"
    
    copy_source = {'Bucket': source_bucket, 'Key': original_key}
    try:
        # Determine content type based on file extension
        content_type = 'image/jpeg'  # Default
        if filename.lower().endswith('.png'):
            content_type = 'image/png'
        elif filename.lower().endswith('.gif'):
            content_type = 'image/gif'
        elif filename.lower().endswith('.webp'):
            content_type = 'image/webp'
        elif filename.lower().endswith(('.jpg', '.jpeg')):
            content_type = 'image/jpeg'
            
        s3_client.copy_object(
            CopySource=copy_source,
            Bucket=dest_bucket,
            Key=dest_key,
            ContentType=content_type
        )
        app.logger.info(f"Copied {original_key} from {source_bucket} to {dest_bucket} as {dest_key}")
        return True
    except ClientError as e:
        app.logger.error(f"Error copying object {original_key}: {e}")
        flash(f"Error copying file: {e.response['Error']['Message']}", "danger")
    except Exception as e:
        app.logger.error(f"Unexpected error copying object {original_key}: {e}")
        flash("An unexpected error occurred while copying the file.", "danger")
    return False

@app.route('/browse')
@login_required
def browse_buckets():
    app.logger.info("Entering browse_buckets function")
    app.logger.info(f"S3_GOOD_BUCKET: {S3_GOOD_BUCKET}")
    app.logger.info(f"S3_BAD_BUCKET: {S3_BAD_BUCKET}")
    app.logger.info(f"S3_INCREDIBLE_BUCKET: {S3_INCREDIBLE_BUCKET}")
    app.logger.info(f"S3_UPLOAD_BUCKET: {S3_UPLOAD_BUCKET}")
    app.logger.info(f"S3_TEMP_BUCKET: {S3_TEMP_BUCKET}")
    
    buckets = {
        'good': {'name': 'Good Images', 'bucket': S3_GOOD_BUCKET, 'prefix': 'images/performer-at-venue/detail/'},
        'bad': {'name': 'Bad Images', 'bucket': S3_BAD_BUCKET, 'prefix': 'bad_images/'},
        'incredible': {'name': 'Incredible Images', 'bucket': S3_INCREDIBLE_BUCKET, 'prefix': 'incredible_images/'},
        'upload': {'name': 'Upload Images', 'bucket': S3_UPLOAD_BUCKET, 'prefix': 'temp_performer_at_venue_images/'},
        'temp': {'name': 'Temp Bucket', 'bucket': S3_TEMP_BUCKET, 'prefix': 'tmp_upload/'}
    }
    app.logger.info(f"Buckets dictionary: {buckets}")
    return render_template('browse.html', buckets=buckets)

@app.route('/browse/<bucket_name>')
@login_required
def browse_bucket(bucket_name):
    buckets = {
        'good': {'name': 'Good Images', 'bucket': S3_GOOD_BUCKET, 'prefix': 'images/performer-at-venue/detail/'},
        'bad': {'name': 'Bad Images', 'bucket': S3_BAD_BUCKET, 'prefix': 'bad_images/'},
        'incredible': {'name': 'Incredible Images', 'bucket': S3_INCREDIBLE_BUCKET, 'prefix': 'incredible_images/'},
        'upload': {'name': 'Upload Images', 'bucket': S3_UPLOAD_BUCKET, 'prefix': 'temp_performer_at_venue_images/'},
        'temp': {'name': 'Temp Bucket', 'bucket': S3_TEMP_BUCKET, 'prefix': 'tmp_upload/'}
    }
    
    if bucket_name not in buckets:
        flash('Invalid bucket selected', 'danger')
        return redirect(url_for('browse_buckets'))
        
    bucket_info = buckets[bucket_name]
    try:
        # Get page number, search query, sort order, and date filter from query parameters
        page = request.args.get('page', 1, type=int)
        search_query = request.args.get('search', '').lower()
        sort_order = request.args.get('sort', 'desc')  # Default to descending order
        date_from = request.args.get('date_from', '')  # Date filter from
        date_to = request.args.get('date_to', '')
        per_page = 200
        
        # Create a paginator for list_objects_v2 with MaxKeys parameter
        paginator = s3_client.get_paginator('list_objects_v2')
        
        # Get objects using the paginator with MaxKeys
        all_files = []
        for page_obj in paginator.paginate(
            Bucket=bucket_info['bucket'],
            Prefix=bucket_info['prefix'],
            MaxKeys=per_page  # Limit the number of keys returned per request
        ):
            if 'Contents' in page_obj:
                for item in page_obj['Contents']:
                    # Skip the prefix itself
                    if item['Key'] != bucket_info['prefix']:
                        # Apply search filter if search query exists
                        if search_query == 'letters':
                            # Get just the filename part (after the last slash) and remove the .webp extension
                            filename = item['Key'].split('/')[-1].replace('.webp', '')
                            if any(c.isalpha() for c in filename):
                                # Apply date filter if dates are provided
                                if apply_date_filter(item['LastModified'], date_from, date_to):
                                    all_files.append({
                                        'key': item['Key'],
                                        'size': item['Size'],
                                        'last_modified': item['LastModified']
                                    })
                        elif not search_query or search_query in item['Key'].lower():
                            # Apply date filter if dates are provided
                            if apply_date_filter(item['LastModified'], date_from, date_to):
                                all_files.append({
                                    'key': item['Key'],
                                    'size': item['Size'],
                                    'last_modified': item['LastModified']
                                })
        
        # Sort files by last_modified date
        all_files.sort(key=lambda x: x['last_modified'], reverse=(sort_order == 'desc'))
        
        # Calculate pagination info
        total_files = len(all_files)
        total_pages = (total_files + per_page - 1) // per_page
        
        # Ensure page is within valid range
        if page < 1:
            page = 1
        elif page > total_pages and total_pages > 0:
            page = total_pages
        
        # Slice the files list to get only the current page
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        current_page_files = all_files[start_idx:end_idx]
        
        return render_template('browse_bucket.html', 
                             bucket=bucket_info,
                             bucket_name=bucket_name,
                             files=current_page_files,
                             current_page=page,
                             total_pages=total_pages,
                             total_files=total_files,
                             search_query=search_query,
                             sort_order=sort_order,
                             date_from=date_from,
                             date_to=date_to)
    except Exception as e:
        app.logger.error(f"Error listing bucket contents: {e}")
        flash(f'Error accessing bucket: {str(e)}', 'danger')
        return redirect(url_for('browse_buckets'))

def apply_date_filter(last_modified, date_from, date_to):
    """Apply date filter to a file's last modified date"""
    if not date_from and not date_to:
        return True
    
    file_date = last_modified.date()
    
    if date_from:
        try:
            from_date = datetime.strptime(date_from, '%Y-%m-%d').date()
            if file_date < from_date:
                return False
        except ValueError:
            app.logger.error(f"Invalid date_from format: {date_from}")
    
    if date_to:
        try:
            to_date = datetime.strptime(date_to, '%Y-%m-%d').date()
            if file_date > to_date:
                return False
        except ValueError:
            app.logger.error(f"Invalid date_to format: {date_to}")
    
    return True

@app.route('/delete/<bucket_name>/<path:object_key>', methods=['POST'])
@login_required
def delete_object_route(bucket_name, object_key):
    buckets = {
        'good': S3_GOOD_BUCKET,
        'bad': S3_BAD_BUCKET,
        'incredible': S3_INCREDIBLE_BUCKET,
        'upload': S3_UPLOAD_BUCKET,
        'temp': S3_TEMP_BUCKET
    }
    
    if bucket_name not in buckets:
        flash('Invalid bucket selected', 'danger')
        return redirect(url_for('browse_buckets'))
        
    try:
        s3_client.delete_object(
            Bucket=buckets[bucket_name],
            Key=object_key
        )
        flash(f'File {object_key} deleted successfully', 'success')
    except Exception as e:
        app.logger.error(f"Error deleting object: {e}")
        flash(f'Error deleting file: {str(e)}', 'danger')
    
    return redirect(url_for('browse_bucket', bucket_name=bucket_name))

@app.route('/delete-all/<bucket_name>', methods=['POST'])
@login_required
def delete_all_objects_route(bucket_name):
    buckets = {
        'good': {'name': 'Good Images', 'bucket': S3_GOOD_BUCKET, 'prefix': 'images/performer-at-venue/detail/'},
        'bad': {'name': 'Bad Images', 'bucket': S3_BAD_BUCKET, 'prefix': 'bad_images/'},
        'incredible': {'name': 'Incredible Images', 'bucket': S3_INCREDIBLE_BUCKET, 'prefix': 'incredible_images/'},
        'upload': {'name': 'Upload Images', 'bucket': S3_UPLOAD_BUCKET, 'prefix': 'temp_performer_at_venue_images/'},
        'temp': {'name': 'Temp Bucket', 'bucket': S3_TEMP_BUCKET, 'prefix': 'tmp_upload/'}
    }
    
    if bucket_name not in buckets:
        flash('Invalid bucket selected', 'danger')
        return redirect(url_for('browse_buckets'))
    
    bucket_info = buckets[bucket_name]
    deleted_count = 0
    error_count = 0
    
    try:
        # Get all objects in the bucket with the specified prefix
        paginator = s3_client.get_paginator('list_objects_v2')
        
        # Collect all keys to delete
        keys_to_delete = []
        for page in paginator.paginate(
            Bucket=bucket_info['bucket'],
            Prefix=bucket_info['prefix']
        ):
            if 'Contents' in page:
                for item in page['Contents']:
                    keys_to_delete.append(item['Key'])
        
        # Delete objects in batches of 1000 (S3 limit)
        batch_size = 1000
        for i in range(0, len(keys_to_delete), batch_size):
            batch = keys_to_delete[i:i+batch_size]
            try:
                response = s3_client.delete_objects(
                    Bucket=bucket_info['bucket'],
                    Delete={'Objects': [{'Key': key} for key in batch]}
                )
                
                # Count successful deletions
                if 'Deleted' in response:
                    deleted_count += len(response['Deleted'])
                
                # Count errors
                if 'Errors' in response:
                    error_count += len(response['Errors'])
                    
            except Exception as e:
                app.logger.error(f"Error deleting batch of objects: {e}")
                error_count += len(batch)
        
        if error_count == 0:
            flash(f'Successfully deleted {deleted_count} files from {bucket_info["name"]}', 'success')
        else:
            flash(f'Deleted {deleted_count} files, but encountered {error_count} errors', 'warning')
            
    except Exception as e:
        app.logger.error(f"Error listing bucket contents: {e}")
        flash(f'Error accessing bucket: {str(e)}', 'danger')
    
    return redirect(url_for('browse_bucket', bucket_name=bucket_name))

if __name__ == '__main__':
    if not os.path.exists('templates'):
        os.makedirs('templates')
    # For local development
    app.run(debug=True)
    
# Set higher timeout for Gunicorn when running on Heroku
# Usage: gunicorn --timeout 300 app:app