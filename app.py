import os
import random
import boto3
import requests
from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify
from dotenv import load_dotenv
from botocore.exceptions import NoCredentialsError, ClientError
from functools import wraps
from datetime import datetime, timedelta, timezone
from werkzeug.utils import secure_filename
from requests.exceptions import RequestException
import uuid
import time
from io import BytesIO
import json
import base64
import logging
import threading
import re
import hashlib
import mimetypes
import psutil
import concurrent.futures
from zoneinfo import ZoneInfo

load_dotenv()

# Get the absolute path to the templates directory
template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
app = Flask(__name__, template_folder=template_dir)

# Set a fixed secret key for session management
app.secret_key = os.environ.get('SECRET_KEY', 'your-fixed-secret-key-for-development')

# Define MST timezone (UTC-7)
MST = ZoneInfo("Etc/GMT+7")

# Custom Jinja filter for MST datetime formatting
def format_datetime_mst(dt_utc):
    if not isinstance(dt_utc, datetime):
        return dt_utc # Return as is if not a datetime object
    # Ensure the datetime is timezone-aware (assume UTC if naive)
    if dt_utc.tzinfo is None:
        dt_utc = dt_utc.replace(tzinfo=timezone.utc)
    # Convert to MST
    dt_mst = dt_utc.astimezone(MST)
    # Format as requested
    return dt_mst.strftime('%m/%d/%y %I:%M %p')

# Register the custom filter
app.jinja_env.filters['datetime_mst'] = format_datetime_mst

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
S3_ISSUE_BUCKET = os.getenv("S3_ISSUE_BUCKET")

BYTESCALE_API_KEY = os.getenv("BYTESCALE_API_KEY")
BYTESCALE_UPLOAD_URL = os.getenv("BYTESCALE_UPLOAD_URL")

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
BROWSE_PASSWORD = os.getenv("BROWSE_PASSWORD")

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
        
        # Get uploader initials and validate
        uploader_initials = request.form.get('uploaderInitials', '').strip()
        if not uploader_initials:
            error_msg = 'Uploader initials are required'
            app.logger.warning(error_msg)
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'status': 'error',
                    'message': error_msg
                })
            flash(error_msg, 'warning')
            return redirect(request.url)
        
        # Validate initials format: any text followed by _##_## where ## are two digits
        initials_pattern = re.compile(r'^.+_\d{2}_\d{2}$')
        if not initials_pattern.match(uploader_initials):
            error_msg = 'Initials must follow the format: any text followed by _##_## (e.g., ABC_12_34)'
            app.logger.warning(f"Invalid initials format: {uploader_initials}")
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'status': 'error',
                    'message': error_msg
                })
            flash(error_msg, 'warning')
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
        
        # Process the single file directly with uploader initials
        result = process_image(file_data, filename, content_type, uploader_initials=uploader_initials)
        
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

def process_image(file_data, filename, content_type, timeout=None, uploader_initials=None):
    """
    Upload an image directly to the S3 temp bucket in its original format.
    
    Args:
        file_data: The file data as bytes
        filename: The original filename (with perf_id-ven_id format)
        content_type: The content type of the file
        timeout: Kept for backwards compatibility
        uploader_initials: Initials of the person uploading the file
        
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
        
        # Use original filename exactly as provided - the image_processor.py will handle format conversion
        upload_path = f"tmp_upload/{filename}"
        
        # Add metadata with uploader initials if provided
        extra_args = {'ContentType': content_type}
        if uploader_initials:
            extra_args['Metadata'] = {'uploader-initials': uploader_initials, 'review_status': 'FALSE'}
            app.logger.info(f"Adding uploader initials metadata: {uploader_initials}")
        
        # Upload to S3 using BytesIO for memory efficiency
        file_obj = BytesIO(file_data)
        
        s3_client.upload_fileobj(
            file_obj,
            S3_TEMP_BUCKET,
            upload_path,
            ExtraArgs=extra_args,
            Config=s3_upload_config
        )
        
        file_obj.close()
        
        return {
            'status': 'success',
            'message': 'Upload successful',
            's3_path': upload_path,
            'filename': filename,
            'uploader_initials': uploader_initials
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
                # For upload bucket, keep only webp files and make sure they match the expected format
                # Format should be numeric_id.numeric_id.webp
                image_objects = []
                for obj in all_objects:
                    filename = obj['Key'].split('/')[-1]
                    # Skip files that don't end with .webp
                    if not filename.lower().endswith('.webp'):
                        continue
                        
                    # Skip files that are marked as duplicates (ending with _dupe.webp)
                    if "_dupe." in filename:
                        continue
                        
                    # Skip files that don't match numeric_id.numeric_id.webp format
                    base_name = os.path.splitext(filename)[0]  # Remove .webp
                    parts = base_name.split('.')
                    
                    # Must have one dot separating two parts
                    if len(parts) != 2:
                        continue
                        
                    # Both parts must be numeric
                    try:
                        int(parts[0])
                        int(parts[1])
                        image_objects.append(obj)
                    except ValueError:
                        continue
                
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
    
    # Only check the upload bucket for images
    image_key = get_random_image_key(S3_UPLOAD_BUCKET)
    source_bucket = S3_UPLOAD_BUCKET
    
    image_url = None
    uploader_initials = "Unknown"
    review_status = "FALSE"
    
    if image_key:
        image_url = get_presigned_url(source_bucket, image_key)
        app.logger.info(f"Loading image for review: {image_key} from {source_bucket}")
        
        # Get metadata for the image to extract uploader initials and review status
        try:
            head_response = s3_client.head_object(
                Bucket=source_bucket,
                Key=image_key
            )
            metadata = head_response.get('Metadata', {})
            uploader_initials = metadata.get('uploader-initials', 'Unknown')
            review_status = metadata.get('review_status', 'FALSE')
            app.logger.info(f"Found metadata - uploader: {uploader_initials}, review status: {review_status}")
        except Exception as e:
            app.logger.error(f"Error getting metadata for {image_key}: {e}")

    return render_template('review.html', 
                          image_url=image_url, 
                          image_key=image_key, 
                          source_bucket=source_bucket,
                          uploader_initials=uploader_initials,
                          review_status=review_status)

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
                    # Only use the dismissable flash message, not a static one
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
            # Only log to the app logger, don't use flash messages twice
            app.logger.info(f"Image '{image_key}' moved to {action} bucket.")
            # Use a single flash message
            filename = image_key.split('/')[-1]
            flash(f"Image '{filename}' moved to {action} bucket.", "success")

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
    app.logger.info(f"S3_ISSUE_BUCKET: {S3_ISSUE_BUCKET}")
    
    # Clear success messages related to uploads from session
    flashed_messages = session.get('_flashes', [])
    if flashed_messages:
        # Keep only non-success messages or messages that don't contain "uploaded"
        filtered_messages = [(category, message) for category, message in flashed_messages 
                            if category != 'success' or 'uploaded' not in message.lower()]
        session['_flashes'] = filtered_messages
    
    buckets = {
        'good': {'name': 'Good Images', 'bucket': S3_GOOD_BUCKET, 'prefix': 'images/performer-at-venue/detail/'},
        'bad': {'name': 'Bad Images', 'bucket': S3_BAD_BUCKET, 'prefix': 'bad_images/'},
        'incredible': {'name': 'Incredible Images', 'bucket': S3_INCREDIBLE_BUCKET, 'prefix': 'incredible_images/'},
        'upload': {'name': 'Upload Images', 'bucket': S3_UPLOAD_BUCKET, 'prefix': 'temp_performer_at_venue_images/'},
        'temp': {'name': 'Temp Bucket', 'bucket': S3_TEMP_BUCKET, 'prefix': 'tmp_upload/'},
        'issue': {'name': 'Issue Images', 'bucket': S3_ISSUE_BUCKET, 'prefix': 'issue_files/'}
    }
    app.logger.info(f"Buckets dictionary: {buckets}")
    return render_template('browse.html', buckets=buckets)

@app.route('/browse/<bucket_name>')
@login_required
def browse_bucket(bucket_name):
    # Clear success messages related to uploads from session
    flashed_messages = session.get('_flashes', [])
    if flashed_messages:
        # Keep only non-success messages or messages that don't contain "uploaded"
        filtered_messages = [(category, message) for category, message in flashed_messages
                            if category != 'success' or 'uploaded' not in message.lower()]
        session['_flashes'] = filtered_messages

    buckets = {
        'good': {'name': 'Good Images', 'bucket': S3_GOOD_BUCKET, 'prefix': 'images/performer-at-venue/detail/'},
        'bad': {'name': 'Bad Images', 'bucket': S3_BAD_BUCKET, 'prefix': 'bad_images/'},
        'incredible': {'name': 'Incredible Images', 'bucket': S3_INCREDIBLE_BUCKET, 'prefix': 'incredible_images/'},
        'upload': {'name': 'Upload Images', 'bucket': S3_UPLOAD_BUCKET, 'prefix': 'temp_performer_at_venue_images/'},
        'temp': {'name': 'Temp Bucket', 'bucket': S3_TEMP_BUCKET, 'prefix': 'tmp_upload/'},
        'issue': {'name': 'Issue Images', 'bucket': S3_ISSUE_BUCKET, 'prefix': 'issue_files/'}
    }

    if bucket_name not in buckets:
        flash('Invalid bucket selected', 'danger')
        return redirect(url_for('browse_buckets'))

    bucket_info = buckets[bucket_name]
    try:
        if not bucket_info['bucket']:
            raise ValueError(f"Bucket name for '{bucket_name}' is not configured")

        # Get request parameters
        page = request.args.get('page', 1, type=int)
        search_query = request.args.get('search', '').lower()
        # Store original case for display in template, use lower for filtering
        uploader_filter_display = request.args.get('uploader', '').strip()
        uploader_filter = uploader_filter_display.lower()
        sort_order = request.args.get('sort', 'desc')
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')
        per_page = 200
        max_items_to_scan = 500000 # Limit initial scan

        prefix = str(bucket_info['prefix']) if bucket_info['prefix'] else ''

        # --- Fetch and Filter Data ---
        all_scanned_files = []
        s3 = get_s3_client() # Use thread-local client
        s3_paginator = s3.get_paginator('list_objects_v2')
        is_truncated = False
        items_scanned = 0

        app.logger.info(f"Starting scan for bucket '{bucket_name}' prefix '{prefix}', max_scan={max_items_to_scan}")

        # Scan up to max_items_to_scan or until paginator finishes
        for page_obj in s3_paginator.paginate(Bucket=bucket_info['bucket'], Prefix=prefix):
            page_truncated = False
            if 'Contents' in page_obj:
                for item in page_obj['Contents']:
                    if item['Key'] == prefix: # Skip the prefix itself
                        continue

                    items_scanned += 1
                    # Store raw data needed for initial filtering
                    all_scanned_files.append({
                        'key': item['Key'],
                        'size': item['Size'],
                        'last_modified': item['LastModified'],
                        'metadata': {} # Initialize empty
                    })

                    if items_scanned >= max_items_to_scan:
                        page_truncated = True # Mark that we stopped scanning mid-page
                        break # Stop scanning files within this page

            # Check if S3 itself reported truncation OR if we stopped mid-page
            current_page_s3_truncated = page_obj.get('IsTruncated', False)
            is_truncated = current_page_s3_truncated or page_truncated
            
            if items_scanned >= max_items_to_scan:
                 app.logger.info(f"Reached max_items_to_scan ({max_items_to_scan}). S3 IsTruncated on last page: {current_page_s3_truncated}")
                 break # Stop iterating paginator pages


        app.logger.info(f"Scanned {items_scanned} items. Final is_truncated determination: {is_truncated}")

        # --- Apply Filters (Client-side on the scanned items) ---
        # 1. Date Filter
        if date_from or date_to:
            pre_filter_count = len(all_scanned_files)
            all_scanned_files = [
                f for f in all_scanned_files if apply_date_filter(f['last_modified'], date_from, date_to)
            ]
            app.logger.info(f"Applied date filter: {pre_filter_count} -> {len(all_scanned_files)} items")

        # 2. Search Filter
        if search_query:
            pre_filter_count = len(all_scanned_files)
            if search_query == 'letters':
                temp_files = []
                for f in all_scanned_files:
                    filename = f['key'].split('/')[-1]
                    base_filename = filename.rsplit('.', 1)[0] if '.' in filename else filename
                    if any(c.isalpha() for c in base_filename):
                        temp_files.append(f)
                all_scanned_files = temp_files
            else:
                 all_scanned_files = [
                    f for f in all_scanned_files if search_query in f['key'].lower()
                ]
            app.logger.info(f"Applied search filter ('{search_query}'): {pre_filter_count} -> {len(all_scanned_files)} items")

        # 3. Uploader Filter (requires metadata fetch for *remaining* items)
        if uploader_filter:
            pre_filter_count = len(all_scanned_files)
            keys_to_fetch_metadata = [f['key'] for f in all_scanned_files]
            fetched_metadata = {}

            if keys_to_fetch_metadata: # Only fetch if there are files left
                app.logger.info(f"Fetching metadata for uploader filter for {len(keys_to_fetch_metadata)} items")
                def fetch_meta(key):
                    try:
                        # Use the same thread-local client instance
                        head = s3.head_object(Bucket=bucket_info['bucket'], Key=key)
                        return key, head.get('Metadata', {})
                    except ClientError as e:
                        if e.response['Error']['Code'] == '404':
                             app.logger.warning(f"Metadata fetch: Object not found {key}")
                        else:
                             app.logger.warning(f"Error fetching metadata for {key}: {e}")
                        return key, {} # Return empty metadata on error
                    except Exception as e:
                         app.logger.warning(f"Unexpected error fetching metadata for {key}: {e}")
                         return key, {}


                # Limit concurrency
                max_workers = min(10, os.cpu_count() + 4) # Reduce max workers slightly
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                    future_to_key = {executor.submit(fetch_meta, key): key for key in keys_to_fetch_metadata}
                    for future in concurrent.futures.as_completed(future_to_key):
                        key = future_to_key[future]
                        try:
                            _, meta = future.result()
                            fetched_metadata[key] = meta
                        except Exception as exc:
                            app.logger.error(f'{key} generated an exception during metadata fetch processing: {exc}')
                            fetched_metadata[key] = {}

                # Apply filter using fetched metadata
                temp_files = []
                for f in all_scanned_files:
                    # Ensure metadata from fetch is added to the object
                    f['metadata'] = fetched_metadata.get(f['key'], {})
                    file_uploader = f.get('metadata', {}).get('uploader-initials', '').lower()
                    if uploader_filter in file_uploader:
                        temp_files.append(f)
                all_scanned_files = temp_files
            app.logger.info(f"Applied uploader filter ('{uploader_filter}'): {pre_filter_count} -> {len(all_scanned_files)} items")

        # Final list after all filters
        filtered_files = all_scanned_files
        total_files = len(filtered_files)
        # If S3 indicated more items beyond our scan limit, the total count based on filtered items is an estimate
        total_files_estimate = is_truncated

        # --- Sort ---
        filtered_files.sort(key=lambda x: x['last_modified'], reverse=(sort_order == 'desc'))
        app.logger.info(f"Sorted {total_files} items. Estimate={total_files_estimate}")

        # --- Paginate ---
        total_pages = (total_files + per_page - 1) // per_page if total_files > 0 else 1
        if page < 1: page = 1
        # Don't redirect to last page if estimate, allow navigating beyond current known items
        elif page > total_pages and total_pages > 0 and not total_files_estimate:
             page = total_pages

        start_idx = (page - 1) * per_page
        # Only slice up to the known number of files
        end_idx = min(start_idx + per_page, total_files)
        current_page_files = filtered_files[start_idx:end_idx] if total_files > 0 else []
        app.logger.info(f"Pagination: Page {page}/{total_pages}{'+' if total_files_estimate else ''}. Displaying {len(current_page_files)} items ({start_idx}-{end_idx-1}) from {total_files}{'+' if total_files_estimate else ''} total filtered.")

        # --- Fetch Metadata for Display (if not already fetched by uploader filter) ---
        if not uploader_filter:
            keys_to_fetch_metadata = [f['key'] for f in current_page_files if not f.get('metadata')] # Check if metadata is empty dict
            if keys_to_fetch_metadata:
                app.logger.info(f"Fetching display metadata for {len(keys_to_fetch_metadata)} items on page {page}")
                fetched_metadata = {}
                def fetch_meta(key):
                    try:
                        # Use the same thread-local client instance
                        head = s3.head_object(Bucket=bucket_info['bucket'], Key=key)
                        return key, head.get('Metadata', {})
                    except ClientError as e:
                         if e.response['Error']['Code'] == '404':
                             app.logger.warning(f"Metadata fetch: Object not found {key}")
                         else:
                             app.logger.warning(f"Error fetching metadata for {key}: {e}")
                         return key, {}
                    except Exception as e:
                         app.logger.warning(f"Unexpected error fetching metadata for {key}: {e}")
                         return key, {}

                max_workers = min(10, os.cpu_count() + 4)
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                    future_to_key = {executor.submit(fetch_meta, key): key for key in keys_to_fetch_metadata}
                    for future in concurrent.futures.as_completed(future_to_key):
                        key = future_to_key[future]
                        try:
                            _, meta = future.result()
                            fetched_metadata[key] = meta
                        except Exception as exc:
                             app.logger.error(f'{key} generated an exception during metadata fetch processing: {exc}')
                             fetched_metadata[key] = {}

                # Update file objects on the current page
                for f in current_page_files:
                    if f['key'] in fetched_metadata:
                        f['metadata'] = fetched_metadata[f['key']]

        # --- Render ---
        return render_template('browse_bucket.html',
                             bucket=bucket_info,
                             bucket_name=bucket_name,
                             files=current_page_files,
                             current_page=page,
                             total_pages=total_pages,
                             total_files=total_files,
                             total_files_estimate=total_files_estimate, # Pass estimate flag
                             per_page=per_page, # Pass per_page for template logic
                             search_query=request.args.get('search', ''), # Pass original search query
                             uploader_filter=uploader_filter_display, # Pass original case uploader filter
                             sort_order=sort_order,
                             date_from=date_from,
                             date_to=date_to)

    except Exception as e:
        app.logger.error(f"Error browsing bucket '{bucket_name}': {str(e)}", exc_info=True) # Log traceback
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
        'temp': S3_TEMP_BUCKET,
        'issue': S3_ISSUE_BUCKET
    }
    
    if bucket_name not in buckets:
        flash('Invalid bucket selected', 'danger')
        return redirect(url_for('browse_buckets'))
        
    try:
        # Extract just the filename for the message
        filename = object_key.split('/')[-1]
        
        s3_client.delete_object(
            Bucket=buckets[bucket_name],
            Key=object_key
        )
        
        # Log the full path but only flash the filename in the message
        app.logger.info(f"Deleted {object_key} from {buckets[bucket_name]}")
        flash(f'File "{filename}" deleted successfully', 'success')
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
        'temp': {'name': 'Temp Bucket', 'bucket': S3_TEMP_BUCKET, 'prefix': 'tmp_upload/'},
        'issue': {'name': 'Issue Images', 'bucket': S3_ISSUE_BUCKET, 'prefix': 'issue_files/'}
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
            # Log details to the application log
            app.logger.info(f"Successfully deleted {deleted_count} files from {bucket_info['bucket']}")
            # Use a simplified message for the flash notification
            flash(f'Successfully deleted {deleted_count} files from {bucket_info["name"]}', 'success')
        else:
            app.logger.warning(f"Deleted {deleted_count} files, but encountered {error_count} errors in {bucket_info['bucket']}")
            flash(f'Deleted {deleted_count} files, but encountered {error_count} errors', 'warning')
            
    except Exception as e:
        app.logger.error(f"Error listing bucket contents: {e}")
        flash(f'Error accessing bucket: {str(e)}', 'danger')
    
    return redirect(url_for('browse_bucket', bucket_name=bucket_name))

@app.route('/delete-selected/<bucket_name>', methods=['POST'])
@login_required
def delete_selected_route(bucket_name):
    buckets = {
        'good': S3_GOOD_BUCKET,
        'bad': S3_BAD_BUCKET,
        'incredible': S3_INCREDIBLE_BUCKET,
        'upload': S3_UPLOAD_BUCKET,
        'temp': S3_TEMP_BUCKET,
        'issue': S3_ISSUE_BUCKET
    }
    
    if bucket_name not in buckets:
        flash('Invalid bucket selected', 'danger')
        return redirect(url_for('browse_buckets'))
    
    # Get the selected files from the form
    selected_files = request.form.getlist('selected_files')
    
    if not selected_files:
        flash('No files were selected for deletion', 'warning')
        return redirect(url_for('browse_bucket', bucket_name=bucket_name))
    
    deleted_count = 0
    error_count = 0
    
    try:
        # Delete files in batches of 1000 (S3 limit)
        batch_size = 1000
        for i in range(0, len(selected_files), batch_size):
            batch = selected_files[i:i+batch_size]
            try:
                response = s3_client.delete_objects(
                    Bucket=buckets[bucket_name],
                    Delete={'Objects': [{'Key': key} for key in batch]}
                )
                
                # Count successful deletions
                if 'Deleted' in response:
                    deleted_count += len(response['Deleted'])
                
                # Count errors
                if 'Errors' in response:
                    error_count += len(response['Errors'])
                    for error in response['Errors']:
                        app.logger.error(f"Error deleting {error.get('Key')}: {error.get('Message')}")
                    
            except Exception as e:
                app.logger.error(f"Error deleting batch of objects: {e}")
                error_count += len(batch)
        
        # Log the results
        if error_count == 0:
            flash(f'Successfully deleted {deleted_count} selected files', 'success')
        else:
            flash(f'Deleted {deleted_count} files, but encountered {error_count} errors', 'warning')
    
    except Exception as e:
        app.logger.error(f"Error in batch deletion: {e}")
        flash(f'Error deleting files: {str(e)}', 'danger')
    
    return redirect(url_for('browse_bucket', bucket_name=bucket_name))

@app.route('/image-preview/<bucket_name>/<path:object_key>')
@login_required
def get_image_preview(bucket_name, object_key):
    # Get query params
    is_thumbnail = request.args.get('thumbnail', 'false').lower() == 'true'
    
    buckets = {
        'good': S3_GOOD_BUCKET,
        'bad': S3_BAD_BUCKET,
        'incredible': S3_INCREDIBLE_BUCKET,
        'upload': S3_UPLOAD_BUCKET,
        'temp': S3_TEMP_BUCKET,
        'issue': S3_ISSUE_BUCKET
    }
    
    if bucket_name not in buckets:
        app.logger.error(f"Invalid bucket requested: {bucket_name}")
        return "Invalid bucket", 400
    
    try:
        # Generate a presigned URL with a short expiration
        presigned_url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': buckets[bucket_name],
                'Key': object_key
            },
            ExpiresIn=300  # 5 minutes
        )
        
        # If it's a thumbnail request, redirect to the presigned URL
        if is_thumbnail:
            return redirect(presigned_url)
        
        # For full image view, display in a simple HTML page
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Image Preview</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {{ margin: 0; padding: 20px; text-align: center; background-color: #333; }}
                .image-container {{ max-width: 100%; height: 90vh; display: flex; justify-content: center; align-items: center; }}
                img {{ max-width: 100%; max-height: 100%; object-fit: contain; }}
                .filename {{ color: white; margin-bottom: 20px; font-family: Arial, sans-serif; }}
            </style>
        </head>
        <body>
            <div class="filename">{object_key}</div>
            <div class="image-container">
                <img src="{presigned_url}" alt="Full size image">
            </div>
        </body>
        </html>
        """
        
    except Exception as e:
        app.logger.error(f"Error generating image preview: {e}")
        return f"Error loading image: {str(e)}", 500

if __name__ == '__main__':
    if not os.path.exists('templates'):
        os.makedirs('templates')
    # For local development
    app.run(debug=True)
    
# Set higher timeout for Gunicorn when running on Heroku
# Usage: gunicorn --timeout 300 app:app