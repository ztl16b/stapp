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
import json
import base64
import logging
import threading
import re
import csv

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

# Load suggestions from CSV file
suggestions_dict = {}
try:
    suggestions_file = os.path.join(os.path.dirname(__file__), 'suggestions.csv')
    with open(suggestions_file, 'r') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            key = row.get('text', '').strip()
            value = row.get('Suggestion', '').strip()
            if key and value:
                if key not in suggestions_dict:
                    suggestions_dict[key] = []
                suggestions_dict[key].append(value)
    app.logger.info(f"Loaded {len(suggestions_dict)} suggestion keys from {suggestions_file}")
except Exception as e:
    app.logger.error(f"Error loading suggestions: {e}")
    suggestions_dict = {}

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
            extra_args['Metadata'] = {'uploader-initials': uploader_initials}
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
    
    # First check the temp bucket for any images
    image_key = get_random_image_key(S3_TEMP_BUCKET)
    source_bucket = S3_TEMP_BUCKET
    
    # If no images in temp bucket, check the upload bucket
    if not image_key:
        image_key = get_random_image_key(S3_UPLOAD_BUCKET)
        source_bucket = S3_UPLOAD_BUCKET
    
    image_url = None
    uploader_initials = "Unknown"
    
    if image_key:
        image_url = get_presigned_url(source_bucket, image_key)
        app.logger.info(f"Loading image for review: {image_key} from {source_bucket}")
        
        # Get metadata for the image to extract uploader initials
        try:
            head_response = s3_client.head_object(
                Bucket=source_bucket,
                Key=image_key
            )
            metadata = head_response.get('Metadata', {})
            uploader_initials = metadata.get('uploader-initials', 'Unknown')
            app.logger.info(f"Found uploader initials: {uploader_initials}")
        except Exception as e:
            app.logger.error(f"Error getting metadata for {image_key}: {e}")

    return render_template('review.html', 
                          image_url=image_url, 
                          image_key=image_key, 
                          source_bucket=source_bucket,
                          uploader_initials=uploader_initials)

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
        # Verify that the bucket and prefix exist
        if not bucket_info['bucket']:
            raise ValueError(f"Bucket name for '{bucket_name}' is not configured")
            
        # Get page number, search query, sort order, and date filter from query parameters
        page = request.args.get('page', 1, type=int)
        search_query = request.args.get('search', '').lower()
        uploader_filter = request.args.get('uploader', '')  # Uploader initials filter
        sort_order = request.args.get('sort', 'desc')  # Default to descending order
        date_from = request.args.get('date_from', '')  # Date filter from
        date_to = request.args.get('date_to', '')
        per_page = 200
        
        # Make sure the prefix is a string
        prefix = str(bucket_info['prefix']) if bucket_info['prefix'] else ''
        
        # Get continuation token from session (for pagination)
        session_key = f"s3_pagination_{bucket_name}"
        pagination_data = session.get(session_key, {})
        
        # If first page or a specific search/filter is applied, reset pagination
        if page == 1 or request.args.get('reset_pagination'):
            pagination_data = {}
        
        # Use S3's native pagination via continuation tokens
        next_token = pagination_data.get(f'page_{page}', None)
        current_page_files = []
        has_more = False
        
        # For the Good bucket, use a more efficient approach - only fetch current page
        if bucket_name == 'good':
            # Prepare the list_objects_v2 params
            list_params = {
                'Bucket': bucket_info['bucket'],
                'Prefix': prefix,
                'MaxKeys': per_page,
            }
            
            # Add continuation token if we have one for this page
            if next_token:
                list_params['ContinuationToken'] = next_token
                
            # For pagination, we need to get one page ahead
            try:
                response = s3_client.list_objects_v2(**list_params)
                
                # Store token for next page
                if response.get('IsTruncated'):
                    has_more = True
                    pagination_data[f'page_{page+1}'] = response.get('NextContinuationToken')
                    session[session_key] = pagination_data
                
                # Process files in the current page
                if 'Contents' in response:
                    items = response['Contents']
                    app.logger.info(f"Got {len(items)} files from S3 for page {page}")
                    
                    for item in items:
                        # Skip the prefix itself
                        if item['Key'] != prefix:
                            file_obj = {
                                'key': item['Key'],
                                'size': item['Size'],
                                'last_modified': item['LastModified'],
                                'metadata': {}  # Initialize empty metadata
                            }
                            current_page_files.append(file_obj)
                            
                # Apply any client-side filtering after getting the current page
                if search_query or uploader_filter or date_from or date_to:
                    filtered_files = []
                    
                    # Get metadata for each file for filtering
                    for file in current_page_files:
                        # Only get metadata if we need it for filtering
                        if uploader_filter:
                            try:
                                head_response = s3_client.head_object(
                                    Bucket=bucket_info['bucket'],
                                    Key=file['key']
                                )
                                file['metadata'] = head_response.get('Metadata', {})
                            except Exception as e:
                                app.logger.error(f"Error getting metadata for {file['key']}: {e}")
                                file['metadata'] = {}
                        
                        # Apply text search filter
                        if search_query and search_query != 'letters':
                            if search_query not in file['key'].lower():
                                continue
                                
                        # Apply "letters" filter
                        if search_query == 'letters':
                            filename = file['key'].split('/')[-1]
                            base_filename = filename
                            if '.' in filename:
                                base_filename = filename.rsplit('.', 1)[0]
                            
                            if not any(c.isalpha() for c in base_filename):
                                continue
                                
                        # Apply uploader filter
                        if uploader_filter:
                            file_uploader = file.get('metadata', {}).get('uploader-initials', '').lower()
                            if uploader_filter.lower() not in file_uploader:
                                continue
                                
                        # Apply date filter
                        if not apply_date_filter(file['last_modified'], date_from, date_to):
                            continue
                            
                        filtered_files.append(file)
                    
                    current_page_files = filtered_files
                    
                # Sort files (if needed)
                current_page_files.sort(key=lambda x: x['last_modified'], reverse=(sort_order == 'desc'))
                
                # For filtered results, pagination gets more complex
                # We'll estimate based on what we know
                total_files = len(current_page_files)
                total_pages = 1
                
                if has_more or page > 1:
                    # If we have more pages or we're not on page 1,
                    # provide minimal pagination info
                    total_pages = page + (1 if has_more else 0)
                    total_files = (page-1) * per_page + len(current_page_files)
                    
                # Always ensure the user can navigate
                if page > 1:
                    pagination_data[f'page_{page-1}'] = pagination_data.get(f'page_{page-1}', None)
                
                # Get metadata for display purposes
                for file in current_page_files:
                    if not uploader_filter:  # Only if we haven't already fetched metadata
                        try:
                            head_response = s3_client.head_object(
                                Bucket=bucket_info['bucket'],
                                Key=file['key']
                            )
                            file['metadata'] = head_response.get('Metadata', {})
                        except Exception as e:
                            app.logger.error(f"Error getting metadata for {file['key']}: {e}")
                            file['metadata'] = {}
                
            except Exception as e:
                app.logger.error(f"Error listing bucket contents: {e}")
                flash(f"Error accessing bucket: {str(e)}", "danger")
                return redirect(url_for('browse_buckets'))
        else:
            # For other buckets, use the original implementation
            all_files = []
            
            # Use the paginator for efficiency
            paginator = s3_client.get_paginator('list_objects_v2')
            
            for page_obj in paginator.paginate(
                Bucket=bucket_info['bucket'],
                Prefix=prefix,
                MaxKeys=per_page  # Limit the number of keys returned per request
            ):
                if 'Contents' in page_obj:
                    for item in page_obj['Contents']:
                        # Skip the prefix itself
                        if item['Key'] != prefix:
                            # Apply search filter if search query exists
                            if search_query == 'letters':
                                # Get just the filename part (after the last slash)
                                filename = item['Key'].split('/')[-1]
                                # Remove extension for comparison
                                base_filename = filename
                                if '.' in filename:
                                    base_filename = filename.rsplit('.', 1)[0]
                                    
                                if any(c.isalpha() for c in base_filename):
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
            
            # Get metadata for each file (including uploader name)
            for file in all_files:
                try:
                    # Get object metadata using head_object call
                    head_response = s3_client.head_object(
                        Bucket=bucket_info['bucket'],
                        Key=file['key']
                    )
                    # Add metadata to file object
                    file['metadata'] = head_response.get('Metadata', {})
                    app.logger.debug(f"Metadata for {file['key']}: {file['metadata']}")
                except Exception as e:
                    app.logger.error(f"Error getting metadata for {file['key']}: {e}")
                    file['metadata'] = {}
            
            # Apply uploader filter if provided
            if uploader_filter:
                filtered_files = []
                for file in all_files:
                    file_uploader = file.get('metadata', {}).get('uploader-initials', '').lower()
                    if uploader_filter.lower() in file_uploader:
                        filtered_files.append(file)
                all_files = filtered_files
                
            # Sort files by last_modified date
            all_files.sort(key=lambda x: x['last_modified'], reverse=(sort_order == 'desc'))
            
            # Calculate pagination info
            total_files = len(all_files)
            total_pages = (total_files + per_page - 1) // per_page if total_files > 0 else 1
            
            # Ensure page is within valid range
            if page < 1:
                page = 1
            elif page > total_pages and total_pages > 0:
                page = total_pages
            
            # Slice the files list to get only the current page
            start_idx = (page - 1) * per_page
            end_idx = min(start_idx + per_page, total_files)
            current_page_files = all_files[start_idx:end_idx] if total_files > 0 else []
            
        # Common response for all buckets
        return render_template('browse_bucket.html', 
                             bucket=bucket_info,
                             bucket_name=bucket_name,
                             files=current_page_files,
                             current_page=page,
                             total_pages=total_pages,
                             total_files=total_files,
                             search_query=search_query,
                             uploader_filter=uploader_filter,
                             sort_order=sort_order,
                             date_from=date_from,
                             date_to=date_to,
                             is_lazy_loading=(bucket_name == 'good'))
                             
    except Exception as e:
        app.logger.error(f"Error browsing bucket '{bucket_name}': {str(e)}")
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

@app.route('/suggestions', methods=['GET'])
def get_suggestions():
    """Return suggestions for the uploader initials field based on input text"""
    query = request.args.get('q', '').strip().upper()
    
    if not query:
        return jsonify([])
    
    # Get current date for formatting suggestions
    now = datetime.now()
    month = now.strftime('%m')
    day = now.strftime('%d')
    
    # Check if we have a direct match for the first letter
    matched_suggestions = []
    if query and query[0] in suggestions_dict:
        # Get suggestions for this letter
        for suggestion_template in suggestions_dict[query[0]]:
            # Replace MM_DD with the current month and day
            formatted_suggestion = suggestion_template.replace('MM', month).replace('DD', day)
            matched_suggestions.append(formatted_suggestion)
    
    return jsonify(matched_suggestions)

if __name__ == '__main__':
    if not os.path.exists('templates'):
        os.makedirs('templates')
    # For local development
    app.run(debug=True)
    
# Set higher timeout for Gunicorn when running on Heroku
# Usage: gunicorn --timeout 300 app:app