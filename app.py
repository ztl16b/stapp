import random
import os
import boto3 #type:ignore   
import requests #type:ignore
from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify #type:ignore
from dotenv import load_dotenv #type:ignore
from botocore.exceptions import NoCredentialsError, ClientError #type:ignore
from functools import wraps
from datetime import datetime, timedelta, timezone
from werkzeug.utils import secure_filename #type:ignore
from requests.exceptions import RequestException #type:ignore
import uuid
import time
from io import BytesIO
from openai import OpenAI #type:ignore
import json
import base64
import logging
import threading
import re
import hashlib
import mimetypes
import psutil #type:ignore
import concurrent.futures
from zoneinfo import ZoneInfo
import csv

load_dotenv()

template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
app = Flask(__name__, template_folder=template_dir)

app.secret_key = os.environ.get('SECRET_KEY')

MST = ZoneInfo("Etc/GMT+7")

# Custom Jinja filter for MST datetime formatting
def format_datetime_mst(dt_utc):
    if not isinstance(dt_utc, datetime):
        try:
            dt_utc = datetime.fromisoformat(dt_utc)
        except (ValueError, TypeError):
            return dt_utc # Return as is if conversion fails
    
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
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
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
S3_PERFORMER_BUCKET = os.getenv("S3_PERFORMER_BUCKET")
S3_RESOURCES_BUCKET = "etickets-content-test-bucket"
S3_REF_BUCKET = os.getenv("S3_REF_BUCKET") # New reference bucket
S3_REF_BUCKET_PREFIX = os.getenv("S3_REF_BUCKET_PREFIX") # New reference bucket prefix

S3_UPLOAD_BUCKET_PREFIX = os.getenv("S3_UPLOAD_BUCKET_PREFIX")
S3_GOOD_BUCKET_PREFIX = os.getenv("S3_GOOD_BUCKET_PREFIX")
S3_BAD_BUCKET_PREFIX = os.getenv("S3_BAD_BUCKET_PREFIX")
S3_INCREDIBLE_BUCKET_PREFIX = os.getenv("S3_INCREDIBLE_BUCKET_PREFIX")
S3_TEMP_BUCKET_PREFIX = os.getenv("S3_TEMP_BUCKET_PREFIX")
S3_ISSUE_BUCKET_PREFIX = os.getenv("S3_ISSUE_BUCKET_PREFIX")
S3_PERFORMER_BUCKET_PREFIX = os.getenv("S3_PERFORMER_BUCKET_PREFIX")

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

thread_local = threading.local()

performer_data = {}

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

def load_performer_data():
    global performer_data
    s3 = get_s3_client()
    
    try:
        csv_obj = s3.get_object(Bucket=S3_RESOURCES_BUCKET, Key="temp/performer-infos.csv")
        csv_content = csv_obj['Body'].read().decode('utf-8')
        
        csv_reader = csv.DictReader(csv_content.splitlines())
        
        performer_data = {row['performer_id']: row['name_alias'] for row in csv_reader if 'performer_id' in row and 'name_alias' in row}
        
        app.logger.info(f"Loaded {len(performer_data)} performers from CSV")
    except Exception as e:
        app.logger.error(f"Error loading performer data: {e}")
        performer_data = {}
        
    return performer_data

try:
    s3_client = get_s3_client()
    
    s3_upload_config = boto3.s3.transfer.TransferConfig(
        multipart_threshold=8 * 1024 * 1024,
        max_concurrency=10,
        multipart_chunksize=8 * 1024 * 1024,
        use_threads=True
    )
    
    load_performer_data()

except NoCredentialsError:
    raise ValueError("AWS credentials not found. Ensure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set.")
except Exception as e:
    raise ValueError(f"Error initializing S3 client: {e}")

def extract_performer_id(filename):
    try:
        # First, check if an underscore is present
        if '_' in filename:
            # Take the part before the first underscore
            performer_id_str = filename.split('_', 1)[0]
        else:
            # Fallback to splitting by dot if no underscore
            parts = filename.split('.')
            # First part is performer_id
            if len(parts) >= 1:
                performer_id_str = parts[0]
            else:
                return None # Should not happen if filename is valid

        # Validate if the extracted part is numeric
        if performer_id_str.isdigit():
            return performer_id_str
        else:
            app.logger.warning(f"Extracted performer_id '{performer_id_str}' from '{filename}' is not numeric.")
            return None
    except Exception as e:
        app.logger.error(f"Error extracting performer_id from {filename}: {e}")
    return None

# Helper function to get performer name from performer_id
def get_performer_name(performer_id):
    """Get performer name (name_alias) from performer_id"""
    global performer_data
    
    # If performer data is empty, try loading it again
    if not performer_data:
        load_performer_data()
    
    return performer_data.get(performer_id, "Unknown Performer")

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
        admin_password = os.getenv('ADMIN_PASSWORD')
        
        if password == admin_password:
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

def process_image(file_data, filename, content_type, uploader_initials=None):
    """
    Upload an image directly to the S3 temp bucket in its original format.
    
    Args:
        file_data: The file data as bytes
        filename: The original filename (with perf_id-ven_id format)
        content_type: The content type of the file
        uploader_initials: Initials of the person uploading the file
        
    Returns:
        dict: Status information about the processing
    """
    try:
        # Quick validation of file format using first few bytes
        file_start = file_data[:8]  # First 8 bytes is enough for all formats
        
        # Valid image signatures for different formats
        valid_signatures = {
            b'\xff\xd8\xff': 'JPEG',    # JPEG
            b'\x89\x50\x4e\x47': 'PNG', # PNG
            b'\x47\x49\x46': 'GIF',     # GIF
            b'\x42\x4d': 'BMP',         # BMP
            b'\x52\x49\x46\x46': 'WEBP' # WEBP
        }
        
        is_valid_image = any(file_start.startswith(sig) for sig in valid_signatures)
                
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
        metadata = {
            'review_status': 'FALSE',
            'perfimg_status': 'FALSE',
            'uploader-initials': uploader_initials if uploader_initials else 'Unknown'
        }
        
        # Set upload timestamp 
        upload_time = datetime.utcnow().isoformat()
        metadata['upload_time'] = upload_time
        
        extra_args['Metadata'] = metadata
        extra_args['ACL'] = "public-read"
        extra_args['ContentDisposition'] = "inline"
        app.logger.info(f"Adding metadata and ACL: {metadata}, ACL: public-read, ContentDisposition: inline")
        
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
            'uploader_initials': uploader_initials,
            'metadata': metadata
        }
    except Exception as e:
        app.logger.error(f"Error processing {filename}: {str(e)}")
        return {
            'status': 'error',
            'message': str(e),
            'filename': filename
        }

def get_random_image_key(bucket_name, filter_by_review=None):
    """Gets a random object key from the specified bucket, optionally filtered by review status."""
    try:
        # Different prefix depending on which bucket we're using
        prefix = None
        if bucket_name == S3_UPLOAD_BUCKET:
            prefix = 'temp_performer_at_venue_images/'
        elif bucket_name == S3_TEMP_BUCKET:
            prefix = 'tmp_upload/'
        elif bucket_name == S3_GOOD_BUCKET:
            prefix = 'images/performer-at-venue/detail/'
            
        # Get list of objects with the appropriate prefix
        response = s3_client.list_objects_v2(
            Bucket=bucket_name,
            Prefix=prefix if prefix else ''
        )
            
        if 'Contents' in response and response['Contents']:
            all_objects = response['Contents']
            
            # Filter by file type and structure based on bucket
            image_objects = []
            
            # For Good bucket, filter by review status if requested
            if bucket_name == S3_GOOD_BUCKET and filter_by_review:
                for obj in all_objects:
                    # Get metadata to check review status
                    try:
                        head_response = s3_client.head_object(
                            Bucket=bucket_name,
                            Key=obj['Key']
                        )
                        metadata = head_response.get('Metadata', {})
                        review_status = metadata.get('review_status', 'FALSE')
                        
                        # If filtering for unreviewed images, only include those with FALSE status
                        if filter_by_review == 'unreviewed' and review_status != 'TRUE':
                            image_objects.append(obj)
                        # If filtering for reviewed images, only include those with TRUE status
                        elif filter_by_review == 'reviewed' and review_status == 'TRUE':
                            image_objects.append(obj)
                    except Exception as e:
                        app.logger.error(f"Error checking metadata for {obj['Key']}: {e}")
                        continue
            # For temp bucket, accept all image file types
            elif bucket_name == S3_TEMP_BUCKET:
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

def _prepare_s3_operation(source_bucket, dest_bucket, object_key, destination=None, bad_reason=None):
    """Common preparation for S3 operations like copy and move."""
    # dest_key = object_key # Default dest_key to original_key before path manipulation # Removed this line as dest_key is now constructed more deliberately
    original_key = object_key
    
    # Extract the filename from the path, handling both old and new formats
    filename = object_key.split('/')[-1]
    
    # Remove any timestamp prefixes for the destination
    if '_' in filename:
        # Handle new timestamp_uuid_filename.ext format
        parts = filename.split('_', 2)
        if len(parts) >= 3:
            filename = parts[2]  # Get just the original filename part
    
    # Determine destination path based on dest_bucket
    # Default dest_key is just the filename. This might be used if a bucket doesn't have a defined prefix
    # or isn't one of the explicitly handled cases below.
    dest_key = filename

    if dest_bucket == S3_PERFORMER_BUCKET and S3_PERFORMER_BUCKET_PREFIX:
        dest_key = f"{S3_PERFORMER_BUCKET_PREFIX}{filename}"
    elif dest_bucket == S3_INCREDIBLE_BUCKET and S3_INCREDIBLE_BUCKET_PREFIX:
        dest_key = f"{S3_INCREDIBLE_BUCKET_PREFIX}{filename}"
    elif dest_bucket == S3_GOOD_BUCKET and S3_GOOD_BUCKET_PREFIX:
        dest_key = f"{S3_GOOD_BUCKET_PREFIX}{filename}"
    elif dest_bucket == S3_BAD_BUCKET and S3_BAD_BUCKET_PREFIX:
        dest_key = f"{S3_BAD_BUCKET_PREFIX}{filename}"
    elif dest_bucket == S3_ISSUE_BUCKET and S3_ISSUE_BUCKET_PREFIX: # Added for completeness based on available prefixes
        dest_key = f"{S3_ISSUE_BUCKET_PREFIX}{filename}"
    # If no specific bucket matches, dest_key remains `filename` (root of dest_bucket)
    
    # Determine content type based on file extension
    content_type = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
        
    # Get metadata from source object if it exists
    try:
        head_response = s3_client.head_object(Bucket=source_bucket, Key=original_key)
        metadata = head_response.get('Metadata', {})
    except ClientError as e:
        app.logger.error(f"Error getting metadata for {original_key}: {e}")
        # Initialize with default values
        metadata = {} # Start with empty, defaults will be applied below
        
    # Ensure uploader-initials is preserved or defaulted
    if 'uploader-initials' not in metadata:
        metadata['uploader-initials'] = 'Unknown'
        
    # Initialize review_status and perfimg_status if not in metadata,
    # these might be overwritten by destination logic below.
    if 'review_status' not in metadata:
        metadata['review_status'] = 'FALSE'
    if 'perfimg_status' not in metadata:
        metadata['perfimg_status'] = 'FALSE'

    # Set review_status and perfimg_status based on destination
    if destination == 'good':
        metadata['review_status'] = 'TRUE'
        metadata['perfimg_status'] = 'TRUE' 
    elif destination == 'bad':
        metadata['review_status'] = 'TRUE' # Mark as reviewed even if bad
        if bad_reason:
            metadata['bad_reason'] = bad_reason
    elif destination == 'incredible':
        metadata['review_status'] = 'TRUE'
        metadata['perfimg_status'] = 'TRUE'
    
    return {
        'copy_source': {'Bucket': source_bucket, 'Key': original_key},
        'dest_key': dest_key,
        'content_type': content_type,
        'metadata': metadata,
        'original_key': original_key,
        'filename': filename
    }

def move_s3_object(source_bucket, dest_bucket, object_key, destination=None, bad_reason=None):
    """Moves an object from source_bucket to dest_bucket."""
    op_data = _prepare_s3_operation(source_bucket, dest_bucket, object_key, destination, bad_reason)
    copy_successful = False
    try:
        s3_client.copy_object(
            CopySource=op_data['copy_source'],
            Bucket=dest_bucket,
            Key=op_data['dest_key'],
            ContentType=op_data['content_type'],
            Metadata=op_data['metadata'],
            MetadataDirective='REPLACE',
            ACL="public-read",
            ContentDisposition="inline"
        )
        app.logger.info(f"Copied {op_data['original_key']} from {source_bucket} to {dest_bucket} as {op_data['dest_key']}")
        copy_successful = True
    except ClientError as e:
        app.logger.error(f"Error copying object {object_key} during move: {e}")
        error_code = e.response.get('Error', {}).get('Code')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        if error_code == 'AccessDenied':
            flash(f"Access Denied: Cannot copy {op_data.get('filename', object_key)}. Check S3 permissions (GetObject for source, PutObject for destination).", "danger")
        else:
            flash(f"Error copying file '{op_data.get('filename', object_key)}' during move: {error_message}", "danger")
        return False # Explicitly return False on copy error
    except Exception as e:
        app.logger.error(f"Unexpected error copying object {object_key} during move: {e}")
        flash(f"An unexpected error occurred while copying '{op_data.get('filename', object_key)}' during move.", "danger")
        return False # Explicitly return False on copy error

    if copy_successful:
        try:
            s3_client.delete_object(Bucket=source_bucket, Key=op_data['original_key'])
            app.logger.info(f"Deleted {op_data['original_key']} from {source_bucket} after successful copy.")
            return True # Move successful
        except ClientError as e:
            app.logger.error(f"Error deleting object {op_data['original_key']} after copy: {e}")
            error_message = e.response.get('Error', {}).get('Message', str(e))
            flash(f"File '{op_data.get('filename', op_data['original_key'])}' copied, but error deleting original: {error_message}", "warning")
            return False # Move partially failed (delete failed)
        except Exception as e:
            app.logger.error(f"Unexpected error deleting object {op_data['original_key']} after copy: {e}")
            flash(f"File '{op_data.get('filename', op_data['original_key'])}' copied, but an unexpected error occurred while deleting the original.", "warning")
            return False # Move partially failed (delete failed)
    else:
        # Copy was not successful, error already flashed by copy exception block.
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

@app.route('/perf_ven_review')
@login_required
def perf_ven_review_image_route():
    # Log session information for debugging
    app.logger.info(f"Perf Ven Review page accessed by user {session.get('user_id', 'unknown')}")
    
    # Check the Good bucket for unreviewed images only
    image_key = get_random_image_key(S3_GOOD_BUCKET, filter_by_review='unreviewed')
    source_bucket = S3_GOOD_BUCKET
    
    image_url = None
    uploader_initials = "Unknown"
    review_status = "FALSE"
    perfimg_status = "FALSE"
    performer_name = "Unknown Performer"
    
    if image_key:
        image_url = get_presigned_url(source_bucket, image_key)
        app.logger.info(f"Loading unreviewed image for review: {image_key} from {source_bucket}")
        
        # Get metadata for the image to extract uploader initials and review status
        try:
            head_response = s3_client.head_object(
                Bucket=source_bucket,
                Key=image_key
            )
            metadata = head_response.get('Metadata', {})
            uploader_initials = metadata.get('uploader-initials', 'Unknown')
            review_status = metadata.get('review_status', 'FALSE')
            perfimg_status = metadata.get('perfimg_status', 'FALSE')
            app.logger.info(f"Found metadata - uploader: {uploader_initials}, review status: {review_status}, perfimg status: {perfimg_status}")
            
            # Extract performer_id from filename
            filename = image_key.split('/')[-1]
            performer_id = extract_performer_id(filename)
            
            if performer_id:
                # Look up performer name
                performer_name = get_performer_name(performer_id)
                app.logger.info(f"Found performer name for ID {performer_id}: {performer_name}")
        except Exception as e:
            app.logger.error(f"Error getting metadata for {image_key}: {e}")

    return render_template('perf_ven_review.html', 
                          image_url=image_url, 
                          image_key=image_key, 
                          source_bucket=source_bucket,
                          uploader_initials=uploader_initials,
                          review_status=review_status,
                          perfimg_status=perfimg_status,
                          performer_name=performer_name)

@app.route('/move/<action>/<path:image_key>', methods=['POST'])
@login_required
def move_image_route(action, image_key):
    if not image_key:
        flash("No image key provided for move operation.", "danger")
        return redirect(url_for('perf_ven_review_image_route'))

    # Get the source bucket from the form data
    source_bucket = request.form.get('source_bucket', S3_UPLOAD_BUCKET)
    
    # Get the bad reason if provided (for bad action)
    bad_reason = request.form.get('bad_reason', None)
    
    # Get the custom reason for "Other" option (if provided)
    other_reason = request.form.get('other_reason', None)
    
    # If "Other" is selected and other_reason is provided, use that as bad_reason
    if bad_reason == 'other' and other_reason:
        bad_reason = f"{other_reason}"
    
    # Log the action
    app.logger.info(f"Moving image with key: {image_key} from {source_bucket} to {action} bucket")
    if bad_reason:
        app.logger.info(f"Bad reason selected: {bad_reason}")

    # If we're already in the good bucket, we need to update the metadata to mark as reviewed
    if source_bucket == S3_GOOD_BUCKET:
        try:
            # Get current metadata and content
            head_response = s3_client.head_object(
                Bucket=source_bucket,
                Key=image_key
            )
            current_metadata = head_response.get('Metadata', {})
            content_type = head_response.get('ContentType', 'image/webp')
            
            # Ensure all metadata fields exist with appropriate defaults
            if 'uploader-initials' not in current_metadata:
                current_metadata['uploader-initials'] = 'Unknown'
                
            # Update review status
            current_metadata['review_status'] = 'TRUE'
            
            # Ensure perfimg_status is preserved or set to FALSE if not already in metadata
            if 'perfimg_status' not in current_metadata:
                current_metadata['perfimg_status'] = 'FALSE'
                
            # For BAD action, move the image from Good to Bad bucket
            if action == 'bad':
                # If bad_reason provided, add it to metadata
                if bad_reason:
                    current_metadata['bad_reason'] = bad_reason
                
                # Extract the filename from the path
                filename = image_key.split('/')[-1]
                
                # Create the destination path in the bad bucket
                bad_dest_key = f"bad_images/{filename}"
                
                # Get the object data
                get_response = s3_client.get_object(
                    Bucket=source_bucket,
                    Key=image_key
                )
                file_data = get_response['Body'].read()
                
                # Upload to bad bucket with updated metadata
                s3_client.put_object(
                    Bucket=S3_BAD_BUCKET,
                    Key=bad_dest_key,
                    Body=file_data,
                    ContentType=content_type,
                    Metadata=current_metadata,
                    ACL="public-read",
                    ContentDisposition="inline"
                )
                
                # Delete from good bucket
                s3_client.delete_object(
                    Bucket=source_bucket,
                    Key=image_key
                )
                
                app.logger.info(f"Moved {image_key} from Good bucket to Bad bucket")
                flash(f"Image '{filename}' moved to bad bucket.", "success")
                return redirect(url_for('perf_ven_review_image_route'))
                
            # For INCREDIBLE action, also copy to the incredible bucket
            elif action == 'incredible':
                # Extract the filename from the path
                filename = image_key.split('/')[-1]
                
                # Create the destination path in the incredible bucket
                incredible_dest_key = f"incredible_images/{filename}"
                
                # Copy to incredible bucket - ensure review_status is TRUE
                current_metadata['review_status'] = 'TRUE'
                
                s3_client.copy_object(
                    CopySource={'Bucket': source_bucket, 'Key': image_key},
                    Bucket=S3_INCREDIBLE_BUCKET,
                    Key=incredible_dest_key,
                    Metadata=current_metadata,
                    ContentType=content_type,
                    MetadataDirective='REPLACE',
                    ACL="public-read",
                    ContentDisposition="inline"
                )
                
                # Update metadata in the good bucket
                s3_client.copy_object(
                    CopySource={'Bucket': source_bucket, 'Key': image_key},
                    Bucket=source_bucket,
                    Key=image_key,
                    Metadata=current_metadata,
                    MetadataDirective='REPLACE',
                    ContentType=content_type,
                    ACL="public-read",
                    ContentDisposition="inline"
                )
                
                app.logger.info(f"Updated metadata for {image_key} and copied to incredible bucket")
                flash(f"Image '{image_key.split('/')[-1]}' marked as reviewed and copied to incredible bucket.", "success")
            else:
                # For GOOD action, just update metadata
                s3_client.copy_object(
                    CopySource={'Bucket': source_bucket, 'Key': image_key},
                    Bucket=source_bucket,
                    Key=image_key,
                    Metadata=current_metadata,
                    MetadataDirective='REPLACE',
                    ContentType=content_type,
                    ACL="public-read",
                    ContentDisposition="inline"
                )
                
                app.logger.info(f"Updated metadata for {image_key} to mark as reviewed")
                flash(f"Image '{image_key.split('/')[-1]}' marked as reviewed.", "success")
                
            return redirect(url_for('perf_ven_review_image_route'))
            
        except Exception as e:
            app.logger.error(f"Error updating metadata: {e}")
            flash(f"Error updating review status: {str(e)}", "danger")
            return redirect(url_for('perf_ven_review_image_route'))

    # Original logic for moving between buckets
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
        if move_s3_object(source_bucket, destination_bucket, image_key, destination=action, bad_reason=bad_reason):
            success = True
            # Only log to the app logger, don't use flash messages twice
            app.logger.info(f"Image '{image_key}' moved to {action} bucket.")
            # Use a single flash message
            filename = image_key.split('/')[-1]
            flash(f"Image '{filename}' moved to {action} bucket.", "success")

    if not success:
        flash(f"Failed to move image '{image_key}' to {action} bucket.", "danger")

    return redirect(url_for('perf_ven_review_image_route'))

def copy_s3_object(source_bucket, dest_bucket, object_key, destination=None, bad_reason=None):
    """Copies an object from source_bucket to dest_bucket without deleting the original."""
    app.logger.info(f"[copy_s3_object] Attempting to copy: {object_key} from {source_bucket} to {dest_bucket} (destination hint: {destination})")
    try:
        op_data = _prepare_s3_operation(source_bucket, dest_bucket, object_key, destination, bad_reason)
        app.logger.info(f"[copy_s3_object] Prepared operation data. Effective dest_bucket: {dest_bucket}, dest_key: {op_data['dest_key']}")
        s3_client.copy_object(
            CopySource=op_data['copy_source'],
            Bucket=dest_bucket, # Use the dest_bucket passed to copy_s3_object
            Key=op_data['dest_key'],
            ContentType=op_data['content_type'],
            Metadata=op_data['metadata'],
            MetadataDirective='REPLACE',
            ACL="public-read",
            ContentDisposition="inline"
        )
        app.logger.info(f"[copy_s3_object] Successfully copied {op_data['original_key']} from {source_bucket} to {dest_bucket} as {op_data['dest_key']}")
        return True
    except ClientError as e:
        app.logger.error(f"[copy_s3_object] ClientError copying {object_key} from {source_bucket} to {dest_bucket} (dest_key: {op_data.get('dest_key', 'N/A')}): {e}")
        error_code = e.response.get('Error', {}).get('Code')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        filename_display = op_data.get('filename', object_key) if 'op_data' in locals() else object_key

        if error_code == 'AccessDenied':
            flash(f"Access Denied: Cannot copy {filename_display}. Check S3 permissions (GetObject for source, PutObject for destination).", "danger")
        else:
            flash(f"Error copying file '{filename_display}': {error_message}", "danger")
    except Exception as e:
        app.logger.error(f"Unexpected error copying object {object_key}: {e}")
        filename_display = op_data.get('filename', object_key) if 'op_data' in locals() else object_key
        flash(f"An unexpected error occurred while copying '{filename_display}'.", "danger")
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
    app.logger.info(f"S3_PERFORMER_BUCKET: {S3_PERFORMER_BUCKET}")
    
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
        'issue': {'name': 'Issue Images', 'bucket': S3_ISSUE_BUCKET, 'prefix': 'issue_files/'},
        'performers': {'name': 'Performers Images', 'bucket': S3_PERFORMER_BUCKET, 'prefix': 'images/performers/detail/'},
        'reference': {'name': 'Reference Images', 'bucket': S3_REF_BUCKET, 'prefix': S3_REF_BUCKET_PREFIX} # New reference bucket
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
        'issue': {'name': 'Issue Images', 'bucket': S3_ISSUE_BUCKET, 'prefix': 'issue_files/'},
        'performers': {'name': 'Performers Images', 'bucket': S3_PERFORMER_BUCKET, 'prefix': 'images/performers/detail/'},
        'reference': {'name': 'Reference Images', 'bucket': S3_REF_BUCKET, 'prefix': S3_REF_BUCKET_PREFIX} # New reference bucket
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
        # max_items_to_scan = 300 # Limit initial scan  -- This will be replaced
        num_recent_items_target = 50  # Target number of most recent items to process
        s3_candidate_scan_limit = 10000  # How many items to fetch fro3 to find the recent ones

        prefix = str(bucket_info['prefix']) if bucket_info['prefix'] else ''
        
        # --- Fetch and Filter Data ---
        s3 = get_s3_client() # Use thread-local client
        s3_paginator = s3.get_paginator('list_objects_v2')
        
        s3_results_candidates = [] # Temp list for S3 scan results before sorting
        items_retrieved_from_s3 = 0
        s3_scan_was_truncated = False # True if S3 scan was cut short or S3 reported more data

        app.logger.info(f"Scanning S3 for up to {s3_candidate_scan_limit} items to find the {num_recent_items_target} most recent for bucket '{bucket_name}', prefix '{prefix}'.")
        
        # Special handling for '10.webp' in 'performers' bucket: add to candidates for sorting
        if bucket_name == 'performers':
            try:
                app.logger.info(f"Special check for '10.webp' in the bucket {bucket_info['bucket']}")
                # Ensure LastModified is a datetime object for consistent sorting
                direct_check = s3.head_object(Bucket=bucket_info['bucket'], Key="10.webp")
                last_modified_dt = direct_check.get('LastModified', datetime.now(timezone.utc))
                if not isinstance(last_modified_dt, datetime):
                     last_modified_dt = datetime.now(timezone.utc) # Fallback

                s3_results_candidates.append({
                    'key': "10.webp",
                    'size': direct_check.get('ContentLength', 0),
                    'last_modified': last_modified_dt,
                    'metadata': {} # Metadata will be fetched/merged later
                })
                app.logger.info(f"Added 10.webp to candidates with LastModified: {last_modified_dt}")
            except Exception as e:
                app.logger.error(f"Error checking or adding 10.webp directly: {str(e)}")

        # Main S3 scanning loop
        scan_prefix_for_paginate = prefix 
        if bucket_name == 'performers':
            # For performers, scan_prefix_for_paginate is empty to find all, then filter by actual prefix.
             scan_prefix_for_paginate = ''
             app.logger.info(f"Using empty scan_prefix_for_paginate for performers bucket to find all files for recency sort.")


        for page_obj in s3_paginator.paginate(Bucket=bucket_info['bucket'], Prefix=scan_prefix_for_paginate):
            current_page_s3_truncated = page_obj.get('IsTruncated', False)
            if 'Contents' in page_obj:
                app.logger.info(f"DEBUG: S3 page returned {len(page_obj['Contents'])} items with scan_prefix_for_paginate '{scan_prefix_for_paginate}'")
                for item in page_obj['Contents']:
                    if item['Key'] == scan_prefix_for_paginate and scan_prefix_for_paginate: # Skip the prefix folder itself
                        continue
                    if item['Key'] == "10.webp" and bucket_name == 'performers': # Avoid double-adding if 10.webp was in Contents
                        # Check if already added from head_object
                        if not any(c['key'] == "10.webp" for c in s3_results_candidates):
                             # Not added via head_object, so add it now from list_objects
                             s3_results_candidates.append({
                                'key': item['Key'],
                                'size': item['Size'],
                                'last_modified': item['LastModified'],
                                'metadata': {}
                            })
                             items_retrieved_from_s3 +=1 # Count it here
                        continue


                    # Performers bucket: specific path filtering
                    if bucket_name == 'performers':
                        # Check if the item's key starts with the actual desired prefix string
                        actual_performer_prefix = 'images/performers/detail/' # As defined in buckets dict
                        if not item['Key'].startswith(actual_performer_prefix):
                            continue 
                        # Also check for image extension
                        file_ext = item['Key'].lower().split('.')[-1] if '.' in item['Key'] else ''
                        if file_ext not in ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp']:
                            continue
                        app.logger.info(f"Queueing file for recency check in performers bucket: {item['Key']}")
                        
                    s3_results_candidates.append({
                        'key': item['Key'],
                        'size': item['Size'],
                        'last_modified': item['LastModified'],
                        'metadata': {} 
                    })
                    items_retrieved_from_s3 += 1

                    if items_retrieved_from_s3 >= s3_candidate_scan_limit:
                        s3_scan_was_truncated = current_page_s3_truncated or True 
                        break 
            
            if not s3_scan_was_truncated: 
                s3_scan_was_truncated = current_page_s3_truncated
            
            if items_retrieved_from_s3 >= s3_candidate_scan_limit:
                 app.logger.info(f"Reached s3_candidate_scan_limit ({s3_candidate_scan_limit}).")
                 break

        app.logger.info(f"Retrieved {items_retrieved_from_s3} candidate items from S3. S3 scan reported truncation: {s3_scan_was_truncated}")

        # Sort all candidates by recency (most recent first)
        s3_results_candidates.sort(key=lambda x: x['last_modified'], reverse=True)
        
        # Select the top 'num_recent_items_target'
        all_scanned_files = s3_results_candidates[:num_recent_items_target]
        
        items_scanned = len(all_scanned_files) 
        is_truncated = s3_scan_was_truncated # If the S3 scan itself was truncated, then our total estimate should reflect that

        app.logger.info(f"Selected {items_scanned} most recent items for processing (target: {num_recent_items_target}). Overall list might be truncated: {is_truncated}")
        
        unreviewed_count = 0  # Initialize counter for unreviewed images

        # --- Apply Filters (Client-side on the 'all_scanned_files' which are the N most recent) ---
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
        
        # --- Add Performer Names for each file ---
        # Ensure performer data is loaded
        if not performer_data:
            load_performer_data()
        
        # Add performer name to each file based on filename
        for f in current_page_files:
            filename = f['key'].split('/')[-1]
            performer_id = extract_performer_id(filename)
            if performer_id:
                performer_name = get_performer_name(performer_id)
                f['performer_name'] = performer_name
            else:
                f['performer_name'] = "Unknown Performer"
        
        # Count unreviewed images for all filtered files
        # We need to fetch metadata for all files to get accurate count
        keys_for_unreviewed_count = [f['key'] for f in filtered_files if not f.get('metadata')]
        if keys_for_unreviewed_count:
            app.logger.info(f"Fetching metadata for unreviewed count for {len(keys_for_unreviewed_count)} items")
            fetched_metadata = {}
            
            # Use batching for large datasets
            batch_size = 100
            for i in range(0, len(keys_for_unreviewed_count), batch_size):
                batch_keys = keys_for_unreviewed_count[i:i+batch_size]
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                    future_to_key = {executor.submit(fetch_meta, key): key for key in batch_keys}
                    for future in concurrent.futures.as_completed(future_to_key):
                        key = future_to_key[future]
                        try:
                            _, meta = future.result()
                            fetched_metadata[key] = meta
                        except Exception as exc:
                            app.logger.error(f'{key} generated an exception during metadata fetch for unreviewed count: {exc}')
                            fetched_metadata[key] = {}
            
            # Update metadata for all filtered files
            for f in filtered_files:
                if f['key'] in fetched_metadata:
                    f['metadata'] = fetched_metadata[f['key']]
        
        # Count unreviewed images across all filtered files
        unreviewed_count = sum(1 for f in filtered_files if f.get('metadata', {}).get('review_status', 'FALSE') != 'TRUE')
        app.logger.info(f"Found {unreviewed_count} unreviewed images out of {total_files} total filtered files")

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
                             date_to=date_to,
                             unreviewed_count=unreviewed_count) # Pass unreviewed count to template

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
        'issue': S3_ISSUE_BUCKET,
        'performers': S3_PERFORMER_BUCKET,
        'reference': S3_REF_BUCKET # New reference bucket
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
        'issue': {'name': 'Issue Images', 'bucket': S3_ISSUE_BUCKET, 'prefix': 'issue_files/'},
        'performers': {'name': 'Performers Images', 'bucket': S3_PERFORMER_BUCKET, 'prefix': 'images/performers/detail/'},
        'reference': {'name': 'Reference Images', 'bucket': S3_REF_BUCKET, 'prefix': S3_REF_BUCKET_PREFIX} # New reference bucket
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
        'issue': S3_ISSUE_BUCKET,
        'performers': S3_PERFORMER_BUCKET,
        'reference': S3_REF_BUCKET # New reference bucket
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

@app.route('/toggle-perfimg-status/<bucket_name>/<path:object_key>', methods=['POST'])
@login_required
def toggle_perfimg_status_route(bucket_name, object_key):
    buckets = {
        'good': S3_GOOD_BUCKET,
        'bad': S3_BAD_BUCKET,
        'incredible': S3_INCREDIBLE_BUCKET,
        'upload': S3_UPLOAD_BUCKET,
        'temp': S3_TEMP_BUCKET,
        'issue': S3_ISSUE_BUCKET,
        'performers': S3_PERFORMER_BUCKET,
        'reference': S3_REF_BUCKET # New reference bucket
    }
    
    if bucket_name not in buckets:
        flash('Invalid bucket selected', 'danger')
        return redirect(url_for('browse_buckets'))
        
    try:
        # Get current object metadata
        head_response = s3_client.head_object(
            Bucket=buckets[bucket_name],
            Key=object_key
        )
        
        # Extract metadata and content type
        current_metadata = head_response.get('Metadata', {})
        content_type = head_response.get('ContentType', 'image/webp')
        
        # Ensure all important metadata fields exist
        if 'uploader-initials' not in current_metadata:
            current_metadata['uploader-initials'] = 'Unknown'
        
        if 'review_status' not in current_metadata:
            # Default review status based on bucket
            if bucket_name == 'incredible':
                current_metadata['review_status'] = 'TRUE'
            else:
                current_metadata['review_status'] = 'FALSE'
        
        # Toggle perfimg_status (TRUE -> FALSE, FALSE -> TRUE)
        current_perfimg_status = current_metadata.get('perfimg_status', 'FALSE')
        new_perfimg_status = 'FALSE' if current_perfimg_status == 'TRUE' else 'TRUE'
        current_metadata['perfimg_status'] = new_perfimg_status
        
        # Use copy_object to update the metadata
        s3_client.copy_object(
            CopySource={'Bucket': buckets[bucket_name], 'Key': object_key},
            Bucket=buckets[bucket_name],
            Key=object_key,
            Metadata=current_metadata,
            MetadataDirective='REPLACE',
            ContentType=content_type,
            ACL="public-read",
            ContentDisposition="inline"
        )
        
        # Log the metadata update
        app.logger.info(f"Updated perfimg_status for {object_key} from {current_perfimg_status} to {new_perfimg_status}")
        
        # Extract just the filename for the flash message
        filename = object_key.split('/')[-1]
        flash(f'Toggled perfimg_status for "{filename}" to {new_perfimg_status}', 'success')
        
    except Exception as e:
        app.logger.error(f"Error toggling perfimg_status: {e}")
        flash(f'Error updating metadata: {str(e)}', 'danger')
    
    # Redirect back to the browse bucket page
    return redirect(url_for('browse_bucket', bucket_name=bucket_name))

def get_performer_image_key(filter_by_review=None):
    """Gets a random object key from the performers bucket, specifically from the performers/detail folder."""
    try:
        # Define the specific prefix for performer images
        prefix = 'images/performers/detail/'
        
        # Get list of objects with the performers prefix
        response = s3_client.list_objects_v2(
            Bucket=S3_PERFORMER_BUCKET,
            Prefix=prefix
        )
            
        if 'Contents' in response and response['Contents']:
            all_objects = response['Contents']
            
            # Filter to include only image files
            image_objects = []
            
            for obj in all_objects:
                # Skip the prefix itself or any folder objects
                if obj['Key'] == prefix or obj['Key'].endswith('/'):
                    continue
                
                # Only include image files
                file_ext = obj['Key'].lower().split('.')[-1] if '.' in obj['Key'] else ''
                if file_ext not in ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp']:
                    continue
                
                # If filtering by review status
                if filter_by_review:
                    try:
                        head_response = s3_client.head_object(
                            Bucket=S3_PERFORMER_BUCKET,
                            Key=obj['Key']
                        )
                        metadata = head_response.get('Metadata', {})
                        review_status = metadata.get('review_status', 'FALSE')
                        
                        # If filtering for unreviewed images, only include those with FALSE status
                        if filter_by_review == 'unreviewed' and review_status != 'TRUE':
                            image_objects.append(obj)
                        # If filtering for reviewed images, only include those with TRUE status
                        elif filter_by_review == 'reviewed' and review_status == 'TRUE':
                            image_objects.append(obj)
                    except Exception as e:
                        app.logger.error(f"Error checking metadata for {obj['Key']}: {e}")
                        continue
                else:
                    # If not filtering by review status, include all image files
                    image_objects.append(obj)
            
            if image_objects:
                return random.choice(image_objects)['Key']
    except ClientError as e:
        app.logger.error(f"Error listing objects in Performers bucket: {e}")
        flash(f"Error accessing Performers bucket: {e.response['Error']['Message']}", "danger")
    except Exception as e:
        app.logger.error(f"Unexpected error listing performer objects: {e}")
        flash("An unexpected error occurred while listing performer files.", "danger")
    return None

@app.route('/perf_review')
@login_required
def perf_review_image_route():
    """
    Show one image for performer likeness review.
    Sources from S3_UPLOAD_BUCKET (temp_performer_at_venue_images/) or S3_PERFORMER_BUCKET.
    Displays reference photos for comparison.
    """
    app.logger.info(f"Perf Review page accessed by user {session.get('user_id', 'unknown')}")

    # Fetch image from S3_UPLOAD_BUCKET (temp_performer_at_venue_images/)
    # These images are typically PerformerID.VenueID.webp
    image_key = get_random_image_key(S3_UPLOAD_BUCKET) 
    source_bucket = S3_UPLOAD_BUCKET
    
    # If no image found in S3_UPLOAD_BUCKET, try S3_PERFORMER_BUCKET as a fallback (optional, based on desired flow)
    # For now, sticking to the user request of S3_UPLOAD_BUCKET primary.
    # If you want a fallback:
    # if not image_key:
    #     app.logger.info(f"No image found in {S3_UPLOAD_BUCKET}, trying {S3_PERFORMER_BUCKET}")
    #     image_key = get_performer_image_key(filter_by_review='unreviewed')
    #     source_bucket = S3_PERFORMER_BUCKET

    image_url = None
    uploader_initials = "Unknown" # Default, will be fetched from metadata if available
    review_status = "FALSE"   # Default for new images from upload bucket
    perfimg_status = "FALSE"  # Default for new images from upload bucket
    performer_name = "Unknown Performer"
    performer_id = None
    metadata = {}

    if image_key:
        image_url = get_presigned_url(source_bucket, image_key)
        app.logger.info(f"Loading image for performer review: {image_key} from {source_bucket}")

        try:
            head_response = s3_client.head_object(Bucket=source_bucket, Key=image_key)
            metadata = head_response.get('Metadata', {})
            uploader_initials = metadata.get('uploader-initials', 'Unknown')
            # For images from S3_UPLOAD_BUCKET, review_status and perfimg_status are typically not set yet.
            # So we rely on their default 'FALSE' or whatever is in metadata.
            review_status = metadata.get('review_status', 'FALSE')
            perfimg_status = metadata.get('perfimg_status', 'FALSE')

            filename = image_key.split('/')[-1]
            performer_id = extract_performer_id(filename) # extract_performer_id works for PerformerID.VenueID.webp
            if performer_id:
                performer_name = get_performer_name(performer_id)
                app.logger.info(f"Extracted Performer ID {performer_id} → Name '{performer_name}' from filename {filename}")
            else:
                app.logger.warning(f"Could not extract Performer ID from filename {filename}")
        except Exception as e:
            app.logger.error(f"Error reading metadata for {image_key}: {e}")
    else:
        app.logger.info(f"No suitable image found in {source_bucket} for performer review.")


    return render_template(
        'perf_review.html',
        image_url=image_url,
        image_key=image_key,
        source_bucket=source_bucket,
        uploader_initials=uploader_initials,
        review_status=review_status,
        perfimg_status=perfimg_status,
        performer_name=performer_name,
        performer_id=performer_id,  # Pass performer_id for reference images
        metadata=metadata
    )

@app.route('/performer_action/<action>/<path:image_key>', methods=['POST'])
@login_required
def performer_action_route(action, image_key):
    if not image_key:
        flash("No image key provided for action.", "danger")
        return redirect(url_for('perf_review_image_route'))

    source_bucket = request.form.get('source_bucket')
    if not source_bucket:
        flash("Source bucket not provided in form.", "danger")
        return redirect(url_for('perf_review_image_route'))
    
    app.logger.info(f"Performer action: {action} for image: {image_key} from source bucket: {source_bucket}")

    # As per user request, this review page now only processes images from S3_UPLOAD_BUCKET.
    if source_bucket == S3_UPLOAD_BUCKET:
        filename = image_key.split('/')[-1] # Get filename for messages

        if action == 'good':
            # Move to S3_PERFORMER_BUCKET. 
            # Metadata (review_status=TRUE, perfimg_status=TRUE) is set by move_s3_object via _prepare_s3_operation.
            if move_s3_object(source_bucket, S3_PERFORMER_BUCKET, image_key, destination='good'):
                flash(f"Image '{filename}' approved and moved to Performers bucket.", "success")
            else:
                flash(f"Failed to move image '{filename}' to Performers bucket.", "danger")
        
        elif action == 'bad':
            # Move to S3_BAD_BUCKET.
            # Metadata (review_status=TRUE, bad_reason can be set) is set by move_s3_object.
            if move_s3_object(source_bucket, S3_BAD_BUCKET, image_key, destination='bad'):
                flash(f"Image '{filename}' marked BAD and moved to Bad Images bucket.", "success")
            else:
                # move_s3_object already flashes detailed errors for copy or delete failures.
                # Add a general failure message if not already covered by move_s3_object's flashes.
                # However, to avoid double flashing, rely on move_s3_object's messages.
                # If move_s3_object returns False, it has already flashed an error.
                app.logger.error(f"Failed to move image '{filename}' to Bad Images bucket. Check earlier logs/flashes from move_s3_object.")
                # Flash a generic message if specific one wasn't set by helper
                # This might be redundant if move_s3_object is comprehensive.
                if not any(m[0] == 'danger' for m in session.get('_flashes', [])):
                     flash(f"Failed to move image '{filename}' to Bad Images bucket. See logs for details.", "danger")

        elif action == 'incredible':
            copied_to_performers = False
            copied_to_incredible = False
            filename_for_logs = image_key.split('/')[-1] # For clearer logs

            # 1. Copy to Performers Bucket (destination='good' sets review_status=TRUE, perfimg_status=TRUE)
            app.logger.info(f"[performer_action_route/incredible] Attempting to copy {filename_for_logs} from {source_bucket} to S3_PERFORMER_BUCKET ({S3_PERFORMER_BUCKET})")
            if copy_s3_object(source_bucket, S3_PERFORMER_BUCKET, image_key, destination='good'):
                app.logger.info(f"[performer_action_route/incredible] Successfully copied {filename_for_logs} to S3_PERFORMER_BUCKET ({S3_PERFORMER_BUCKET}).")
                copied_to_performers = True
            else:
                app.logger.error(f"[performer_action_route/incredible] FAILED to copy {filename_for_logs} to S3_PERFORMER_BUCKET ({S3_PERFORMER_BUCKET}).")
                # copy_s3_object flashes its own errors

            # 2. Copy to Incredible Bucket (destination='incredible' also sets review_status=TRUE, perfimg_status=TRUE)
            if copied_to_performers: # Only attempt second copy if the first was successful
                app.logger.info(f"[performer_action_route/incredible] Attempting to copy {filename_for_logs} from {source_bucket} to S3_INCREDIBLE_BUCKET ({S3_INCREDIBLE_BUCKET})")
                if copy_s3_object(source_bucket, S3_INCREDIBLE_BUCKET, image_key, destination='incredible'):
                    app.logger.info(f"[performer_action_route/incredible] Successfully copied {filename_for_logs} to S3_INCREDIBLE_BUCKET ({S3_INCREDIBLE_BUCKET}).")
                    copied_to_incredible = True
                else:
                    app.logger.error(f"[performer_action_route/incredible] FAILED to copy {filename_for_logs} to S3_INCREDIBLE_BUCKET ({S3_INCREDIBLE_BUCKET}).")
                    # copy_s3_object flashes its own errors
            
            # 3. Delete from Upload Bucket if both copies were successful
            if copied_to_performers and copied_to_incredible:
                app.logger.info(f"[performer_action_route/incredible] Both copies successful. Attempting to delete {image_key} from {source_bucket}")
                try:
                    s3_client.delete_object(Bucket=source_bucket, Key=image_key)
                    app.logger.info(f"[performer_action_route/incredible] Successfully deleted {image_key} from {source_bucket}.")
                    flash(f"Image '{filename}' marked INCREDIBLE: copied to Performers and Incredible buckets, and removed from Upload bucket.", "success")
                except Exception as e:
                    app.logger.error(f"[performer_action_route/incredible] Error deleting '{image_key}' from {source_bucket} after copies: {e}")
                    flash(f"Image '{filename}' copied to Performers & Incredible, but FAILED to delete from Upload bucket. Please check manually.", "warning")
            elif copied_to_performers and not copied_to_incredible:
                # This case means it's in Performers, but not Incredible. Original is NOT deleted.
                # copy_s3_object (for incredible) should have flashed an error.
                app.logger.warning(f"[performer_action_route/incredible] Image '{filename}' copied to Performers, but FAILED to copy to Incredible. Original NOT deleted from {source_bucket}.")
                # Ensure a clear message if copy_s3_object didn't provide one or it was missed.
                if not any('Incredible bucket' in m[1] for m in session.get('_flashes', []) if m[0] in ['danger', 'warning']):
                    flash(f"Image '{filename}' was copied to Performers, but failed to copy to Incredible. Original image remains in upload bucket.", "warning")

            elif not copied_to_performers:
                # This case means the first copy (to Performers) failed. Nothing should be deleted.
                # copy_s3_object (for performers) should have flashed an error.
                app.logger.warning(f"Image '{filename}' FAILED to copy to Performers. Subsequent steps aborted. Original NOT deleted from {source_bucket}.")
                if not any('Performers bucket' in m[1] for m in session.get('_flashes', []) if m[0] in ['danger', 'warning']):
                     flash(f"Image '{filename}' failed to copy to Performers bucket. Original image remains in upload bucket.", "danger")


        else:
            flash(f"Invalid action: {action} for image from {S3_UPLOAD_BUCKET}.", "danger")
    
    else:
        flash(f"Unsupported source bucket '{source_bucket}' for this performer action. Expected '{S3_UPLOAD_BUCKET}'.", "danger")
    
    return redirect(url_for('perf_review_image_route'))

if __name__ == '__main__':
    if not os.path.exists('templates'):
        os.makedirs('templates')
    # For local development
    app.run(debug=True)
    
# Set higher timeout for Gunicorn when running on Heroku
# Usage: gunicorn --timeout 300 app:app