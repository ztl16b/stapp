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
import subprocess
import shlex
from redis import Redis #type:ignore
from rq import Queue #type:ignore
from rq.job import Job #type:ignore
from tasks import generate_performers
import ssl # Add ssl import
from urllib.parse import urlparse # Add urlparse import
from rq.exceptions import NoSuchJobError # Import NoSuchJobError #type:ignore

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
REVIEWER_PASSWORD = os.getenv("REVIEWER_PASSWORD")
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
        
        # performer_data = {row['performer_id']: row['name_alias'] for row in csv_reader if 'performer_id' in row and 'name_alias' in row}
        new_performer_data = {}
        for row in csv_reader:
            if 'performer_id' in row and row['performer_id'].strip(): # Ensure performer_id exists and is not empty
                new_performer_data[row['performer_id']] = {
                    'name_alias': row.get('name_alias', 'N/A'),
                    'category_name': row.get('category_name', 'N/A')
                }
        performer_data = new_performer_data
        
        app.logger.info(f"Loaded {len(performer_data)} performers from CSV with details")
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
    
    # return performer_data.get(performer_id, "Unknown Performer")
    performer_info = performer_data.get(str(performer_id)) # Ensure ID is string for lookup
    if performer_info:
        return performer_info.get('name_alias', "Unknown Performer")
    return "Unknown Performer"

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
        reviewer_password = os.getenv('REVIEWER_PASSWORD') # Get reviewer password

        if password == admin_password:
            session['logged_in'] = True
            session['permission_level'] = 'admin' # Set permission level
            session.permanent = True
            flash('Admin login successful!', 'success')
            next_url = session.get('next')
            if next_url:
                session.pop('next', None)
                return redirect(next_url)
            return redirect(url_for('browse_buckets'))
        elif reviewer_password and password == reviewer_password: # Check reviewer password
            session['logged_in'] = True
            session['permission_level'] = 'reviewer' # Set permission level
            session.permanent = True
            flash('Login successful!', 'success')
            next_url = session.get('next')
            if next_url:
                session.pop('next', None)
                return redirect(next_url)
            # Reviewers can be redirected to 'upload' or a review page. 'upload' is fine.
            return redirect(url_for('upload'))
        else:
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

        # Ensure image files get a specific image ContentType
        if content_type == 'application/octet-stream' or not content_type:
            ext = os.path.splitext(filename)[1].lower()
            if ext in ['.jpg', '.jpeg']:
                content_type = 'image/jpeg'
            elif ext == '.png':
                content_type = 'image/png'
            elif ext == '.gif':
                content_type = 'image/gif'
            elif ext == '.webp':
                content_type = 'image/webp'
            elif ext == '.bmp':
                content_type = 'image/bmp'
            elif not content_type: # If still None after checking common extensions
                 content_type = 'application/octet-stream' # Fallback
        
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
    """Gets a random object key from the specified bucket, optionally filtered by review status.
       Limits initial scan to a defined number of items before further processing.
    """
    MAX_ITEMS_TO_CONSIDER = 100
    collected_objects = []
    prefix = None

    try:
        # Different prefix depending on which bucket we're using
        if bucket_name == S3_UPLOAD_BUCKET:
            prefix = 'temp_performer_at_venue_images/'
        elif bucket_name == S3_TEMP_BUCKET:
            prefix = 'tmp_upload/'
        elif bucket_name == S3_GOOD_BUCKET:
            prefix = 'images/performer-at-venue/detail/'

        paginator = s3_client.get_paginator('list_objects_v2')
        page_iterator = paginator.paginate(
            Bucket=bucket_name,
            Prefix=prefix if prefix else ''
        )

        for page in page_iterator:
            if 'Contents' in page:
                for obj in page['Contents']:
                    # Skip folder-like objects
                    if not obj['Key'].endswith('/'):
                        collected_objects.append(obj)
                    if len(collected_objects) >= MAX_ITEMS_TO_CONSIDER:
                        break
            if len(collected_objects) >= MAX_ITEMS_TO_CONSIDER:
                break
        
        app.logger.info(f"Collected {len(collected_objects)} items from {bucket_name} (prefix: {prefix}) for random selection pool.")

        if not collected_objects:
            app.logger.info("No objects collected after initial scan.")
            return None
            
        # The rest of the function now uses 'collected_objects' instead of 'all_objects'
        # from a single list_objects_v2 call.
        all_objects_to_filter = collected_objects
        image_objects = []
        
        # For Good bucket, filter by review status if requested
        if bucket_name == S3_GOOD_BUCKET and filter_by_review:
            for obj in all_objects_to_filter:
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
                obj for obj in all_objects_to_filter
                if obj['Key'].lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp'))
            ]
        else: # This covers S3_UPLOAD_BUCKET as per original logic
            # For upload bucket, keep only webp files and make sure they match the expected format
            # Format should be numeric_id.numeric_id.webp
            image_objects = []
            for obj in all_objects_to_filter:
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
    
    # If moving from S3_ISSUE_BUCKET, clean up the filename by removing _text or _likeness suffixes
    if source_bucket == S3_ISSUE_BUCKET:
        filename_base, file_ext = os.path.splitext(filename)
        modified = False
        if filename_base.endswith('_text'):
            filename_base = filename_base[:-len('_text')]
            modified = True
        elif filename_base.endswith('_likeness'): # Use elif to avoid stripping both if somehow present like "_likeness_text"
            filename_base = filename_base[:-len('_likeness')]
            modified = True
        
        if modified:
            new_filename = filename_base + file_ext
            app.logger.info(f"Filename modification for issue bucket: '{filename}' -> '{new_filename}'")
            filename = new_filename

    # Determine destination path based on dest_bucket and destination hint
    dest_key = filename # Default to filename (root of dest_bucket if no prefix matches)

    if destination == 'good':
        if dest_bucket == S3_PERFORMER_BUCKET and S3_PERFORMER_BUCKET_PREFIX: # Used by performer_action_route for 'good'
            dest_key = f"{S3_PERFORMER_BUCKET_PREFIX}{filename}"
        elif dest_bucket == S3_GOOD_BUCKET and S3_GOOD_BUCKET_PREFIX: # Used by move_image_route (perf_ven_review) for 'good'
            dest_key = f"{S3_GOOD_BUCKET_PREFIX}{filename}"
        # If other 'good' destinations with specific (bucket, prefix) combos are needed, add here.
    elif destination == 'bad':
        if dest_bucket == S3_BAD_BUCKET and S3_BAD_BUCKET_PREFIX:
            dest_key = f"{S3_BAD_BUCKET_PREFIX}{filename}"
    elif destination == 'incredible':
        # Note: 'incredible' action in performer_action_route involves two copies:
        # 1. To S3_PERFORMER_BUCKET with destination='good' (handled by the 'good' block)
        # 2. To S3_INCREDIBLE_BUCKET with destination='incredible' (this block)
        if dest_bucket == S3_INCREDIBLE_BUCKET and S3_INCREDIBLE_BUCKET_PREFIX:
            dest_key = f"{S3_INCREDIBLE_BUCKET_PREFIX}{filename}"
    elif destination == 'to_upload_staging': # New destination type
        # dest_bucket is S3_UPLOAD_BUCKET when this is called
        if S3_UPLOAD_BUCKET_PREFIX:
            dest_key = f"{S3_UPLOAD_BUCKET_PREFIX}{filename}"
        # else dest_key remains filename (root of S3_UPLOAD_BUCKET)
    elif destination == 'to_temp_staging': # New destination type
        # dest_bucket is S3_TEMP_BUCKET when this is called
        if S3_TEMP_BUCKET_PREFIX:
            dest_key = f"{S3_TEMP_BUCKET_PREFIX}{filename}"
        # else dest_key remains filename (root of S3_TEMP_BUCKET)
    elif destination == 'to_issue_staging': # New destination type for moving TO Issue bucket
        if dest_bucket == S3_ISSUE_BUCKET and S3_ISSUE_BUCKET_PREFIX:
            dest_key = f"{S3_ISSUE_BUCKET_PREFIX}{filename}"
        # else dest_key remains filename (root of S3_ISSUE_BUCKET)
    else:
        # Fallback logic if destination hint is None or not one of the handled specific actions.
        # This attempts to match based on bucket type if a prefix is defined.
        # Order is important if bucket names can be the same for different roles.
        if dest_bucket == S3_PERFORMER_BUCKET and S3_PERFORMER_BUCKET_PREFIX:
            dest_key = f"{S3_PERFORMER_BUCKET_PREFIX}{filename}"
        elif dest_bucket == S3_BAD_BUCKET and S3_BAD_BUCKET_PREFIX: # Check specific types before more general ones
            dest_key = f"{S3_BAD_BUCKET_PREFIX}{filename}"
        elif dest_bucket == S3_INCREDIBLE_BUCKET and S3_INCREDIBLE_BUCKET_PREFIX:
            dest_key = f"{S3_INCREDIBLE_BUCKET_PREFIX}{filename}"
        elif dest_bucket == S3_GOOD_BUCKET and S3_GOOD_BUCKET_PREFIX:
            dest_key = f"{S3_GOOD_BUCKET_PREFIX}{filename}"
        elif dest_bucket == S3_ISSUE_BUCKET and S3_ISSUE_BUCKET_PREFIX:
            dest_key = f"{S3_ISSUE_BUCKET_PREFIX}{filename}"
        # If no specific prefix is matched above, dest_key remains `filename` (root of dest_bucket)
    
    # Determine content type based on file extension
    content_type_guess, _ = mimetypes.guess_type(filename)
    
    # Start with the guess or a generic fallback
    content_type = content_type_guess if content_type_guess else 'application/octet-stream'

    # If the determined content_type is generic (application/octet-stream)
    # and the file has a common image extension, override with a specific image ContentType.
    if content_type == 'application/octet-stream':
        ext = os.path.splitext(filename)[1].lower()
        if ext in ['.jpg', '.jpeg']:
            content_type = 'image/jpeg'
        elif ext == '.png':
            content_type = 'image/png'
        elif ext == '.gif':
            content_type = 'image/gif'
        elif ext == '.webp':
            content_type = 'image/webp'
        elif ext == '.bmp':
            content_type = 'image/bmp'
    # For non-image files or images with specific mimetypes, the initial 'content_type' will be used or remains 'application/octet-stream' if truly unknown.
        
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
    elif destination in ['to_upload_staging', 'to_temp_staging', 'to_issue_staging']: # New
        metadata['review_status'] = 'FALSE'
        metadata['perfimg_status'] = 'FALSE'
        if 'bad_reason' in metadata: # Remove bad_reason if moving to staging
            del metadata['bad_reason']
    
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
    if session.get('permission_level') != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('upload'))

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
        'reference': {'name': 'Reference Images', 'bucket': S3_REF_BUCKET, 'prefix': S3_REF_BUCKET_PREFIX}, # New reference bucket
        'problem_performers_edit': {'name': 'Edit Problem Performers', 'bucket': None, 'prefix': None, 'is_editor': True, 'route_name': 'edit_problem_performers_route'}, # Special entry
        'completed_performers_edit': {'name': 'Edit Completed Performers', 'bucket': None, 'prefix': None, 'is_editor': True, 'route_name': 'edit_completed_performers_route'} # New special entry
    }
    app.logger.info(f"Buckets dictionary: {buckets}")
    return render_template('browse.html', buckets=buckets)

@app.route('/browse/<bucket_name>')
@login_required
def browse_bucket(bucket_name):
    if session.get('permission_level') != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('upload'))

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
        'reference': {'name': 'Reference Images', 'bucket': S3_REF_BUCKET, 'prefix': S3_REF_BUCKET_PREFIX}, # New reference bucket
        'problem_performers_edit': {'name': 'Edit Problem Performers', 'bucket': None, 'prefix': None, 'is_editor': True, 'route_name': 'edit_problem_performers_route'}, # Special entry
        'completed_performers_edit': {'name': 'Edit Completed Performers', 'bucket': None, 'prefix': None, 'is_editor': True, 'route_name': 'edit_completed_performers_route'} # New special entry
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
        num_recent_items_target = 1500  # Target number of most recent items to process
        s3_candidate_scan_limit = 10000  # How many items to fetch fro3 to find the recent ones

        prefix = str(bucket_info['prefix']) if bucket_info['prefix'] else ''
        
        # --- Fetch and Filter Data ---
        s3 = get_s3_client() # Use thread-local client
        s3_paginator = s3.get_paginator('list_objects_v2')
        
        s3_results_candidates = [] # Temp list for S3 scan results before sorting
        items_retrieved_from_s3 = 0
        s3_scan_was_truncated = False # True if S3 scan was cut short or S3 reported more data

        app.logger.info(f"Scanning S3 for up to {s3_candidate_scan_limit} items to find the {num_recent_items_target} most recent for bucket '{bucket_name}', prefix '{prefix}'.")
        
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
    if session.get('permission_level') != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('upload'))

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
    if session.get('permission_level') != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('upload'))

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
    if session.get('permission_level') != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('upload'))

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
    if session.get('permission_level') != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('upload'))

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
    """Gets a random object key from the performers bucket, specifically from the performers/detail folder.
       Limits initial scan to a defined number of items before further processing.
    """
    MAX_ITEMS_TO_CONSIDER = 100
    collected_objects = []
    prefix = 'images/performers/detail/'

    try:
        paginator = s3_client.get_paginator('list_objects_v2')
        page_iterator = paginator.paginate(
            Bucket=S3_PERFORMER_BUCKET,
            Prefix=prefix
        )

        for page in page_iterator:
            if 'Contents' in page:
                for obj in page['Contents']:
                    # Skip the prefix itself or any folder objects
                    if obj['Key'] == prefix or obj['Key'].endswith('/'):
                        continue
                    collected_objects.append(obj)
                    if len(collected_objects) >= MAX_ITEMS_TO_CONSIDER:
                        break
            if len(collected_objects) >= MAX_ITEMS_TO_CONSIDER:
                break
        
        app.logger.info(f"Collected {len(collected_objects)} items from {S3_PERFORMER_BUCKET} (prefix: {prefix}) for performer image selection pool.")

        if not collected_objects:
            app.logger.info("No objects collected from performer bucket after initial scan.")
            return None

        all_objects_to_filter = collected_objects
        image_objects = []
        
        for obj in all_objects_to_filter:
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

    # Get bad_reason and other_reason from the form
    bad_reason = request.form.get('bad_reason', None)
    other_reason = request.form.get('other_reason', None)

    # Process bad_reason
    processed_bad_reason = None
    if bad_reason == 'other' and other_reason and other_reason.strip():
        processed_bad_reason = f"Other: {other_reason.strip()}"
    elif bad_reason:
        processed_bad_reason = bad_reason

    if processed_bad_reason:
        app.logger.info(f"Bad reason selected: {processed_bad_reason}")

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
            if move_s3_object(source_bucket, S3_BAD_BUCKET, image_key, destination='bad', bad_reason=processed_bad_reason):
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

@app.route('/generate', methods=['GET', 'POST'])
@login_required
def generate_images_route():
    """Page with a form that starts a background image-generation job.
       Displays a list of problematic performer IDs from S3.
    """
    # Add permission check
    if session.get('permission_level') != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('upload'))

    redis_url_env = os.getenv("REDIS_URL")

    s3_problem_performers = []
    s3_problem_performers_error = None

    # --- Fetch problematic performers list from S3 on every GET request ---
    try:
        s3 = get_s3_client() # Use your existing S3 client getter
        if not S3_RESOURCES_BUCKET:
            s3_problem_performers_error = "S3_RESOURCES_BUCKET environment variable is not set."
            app.logger.error(s3_problem_performers_error)
        else:
            problem_file_key = "temp/problem_performers.txt"
            try:
                response = s3.get_object(Bucket=S3_RESOURCES_BUCKET, Key=problem_file_key)
                file_content = response['Body'].read().decode('utf-8')
                if file_content.strip(): # Ensure content is not just whitespace
                    s3_problem_performers = [line.strip() for line in file_content.splitlines() if line.strip()]
                # If file is empty or only whitespace, s3_problem_performers remains empty []
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchKey':
                    s3_problem_performers_error = f"File '{problem_file_key}' not found in bucket '{S3_RESOURCES_BUCKET}'."
                    app.logger.info(s3_problem_performers_error) # Info level, as it might be normal for the file not to exist
                else:
                    s3_problem_performers_error = f"Error fetching '{problem_file_key}' from S3: {str(e)}"
                    app.logger.error(s3_problem_performers_error)
            except Exception as e:
                s3_problem_performers_error = f"Unexpected error reading '{problem_file_key}' from S3: {str(e)}"
                app.logger.error(s3_problem_performers_error, exc_info=True)
    except Exception as e:
        s3_problem_performers_error = f"Error initializing S3 client for fetching problem performers: {str(e)}"
        app.logger.error(s3_problem_performers_error, exc_info=True)
    # End of S3 fetch logic

    if request.method == "POST":
        # Redis connection for POST (job enqueuing)
        if not redis_url_env:
            flash("REDIS_URL is not set. Cannot connect to Redis to enqueue job.", "danger")
            # Pass current S3 fetched data even if POST fails early
            return render_template("generate.html", s3_problem_performers=s3_problem_performers, s3_problem_performers_error=s3_problem_performers_error)

        try:
            url = urlparse(redis_url_env)
            # ... (rest of Redis connection setup as before) ...
            if url.scheme != "rediss":
                raise ValueError("REDIS_URL must use rediss:// scheme for SSL connections.")
            db_number = 0
            if url.path and len(url.path) > 1 and url.path[1:].isdigit():
                db_number = int(url.path[1:])
            redis_conn = Redis(
                host=url.hostname, port=url.port, password=url.password,
                db=db_number, ssl=True, ssl_cert_reqs=None
            )
            redis_conn.ping()
            q = Queue(connection=redis_conn)
        except Exception as e:
            app.logger.error(f"Redis connection failed during POST: {e}", exc_info=True)
            flash(f"Failed to connect to Redis to enqueue job: {e}", "danger")
            return render_template("generate.html", s3_problem_performers=s3_problem_performers, s3_problem_performers_error=s3_problem_performers_error)
        
        # ... (performer_ids parsing logic remains the same) ...
        performer_ids_str = request.form.get("performer_ids", "")
        performer_ids_list = [
            pid.strip() for pid in re.split(r"[\\s,]+", performer_ids_str)
            if pid.strip().isdigit()
        ]

        if not performer_ids_list:
            flash("Please enter at least one numeric performer ID.", "warning")
            return render_template("generate.html", s3_problem_performers=s3_problem_performers, s3_problem_performers_error=s3_problem_performers_error)
        else:
            queued_jobs_count = 0
            failed_to_queue_count = 0
            for pid_str in performer_ids_list:
                try:
                    performer_id = int(pid_str)
                    job = q.enqueue(
                        generate_performers, # This will now be called with a single ID
                        performer_id,
                        job_timeout=600 
                    )
                    app.logger.info(f"Image-generation job '{job.id}' queued for ID: {performer_id}.")
                    queued_jobs_count += 1
                except Exception as e:
                    app.logger.error(f"Error enqueuing job for ID {pid_str}: {e}", exc_info=True)
                    failed_to_queue_count += 1
            
            if queued_jobs_count > 0:
                flash(
                    f"{queued_jobs_count} image-generation job(s) queued successfully for IDs: {', '.join(performer_ids_list[:queued_jobs_count])}.", # Show only successfully queued IDs for brevity if many
                    "success"
                )
            if failed_to_queue_count > 0:
                flash(
                    f"Failed to queue {failed_to_queue_count} image-generation job(s). Please check logs.",
                    "danger"
                )
            
            # Redirect back to the GET version of the page.
            return redirect(url_for("generate_images_route")) 

    # For GET requests, or if POST fails and re-renders
    return render_template("generate.html", s3_problem_performers=s3_problem_performers, s3_problem_performers_error=s3_problem_performers_error)

@app.route('/edit_problem_performers', methods=['GET', 'POST'])
@login_required
def edit_problem_performers_route():
    if session.get('permission_level') != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('upload'))

    s3 = get_s3_client()
    problem_file_key = "temp/problem_performers.txt"
    current_content = ""
    error_message = None
    id_count = 0 # Initialize id_count

    if request.method == 'POST':
        new_content = request.form.get('problem_performers_content', '')
        try:
            if not S3_RESOURCES_BUCKET:
                raise ValueError("S3_RESOURCES_BUCKET environment variable is not set.")
            
            s3.put_object(
                Bucket=S3_RESOURCES_BUCKET,
                Key=problem_file_key,
                Body=new_content.encode('utf-8'),
                ContentType='text/plain'
            )
            flash('Successfully updated problem performers list.', 'success')
            current_content = new_content # Show updated content after saving
        except Exception as e:
            app.logger.error(f"Error updating {problem_file_key} in S3: {str(e)}")
            flash(f"Error updating problem performers list: {str(e)}", 'danger')
            error_message = str(e)
            # In case of save error, try to reload current content to display
            try:
                if S3_RESOURCES_BUCKET:
                    response = s3.get_object(Bucket=S3_RESOURCES_BUCKET, Key=problem_file_key)
                    current_content = response['Body'].read().decode('utf-8')
            except Exception: # Nosemgrep: general-exception-caught
                # If reloading also fails, current_content remains as it was before POST or empty
                pass
        
        # Recalculate count after POST for display
        if current_content:
            ids = [line.strip() for line in current_content.splitlines() if line.strip().isdigit()]
            id_count = len(ids)
            
        return render_template('edit_problem_performers.html', 
                               content=current_content, 
                               error_message=error_message,
                               id_count=id_count) # Pass id_count

    # GET request logic
    try:
        if not S3_RESOURCES_BUCKET:
            raise ValueError("S3_RESOURCES_BUCKET environment variable is not set.")
        response = s3.get_object(Bucket=S3_RESOURCES_BUCKET, Key=problem_file_key)
        current_content = response['Body'].read().decode('utf-8')
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            app.logger.info(f"File '{problem_file_key}' not found in bucket '{S3_RESOURCES_BUCKET}'. Will create on save.")
            # File doesn't exist, treat as empty content
            current_content = "" 
        else:
            app.logger.error(f"Error fetching '{problem_file_key}' from S3: {str(e)}")
            error_message = f"Error fetching problem performers list: {str(e)}"
    except Exception as e:
        app.logger.error(f"Unexpected error reading '{problem_file_key}' from S3: {str(e)}")
        error_message = f"Unexpected error reading problem performers list: {str(e)}"
    
    # Calculate count for GET request
    if current_content:
        ids = [line.strip() for line in current_content.splitlines() if line.strip().isdigit()]
        id_count = len(ids)
        
    return render_template('edit_problem_performers.html', 
                           content=current_content, 
                           error_message=error_message,
                           id_count=id_count) # Pass id_count

@app.route('/edit_completed_performers', methods=['GET', 'POST'])
@login_required
def edit_completed_performers_route():
    if session.get('permission_level') != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('upload'))

    s3 = get_s3_client()
    completed_file_key = "temp/completed_performers.txt"
    current_content = ""
    error_message = None
    id_count = 0 # Initialize id_count

    if request.method == 'POST':
        new_content = request.form.get('completed_performers_content', '')
        try:
            if not S3_RESOURCES_BUCKET:
                raise ValueError("S3_RESOURCES_BUCKET environment variable is not set.")
            
            s3.put_object(
                Bucket=S3_RESOURCES_BUCKET,
                Key=completed_file_key,
                Body=new_content.encode('utf-8'),
                ContentType='text/plain'
            )
            flash('Successfully updated completed performers list.', 'success')
            current_content = new_content # Show updated content after saving
        except Exception as e:
            app.logger.error(f"Error updating {completed_file_key} in S3: {str(e)}")
            flash(f"Error updating completed performers list: {str(e)}", 'danger')
            error_message = str(e)
            try:
                if S3_RESOURCES_BUCKET:
                    response = s3.get_object(Bucket=S3_RESOURCES_BUCKET, Key=completed_file_key)
                    current_content = response['Body'].read().decode('utf-8')
            except Exception: # Nosemgrep: general-exception-caught
                pass
        
        # Recalculate count after POST for display
        if current_content:
            ids = [line.strip() for line in current_content.splitlines() if line.strip().isdigit()]
            id_count = len(ids)
            
        return render_template('edit_completed_performers.html', 
                               content=current_content, 
                               error_message=error_message,
                               id_count=id_count) # Pass id_count

    # GET request logic
    try:
        if not S3_RESOURCES_BUCKET:
            raise ValueError("S3_RESOURCES_BUCKET environment variable is not set.")
        response = s3.get_object(Bucket=S3_RESOURCES_BUCKET, Key=completed_file_key)
        current_content = response['Body'].read().decode('utf-8')
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            app.logger.info(f"File '{completed_file_key}' not found in bucket '{S3_RESOURCES_BUCKET}'. Will create on save.")
            current_content = ""
        else:
            app.logger.error(f"Error fetching '{completed_file_key}' from S3: {str(e)}")
            error_message = f"Error fetching completed performers list: {str(e)}"
    except Exception as e:
        app.logger.error(f"Unexpected error reading '{completed_file_key}' from S3: {str(e)}")
        error_message = f"Unexpected error reading completed performers list: {str(e)}"
        
    # Calculate count for GET request
    if current_content:
        ids = [line.strip() for line in current_content.splitlines() if line.strip().isdigit()]
        id_count = len(ids)
        
    return render_template('edit_completed_performers.html', 
                           content=current_content, 
                           error_message=error_message,
                           id_count=id_count) # Pass id_count

@app.route('/api/performer_info/<performer_id>')
@login_required
def api_lookup_performer_info(performer_id):
    global performer_data
    if not performer_data:
        load_performer_data() # Attempt to load if empty
    
    if not performer_data: # Still empty after load attempt
        return jsonify({'success': False, 'message': 'Performer data not available.'}), 500

    # Ensure performer_id is treated as a string for dictionary lookup consistency
    performer_info = performer_data.get(str(performer_id))
    
    if performer_info:
        return jsonify({
            'success': True, 
            'name_alias': performer_info.get('name_alias', 'N/A'),
            'category_name': performer_info.get('category_name', 'N/A')
        })
    else:
        return jsonify({'success': False, 'message': 'Performer ID not found.'}), 404

@app.route('/move_from_issue/<target_action>/<path:object_key>', methods=['POST'])
@login_required
def move_issue_file_route(target_action, object_key):
    if session.get('permission_level') != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('browse_bucket', bucket_name='issue'))

    if not object_key:
        flash("No image key provided for move operation.", "danger")
        return redirect(url_for('browse_bucket', bucket_name='issue'))

    source_bucket = S3_ISSUE_BUCKET
    filename = object_key.split('/')[-1] # For flash messages

    app.logger.info(f"Attempting to move '{object_key}' from issue bucket to '{target_action}' destination.")

    success = False
    destination_bucket_for_flash = ""
    actual_destination_bucket = None

    if target_action == 'to_upload':
        actual_destination_bucket = S3_UPLOAD_BUCKET
        if move_s3_object(source_bucket, actual_destination_bucket, object_key, destination='to_upload_staging'):
            success = True
            destination_bucket_for_flash = "Upload"
    elif target_action == 'to_temp':
        actual_destination_bucket = S3_TEMP_BUCKET
        if move_s3_object(source_bucket, actual_destination_bucket, object_key, destination='to_temp_staging'):
            success = True
            destination_bucket_for_flash = "Temp"
    else:
        flash(f"Invalid target action: {target_action}", "danger")
        return redirect(url_for('browse_bucket', bucket_name='issue'))

    if success:
        flash(f"Image '{filename}' successfully moved from Issue bucket to {destination_bucket_for_flash} bucket.", "success")
        app.logger.info(f"Successfully moved '{object_key}' from {source_bucket} to {destination_bucket_for_flash} bucket ({actual_destination_bucket}).")
    else:
        app.logger.error(f"Failed to move '{object_key}' from {source_bucket} to {destination_bucket_for_flash} bucket ({actual_destination_bucket}). Check earlier logs from move_s3_object.")
        # move_s3_object should flash specific errors. Add a generic one if it didn't.
        if not any(m[0] == 'danger' for m in session.get('_flashes', [])):
            flash(f"Failed to move image '{filename}' to {destination_bucket_for_flash} bucket. See logs for details.", "danger")
            
    return redirect(url_for('browse_bucket', bucket_name='issue'))

@app.route('/batch_move_from_issue/<target_action>', methods=['POST'])
@login_required
def batch_move_from_issue_route(target_action):
    if session.get('permission_level') != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('browse_bucket', bucket_name='issue'))

    selected_files = request.form.getlist('selected_files')
    if not selected_files:
        flash('No files were selected for the batch operation.', 'warning')
        return redirect(url_for('browse_bucket', bucket_name='issue'))

    source_bucket = S3_ISSUE_BUCKET
    successful_moves = 0
    failed_moves = 0
    
    actual_destination_bucket = None # Initialize to prevent UnboundLocalError if target_action is invalid
    actual_destination_bucket_name = ""
    destination_hint_for_prepare = ""

    if target_action == 'to_upload':
        actual_destination_bucket = S3_UPLOAD_BUCKET
        actual_destination_bucket_name = "Upload"
        destination_hint_for_prepare = 'to_upload_staging'
    elif target_action == 'to_temp':
        actual_destination_bucket = S3_TEMP_BUCKET
        actual_destination_bucket_name = "Temp"
        destination_hint_for_prepare = 'to_temp_staging'
    else:
        flash(f"Invalid batch target action: {target_action}", "danger")
        return redirect(url_for('browse_bucket', bucket_name='issue'))

    for object_key in selected_files:
        # filename = object_key.split('/')[-1] # Not strictly needed for logging here as object_key is logged
        app.logger.info(f"Batch moving '{object_key}' from {source_bucket} to {actual_destination_bucket_name} bucket ({actual_destination_bucket})")
        if move_s3_object(source_bucket, actual_destination_bucket, object_key, destination=destination_hint_for_prepare):
            successful_moves += 1
        else:
            failed_moves += 1
            # move_s3_object flashes its own detailed error, so we don't need to flash per file here.
            app.logger.error(f"Batch move FAILED for '{object_key}' to {actual_destination_bucket_name} bucket. See previous logs from move_s3_object.")

    if successful_moves > 0:
        flash(f"Successfully moved {successful_moves} file(s) to the {actual_destination_bucket_name} bucket.", "success")
    if failed_moves > 0:
        flash(f"Failed to move {failed_moves} file(s) to the {actual_destination_bucket_name} bucket. Please check logs for details.", "danger")
    # Only flash if selected_files was not empty initially but neither success nor fail counts incremented (should not happen with current logic)
    # This condition is better: if selected_files was not empty and we didn't achieve any successful or failed moves (e.g. if loop was skipped)
    if not selected_files: # This case is already handled by the check at the beginning
        pass
    elif successful_moves == 0 and failed_moves == 0:
         flash("No files were processed or eligible for the batch operation.", "info")

    return redirect(url_for('browse_bucket', bucket_name='issue'))

@app.route('/batch_move_from_upload/<target_action>', methods=['POST'])
@login_required
def batch_move_from_upload_route(target_action):
    if session.get('permission_level') != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('browse_bucket', bucket_name='upload'))

    selected_files = request.form.getlist('selected_files')
    if not selected_files:
        flash('No files were selected for the batch operation.', 'warning')
        return redirect(url_for('browse_bucket', bucket_name='upload'))

    source_bucket = S3_UPLOAD_BUCKET
    successful_moves = 0
    failed_moves = 0
    
    actual_destination_bucket = None
    actual_destination_bucket_name = ""
    destination_hint_for_prepare = ""

    if target_action == 'to_issue':
        actual_destination_bucket = S3_ISSUE_BUCKET
        actual_destination_bucket_name = "Issue"
        destination_hint_for_prepare = 'to_issue_staging'
    elif target_action == 'to_bad':
        actual_destination_bucket = S3_BAD_BUCKET
        actual_destination_bucket_name = "Bad"
        destination_hint_for_prepare = 'bad' # Existing hint
        # Retrieve the bad_reason from the form for 'to_bad' action
        processed_bad_reason = request.form.get('batch_bad_reason', None)
        if processed_bad_reason and processed_bad_reason.strip():
            app.logger.info(f"Bad reason provided for batch move: {processed_bad_reason}")
        else:
            # If for some reason bad_reason is empty or not provided by client-side validation,
            # default to a generic reason or handle as an error if reason is strictly required.
            # For now, allow it to be None if not provided, _prepare_s3_operation will handle it.
            app.logger.warning("No specific bad reason provided for batch move to Bad bucket.")
            processed_bad_reason = None # Explicitly set to None if empty

    elif target_action == 'to_incredible':
        actual_destination_bucket = S3_INCREDIBLE_BUCKET
        actual_destination_bucket_name = "Incredible"
        destination_hint_for_prepare = 'incredible' # Existing hint
    elif target_action == 'to_performers':
        actual_destination_bucket = S3_PERFORMER_BUCKET
        actual_destination_bucket_name = "Performers"
        destination_hint_for_prepare = 'good' # Existing hint, sets review/perfimg status to TRUE
    else:
        flash(f"Invalid batch target action: {target_action}", "danger")
        return redirect(url_for('browse_bucket', bucket_name='upload'))

    for object_key in selected_files:
        app.logger.info(f"Batch moving '{object_key}' from {source_bucket} to {actual_destination_bucket_name} bucket ({actual_destination_bucket}) using hint '{destination_hint_for_prepare}'")
        # For 'bad' destination, no bad_reason is passed for batch moves from upload.
        # For 'incredible' and 'performers' (using 'good' hint), no special params needed beyond what _prepare_s3_operation does.
        
        current_bad_reason_for_move = None
        if target_action == 'to_bad':
            current_bad_reason_for_move = processed_bad_reason # Use the reason captured earlier
            
        if move_s3_object(source_bucket, actual_destination_bucket, object_key, destination=destination_hint_for_prepare, bad_reason=current_bad_reason_for_move):
            successful_moves += 1
        else:
            failed_moves += 1
            app.logger.error(f"Batch move FAILED for '{object_key}' to {actual_destination_bucket_name} bucket. See previous logs from move_s3_object.")

    if successful_moves > 0:
        flash(f"Successfully moved {successful_moves} file(s) to the {actual_destination_bucket_name} bucket.", "success")
    if failed_moves > 0:
        flash(f"Failed to move {failed_moves} file(s) to the {actual_destination_bucket_name} bucket. Please check logs for details.", "danger")
    if not selected_files: # Should be caught by earlier check
        pass 
    elif successful_moves == 0 and failed_moves == 0 and selected_files:
         flash("No files were processed or eligible for the batch operation.", "info")

    return redirect(url_for('browse_bucket', bucket_name='upload'))

if __name__ == '__main__':
    if not os.path.exists('templates'):
        os.makedirs('templates')
    # For local development
    app.run(debug=True)
    
# Set higher timeout for Gunicorn when running on Heroku
# Usage: gunicorn --timeout 300 app:app