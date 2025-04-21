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

# Get the absolute path to the templates directory
template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
app = Flask(__name__, template_folder=template_dir)

# Set a fixed secret key for session management
app.secret_key = os.environ.get('SECRET_KEY')

# Define MST timezone (UTC-7)
MST = ZoneInfo("Etc/GMT+7")

# Custom Jinja filter for MST datetime formatting
def format_datetime_mst(dt_utc):
    if not isinstance(dt_utc, datetime):
        # Try to convert string format to datetime
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
S3_PERFORMER_BUCKET = os.getenv("S3_PERFORMER_BUCKET")
S3_RESOURCES_BUCKET = "etickets-content-test-bucket"

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

thread_local = threading.local()

# Global variable to store performer data
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

# Function to load performer data from CSV
def load_performer_data():
    """Load performer data from CSV file in S3 bucket"""
    global performer_data
    s3 = get_s3_client()
    
    try:
        # Get the CSV file from S3
        csv_obj = s3.get_object(Bucket=S3_RESOURCES_BUCKET, Key="temp/performer-infos (1).csv")
        csv_content = csv_obj['Body'].read().decode('utf-8')
        
        # Parse CSV content
        csv_reader = csv.DictReader(csv_content.splitlines())
        
        # Build dictionary with performer_id as key and name_alias as value
        performer_data = {row['performer_id']: row['name_alias'] for row in csv_reader if 'performer_id' in row and 'name_alias' in row}
        
        app.logger.info(f"Loaded {len(performer_data)} performers from CSV")
    except Exception as e:
        app.logger.error(f"Error loading performer data: {e}")
        # Initialize empty dict if error occurs
        performer_data = {}
        
    return performer_data

# Initialize s3 client and load performer data at startup
try:
    # Use the same client creation function for consistency
    s3_client = get_s3_client()
    
    # Create a reusable S3 upload configuration 
    s3_upload_config = boto3.s3.transfer.TransferConfig(
        multipart_threshold=8 * 1024 * 1024,  # 8MB
        max_concurrency=10,
        multipart_chunksize=8 * 1024 * 1024,  # 8MB
        use_threads=True
    )
    
    # Load performer data
    load_performer_data()
except NoCredentialsError:
    raise ValueError("AWS credentials not found. Ensure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set.")
except Exception as e:
    raise ValueError(f"Error initializing S3 client: {e}")

# Helper function to extract performer_id from filename
def extract_performer_id(filename):
    """
    Extract performer_id from filename with format:
    - performer_id.venue_id.webp (for performer-at-venue images)
    - performer_id.webp (for performer images in performer bucket)
    """
    try:
        # Split the filename by dots
        parts = filename.split('.')
        # First part is always performer_id regardless of format
        if len(parts) >= 1:
            return parts[0]  # First part is performer_id
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
        app.logger.info(f"Adding metadata: {metadata}")
        
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
        
    # Get metadata from source object if it exists
    try:
        head_response = s3_client.head_object(Bucket=source_bucket, Key=original_key)
        metadata = head_response.get('Metadata', {})
    except ClientError as e:
        app.logger.error(f"Error getting metadata for {original_key}: {e}")
        # Initialize with default values
        metadata = {
            'review_status': 'FALSE',
            'perfimg_status': 'FALSE'
        }
        
    # Ensure all metadata fields exist with appropriate defaults
    if 'review_status' not in metadata:
        metadata['review_status'] = 'FALSE'
        
    if 'perfimg_status' not in metadata:
        metadata['perfimg_status'] = 'FALSE'
    
    # Set review_status to TRUE for incredible bucket
    if dest_bucket == S3_INCREDIBLE_BUCKET or destination == 'incredible':
        metadata['review_status'] = 'TRUE'
    
    # If bad_reason provided, add it to metadata
    if bad_reason and (dest_bucket == S3_BAD_BUCKET or destination == 'bad'):
        metadata['bad_reason'] = bad_reason
    
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
    try:
        op_data = _prepare_s3_operation(source_bucket, dest_bucket, object_key, destination, bad_reason)
        
        s3_client.copy_object(
            CopySource=op_data['copy_source'],
            Bucket=dest_bucket,
            Key=op_data['dest_key'],
            ContentType=op_data['content_type'],
            Metadata=op_data['metadata'],
            MetadataDirective='REPLACE'
        )
        app.logger.info(f"Copied {op_data['original_key']} from {source_bucket} to {dest_bucket} as {op_data['dest_key']}")

        if dest_bucket != S3_INCREDIBLE_BUCKET or source_bucket == S3_UPLOAD_BUCKET:
            s3_client.delete_object(Bucket=source_bucket, Key=op_data['original_key'])
            app.logger.info(f"Deleted {op_data['original_key']} from {source_bucket}")
        return True
    except ClientError as e:
        app.logger.error(f"Error moving object {object_key}: {e}")
        flash(f"Error moving file: {e.response['Error']['Message']}", "danger")
    except Exception as e:
        app.logger.error(f"Unexpected error moving object {object_key}: {e}")
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
                    Metadata=current_metadata
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
                    MetadataDirective='REPLACE'
                )
                
                # Update metadata in the good bucket
                s3_client.copy_object(
                    CopySource={'Bucket': source_bucket, 'Key': image_key},
                    Bucket=source_bucket,
                    Key=image_key,
                    Metadata=current_metadata,
                    MetadataDirective='REPLACE',
                    ContentType=content_type
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
                    ContentType=content_type
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
    try:
        op_data = _prepare_s3_operation(source_bucket, dest_bucket, object_key, destination, bad_reason)
        
        s3_client.copy_object(
            CopySource=op_data['copy_source'],
            Bucket=dest_bucket,
            Key=op_data['dest_key'],
            ContentType=op_data['content_type'],
            Metadata=op_data['metadata'],
            MetadataDirective='REPLACE'
        )
        app.logger.info(f"Copied {op_data['original_key']} from {source_bucket} to {dest_bucket} as {op_data['dest_key']}")
        return True
    except ClientError as e:
        app.logger.error(f"Error copying object {object_key}: {e}")
        flash(f"Error copying file: {e.response['Error']['Message']}", "danger")
    except Exception as e:
        app.logger.error(f"Unexpected error copying object {object_key}: {e}")
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
        'performers': {'name': 'Performers Images', 'bucket': S3_PERFORMER_BUCKET, 'prefix': 'images/performers/detail/'}
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
        'performers': {'name': 'Performers Images', 'bucket': S3_PERFORMER_BUCKET, 'prefix': 'images/performers/detail/'}
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
        unreviewed_count = 0  # Initialize counter for unreviewed images

        app.logger.info(f"Starting scan for bucket '{bucket_name}' prefix '{prefix}', max_scan={max_items_to_scan}")
        
        # For performers bucket, special handling if needed
        try_without_prefix = False
        if bucket_name == 'performers':
            try:
                # Check if we have any items with the exact prefix
                test_prefix_response = s3.list_objects_v2(
                    Bucket=bucket_info['bucket'],
                    Prefix=prefix,
                    MaxKeys=5
                )
                
                # Log the complete response to debug
                app.logger.info(f"DEBUG: Prefix search response for '{prefix}': {test_prefix_response}")
                
                # Try to locate the specific 10.webp file
                app.logger.info(f"DEBUG: Checking for 10.webp in bucket {bucket_info['bucket']}")
                # Check with prefix
                file_with_prefix = s3.list_objects_v2(
                    Bucket=bucket_info['bucket'],
                    Prefix=f"{prefix}10.webp",
                    MaxKeys=1
                )
                app.logger.info(f"DEBUG: Search with prefix '{prefix}10.webp' result: {file_with_prefix}")
                
                # Check without prefix
                file_without_prefix = s3.list_objects_v2(
                    Bucket=bucket_info['bucket'],
                    Prefix="10.webp",
                    MaxKeys=1
                )
                app.logger.info(f"DEBUG: Search with just '10.webp' result: {file_without_prefix}")
                
                if 'Contents' not in test_prefix_response or len(test_prefix_response['Contents']) == 0:
                    app.logger.info(f"DEBUG: No objects found with prefix '{prefix}'. Will try without prefix.")
                    try_without_prefix = True
            except Exception as e:
                app.logger.error(f"DEBUG: Error checking prefix: {e}")
        
        # Log debug info for performers bucket
        if bucket_name == 'performers':
            try:
                # Just fetch a list of all objects in bucket without prefix to see what's there
                app.logger.info("DEBUG: Listing all objects in performers bucket:")
                all_objects_response = s3.list_objects_v2(Bucket=bucket_info['bucket'])
                if 'Contents' in all_objects_response:
                    for item in all_objects_response['Contents'][:20]:  # Log first 20 for brevity
                        app.logger.info(f"DEBUG: Found object: {item['Key']}")
                else:
                    app.logger.info("DEBUG: No objects found in performers bucket")
            except Exception as e:
                app.logger.error(f"DEBUG: Error listing all objects: {e}")

        # Scan up to max_items_to_scan or until paginator finishes
        scan_prefix = prefix
        if bucket_name == 'performers':
            # Always use empty prefix for performers bucket to find all files
            scan_prefix = ''
            app.logger.info(f"Using empty prefix for performers bucket scan to find all files")
            
            # Check if the file "10.webp" exists directly in the bucket
            try:
                app.logger.info(f"Special check for '10.webp' in the bucket")
                direct_check = s3.head_object(
                    Bucket=bucket_info['bucket'],
                    Key="10.webp"
                )
                app.logger.info(f"10.webp found directly in bucket: {direct_check}")
                
                # If we found the file, add it to the scanned files directly
                all_scanned_files.append({
                    'key': "10.webp",
                    'size': direct_check.get('ContentLength', 0),
                    'last_modified': direct_check.get('LastModified', datetime.now()),
                    'metadata': direct_check.get('Metadata', {})
                })
                
            except Exception as e:
                app.logger.error(f"Error checking for 10.webp directly: {str(e)}")
        
        for page_obj in s3_paginator.paginate(Bucket=bucket_info['bucket'], Prefix=scan_prefix):
            page_truncated = False
            if 'Contents' in page_obj:
                app.logger.info(f"DEBUG: Found {len(page_obj['Contents'])} items with prefix '{scan_prefix}'")
                
                for item in page_obj['Contents']:
                    if item['Key'] == scan_prefix: # Skip the prefix itself
                        continue
                    
                    # For performers bucket, check if it's an image file
                    if bucket_name == 'performers':
                        # If it doesn't have an extension, skip it
                        file_ext = item['Key'].lower().split('.')[-1] if '.' in item['Key'] else ''
                        if file_ext not in ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp']:
                            continue
                        
                        # For performers bucket, we want to include:
                        # 1. ONLY files with the exact prefix 'images/performers/detail/'
                        if not item['Key'].startswith('images/performers/detail/'):
                            continue
                        
                        app.logger.info(f"Including file in performers bucket: {item['Key']}")
                        
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
        'performers': S3_PERFORMER_BUCKET
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
        'performers': {'name': 'Performers Images', 'bucket': S3_PERFORMER_BUCKET, 'prefix': 'images/performers/detail/'}
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
        'performers': S3_PERFORMER_BUCKET
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
        'issue': S3_ISSUE_BUCKET,
        'performers': S3_PERFORMER_BUCKET
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
        'performers': S3_PERFORMER_BUCKET
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
            ContentType=content_type
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
    # Log session information for debugging
    app.logger.info(f"Perf Review page accessed by user {session.get('user_id', 'unknown')}")
    
    # Use the dedicated function to get performer images
    image_key = get_performer_image_key(filter_by_review='unreviewed')
    source_bucket = S3_PERFORMER_BUCKET
    
    image_url = None
    uploader_initials = "Unknown"
    review_status = "FALSE"
    perfimg_status = "FALSE"
    performer_name = "Unknown Performer"
    
    if image_key:
        image_url = get_presigned_url(source_bucket, image_key)
        app.logger.info(f"Loading unreviewed performer image: {image_key} from {source_bucket}")
        
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
            
            # Extract performer_id from filename (simpler format: performer_id.webp)
            filename = image_key.split('/')[-1]
            performer_id = extract_performer_id(filename)
            
            if performer_id:
                # Look up performer name
                performer_name = get_performer_name(performer_id)
                app.logger.info(f"Found performer name for ID {performer_id}: {performer_name}")
        except Exception as e:
            app.logger.error(f"Error getting metadata for {image_key}: {e}")

    return render_template('perf_review.html', 
                          image_url=image_url, 
                          image_key=image_key, 
                          source_bucket=source_bucket,
                          uploader_initials=uploader_initials,
                          review_status=review_status,
                          perfimg_status=perfimg_status,
                          performer_name=performer_name)

@app.route('/performer_action/<action>/<path:image_key>', methods=['POST'])
@login_required
def performer_action_route(action, image_key):
    if not image_key:
        flash("No image key provided for action.", "danger")
        return redirect(url_for('perf_review_image_route'))

    source_bucket = request.form.get('source_bucket', S3_PERFORMER_BUCKET)
    
    # Log the action
    app.logger.info(f"Performer action: {action} for image with key: {image_key} from {source_bucket}")
    
    try:
        # Get current metadata and content type
        head_response = s3_client.head_object(
            Bucket=source_bucket,
            Key=image_key
        )
        current_metadata = head_response.get('Metadata', {})
        content_type = head_response.get('ContentType', 'image/webp')
        
        # Good action - Mark as reviewed but keep in the same bucket
        if action == 'good':
            # Update metadata
            current_metadata['review_status'] = 'TRUE'
            
            # Ensure other fields are present
            if 'uploader-initials' not in current_metadata:
                current_metadata['uploader-initials'] = 'Unknown'
                
            if 'perfimg_status' not in current_metadata:
                current_metadata['perfimg_status'] = 'FALSE'
            
            # Copy object to itself with updated metadata
            s3_client.copy_object(
                CopySource={'Bucket': source_bucket, 'Key': image_key},
                Bucket=source_bucket,
                Key=image_key,
                ContentType=content_type,
                Metadata=current_metadata,
                MetadataDirective='REPLACE'
            )
            
            app.logger.info(f"Marked {image_key} as reviewed in {source_bucket}")
            flash(f"Image marked as GOOD and reviewed.", "success")
            
        # Bad action - Delete from the performers bucket
        elif action == 'bad':
            # Delete the object
            s3_client.delete_object(
                Bucket=source_bucket,
                Key=image_key
            )
            
            app.logger.info(f"Deleted {image_key} from {source_bucket}")
            flash(f"Image marked as BAD and deleted.", "success")
        
        else:
            flash(f"Invalid action: {action}", "danger")
            
    except Exception as e:
        app.logger.error(f"Error during performer action {action} for {image_key}: {e}")
        flash(f"Error processing action: {str(e)}", "danger")
    
    return redirect(url_for('perf_review_image_route'))

def get_good_image_with_false_perfimg():
    """Gets a random object key from the good bucket where perfimg_status is FALSE."""
    try:
        # Define the specific prefix for good images
        prefix = 'images/performer-at-venue/detail/'
        
        # Get list of objects with the good images prefix
        response = s3_client.list_objects_v2(
            Bucket=S3_GOOD_BUCKET,
            Prefix=prefix
        )
            
        if 'Contents' in response and response['Contents']:
            all_objects = response['Contents']
            
            # Filter to include only images with perfimg_status=FALSE
            eligible_objects = []
            
            for obj in all_objects:
                # Skip the prefix itself or any folder objects
                if obj['Key'] == prefix or obj['Key'].endswith('/'):
                    continue
                
                # Only include image files
                file_ext = obj['Key'].lower().split('.')[-1] if '.' in obj['Key'] else ''
                if file_ext not in ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp']:
                    continue
                
                # Check perfimg_status in metadata
                try:
                    head_response = s3_client.head_object(
                        Bucket=S3_GOOD_BUCKET,
                        Key=obj['Key']
                    )
                    metadata = head_response.get('Metadata', {})
                    perfimg_status = metadata.get('perfimg_status', 'FALSE')
                    
                    # Only include images with perfimg_status=FALSE
                    if perfimg_status != 'TRUE':
                        eligible_objects.append(obj)
                except Exception as e:
                    app.logger.error(f"Error checking metadata for {obj['Key']}: {e}")
                    continue
            
            if eligible_objects:
                return random.choice(eligible_objects)['Key']
    except ClientError as e:
        app.logger.error(f"Error listing objects in Good bucket: {e}")
        flash(f"Error accessing Good bucket: {e.response['Error']['Message']}", "danger")
    except Exception as e:
        app.logger.error(f"Unexpected error listing good objects: {e}")
        flash("An unexpected error occurred while listing good files.", "danger")
    return None

@app.route('/add_perf')
@login_required
def add_perf_review_route():
    # Log session information for debugging
    app.logger.info(f"Add Perf page accessed by user {session.get('user_id', 'unknown')}")
    
    # Get a random image from Good bucket with perfimg_status=FALSE
    image_key = get_good_image_with_false_perfimg()
    source_bucket = S3_GOOD_BUCKET
    
    image_url = None
    uploader_initials = "Unknown"
    review_status = "FALSE"
    perfimg_status = "FALSE"
    performer_name = "Unknown Performer"
    
    if image_key:
        image_url = get_presigned_url(source_bucket, image_key)
        app.logger.info(f"Loading image for Add Perf review: {image_key} from {source_bucket}")
        
        # Get metadata for the image
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

    return render_template('add_perf.html', 
                          image_url=image_url, 
                          image_key=image_key, 
                          source_bucket=source_bucket,
                          uploader_initials=uploader_initials,
                          review_status=review_status,
                          perfimg_status=perfimg_status,
                          performer_name=performer_name)

@app.route('/add_perf_action/<action>/<path:image_key>', methods=['POST'])
@login_required
def add_perf_action_route(action, image_key):
    if not image_key:
        flash("No image key provided for action.", "danger")
        return redirect(url_for('add_perf_review_route'))

    source_bucket = request.form.get('source_bucket', S3_GOOD_BUCKET)
    
    # Log the action
    app.logger.info(f"Add Perf action: {action} for image with key: {image_key} from {source_bucket}")
    
    # Skip action just redirects to load another image
    if action == 'skip':
        return redirect(url_for('add_perf_review_route'))
    
    # Good action - Copy to performers bucket with new name
    if action == 'good':
        try:
            # Get current metadata and content
            head_response = s3_client.head_object(
                Bucket=source_bucket,
                Key=image_key
            )
            current_metadata = head_response.get('Metadata', {})
            content_type = head_response.get('ContentType', 'image/webp')
            
            # Get the object data
            get_response = s3_client.get_object(
                Bucket=source_bucket,
                Key=image_key
            )
            file_data = get_response['Body'].read()
            
            # Extract the filename and extension from the path
            original_filename = image_key.split('/')[-1]
            
            # Extract the perf_id from the original filename (format: perf_id.ven_id.webp)
            filename_parts = original_filename.split('.')
            
            # Default new name in case parsing fails
            new_filename = original_filename
            
            # Try to extract perf_id from format perf_id.ven_id.webp
            if len(filename_parts) >= 3:
                # If filename has at least two dots (perf_id.ven_id.ext)
                perf_id = filename_parts[0]
                file_ext = filename_parts[-1]  # Get the extension
                new_filename = f"{perf_id}.{file_ext}"
            elif len(filename_parts) == 2:
                # If filename has only one dot (perf_id.ext)
                perf_id = filename_parts[0]
                file_ext = filename_parts[-1]
                new_filename = original_filename  # Already in correct format
            
            app.logger.info(f"Renaming image from '{original_filename}' to '{new_filename}'")
            
            # Create the new key for performers bucket
            new_key = f"images/performers/detail/{new_filename}"
            
            # Create or update metadata for the performers bucket
            perf_metadata = current_metadata.copy()
            perf_metadata['original_source'] = f"{source_bucket}/{image_key}"
            perf_metadata['perfimg_status'] = 'TRUE'  # Mark as processed
            perf_metadata['review_status'] = 'TRUE'   # Mark as reviewed
            
            # Upload to performers bucket with new name
            s3_client.put_object(
                Bucket=S3_PERFORMER_BUCKET,
                Key=new_key,
                Body=file_data,
                ContentType=content_type,
                Metadata=perf_metadata
            )
            
            # Update the original image's metadata to mark perfimg_status and review_status as TRUE
            current_metadata['perfimg_status'] = 'TRUE'
            current_metadata['review_status'] = 'TRUE'
            
            s3_client.copy_object(
                CopySource={'Bucket': source_bucket, 'Key': image_key},
                Bucket=source_bucket,
                Key=image_key,
                ContentType=content_type,
                Metadata=current_metadata,
                MetadataDirective='REPLACE'
            )
            
            app.logger.info(f"Copied {image_key} to Performers bucket as {new_key} and updated metadata")
            flash(f"Image successfully added to Performers bucket as '{new_filename}'.", "success")
            
        except Exception as e:
            app.logger.error(f"Error during Add Perf action for {image_key}: {e}")
            flash(f"Error processing action: {str(e)}", "danger")
    
    return redirect(url_for('add_perf_review_route'))

if __name__ == '__main__':
    if not os.path.exists('templates'):
        os.makedirs('templates')
    # For local development
    app.run(debug=True)
    
# Set higher timeout for Gunicorn when running on Heroku
# Usage: gunicorn --timeout 300 app:app