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
import concurrent.futures
import threading
import psutil

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

BYTESCALE_API_KEY = os.getenv("BYTESCALE_API_KEY")
BYTESCALE_UPLOAD_URL = os.getenv("BYTESCALE_UPLOAD_URL")

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
BROWSE_PASSWORD = os.getenv("BROWSE_PASSWORD")

# Threading lock for thread-safe operations
upload_lock = threading.Lock()

# Thread-local storage for session data
thread_local = threading.local()

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

try:
    s3_client = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )
except NoCredentialsError:
    raise ValueError("AWS credentials not found. Ensure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set.")
except Exception as e:
    raise ValueError(f"Error initializing S3 client: {e}")

@app.route('/')
def index():
    return redirect(url_for('upload'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'files' not in request.files:
            flash('No files part', 'warning')
            return redirect(request.url)
            
        files = request.files.getlist('files')
        if not files or all(file.filename == '' for file in files):
            flash('No selected files', 'warning')
            return redirect(request.url)
        
        # Limit number of files processed at once to prevent crashes
        max_files_per_batch = 300
        
        # Process files directly, but with better handling
        successful_uploads = []
        failed_uploads = []
        skipped_files = []
        
        # Calculate total number of files
        total_files = len(files)
        app.logger.info(f"Upload started with {total_files} files")
        
        # Check if we need to limit the batch
        if total_files > max_files_per_batch:
            files_to_process = files[:max_files_per_batch]
            skipped_files = [f.filename for f in files[max_files_per_batch:]]
            flash(f'Processing the first {max_files_per_batch} files. The remaining {total_files - max_files_per_batch} files will be skipped.', 'warning')
        else:
            files_to_process = files
        
        # Set a larger timeout for requests to external services
        processing_timeout = 240  # 4 minutes
        
        # Prepare the files for processing
        file_data_list = []
        for file in files_to_process:
            try:
                # Apply size limit (5MB)
                content_length = getattr(file, 'content_length', None) or 0
                if content_length and content_length > 5 * 1024 * 1024:
                    failed_uploads.append((file.filename, "File exceeds 5MB size limit"))
                    continue
                
                # Read file data
                file_data = file.read()
                
                # Skip empty files
                if not file_data:
                    failed_uploads.append((file.filename, "Empty file"))
                    continue
                
                filename = secure_filename(file.filename)  # Sanitize filename
                content_type = file.content_type
                
                # Add to list of files to process
                file_data_list.append((file_data, filename, content_type))
            except Exception as e:
                app.logger.error(f"Error preparing file {file.filename}: {str(e)}")
                failed_uploads.append((file.filename, f"Error preparing file: {str(e)}"))
        
        # Determine optimal thread count based on system resources
        # On Heroku, we should limit threads to avoid overwhelming the dyno
        cpu_count = psutil.cpu_count(logical=True) or 4
        available_memory_mb = psutil.virtual_memory().available / (1024 * 1024)
        
        # Calculate thread count based on available resources
        # Each thread might use ~100MB of memory for processing
        memory_based_threads = max(1, int(available_memory_mb / 100))
        
        # Use the lower of CPU count or memory-based thread count
        # Never use more than 10 threads on Heroku
        optimal_thread_count = min(cpu_count, memory_based_threads, 10)
        
        # For small batches, don't use more threads than files
        thread_count = min(optimal_thread_count, len(file_data_list))
        
        app.logger.info(f"Processing with {thread_count} threads (CPU: {cpu_count}, Memory: {int(available_memory_mb)}MB available)")
        
        # Function to process a file with proper exception handling
        def process_file_task(file_tuple):
            file_data, filename, content_type = file_tuple
            try:
                # Process the image with increased timeout
                result = process_image(file_data, filename, content_type, timeout=processing_timeout)
                
                # Free memory
                del file_data
                
                # Return result with filename for identification
                return (filename, result)
            except Exception as e:
                app.logger.error(f"Unhandled exception in thread processing {filename}: {str(e)}")
                return (filename, {
                    'status': 'error',
                    'message': f'Thread error: {str(e)}',
                    'filename': filename
                })
        
        # Use thread pool for concurrent processing
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
            # Submit all tasks
            future_to_filename = {
                executor.submit(process_file_task, file_tuple): file_tuple[1] 
                for file_tuple in file_data_list
            }
            
            # Process completed tasks as they finish
            for i, future in enumerate(concurrent.futures.as_completed(future_to_filename)):
                filename = future_to_filename[future]
                try:
                    result_filename, result = future.result()
                    results.append((result_filename, result))
                    
                    # Log progress periodically
                    if (i + 1) % 10 == 0 or i == len(file_data_list) - 1:
                        app.logger.info(f"Progress: {i + 1}/{len(file_data_list)} files processed")
                    
                except Exception as e:
                    app.logger.error(f"Error getting result for {filename}: {str(e)}")
                    failed_uploads.append((filename, f"Thread execution error: {str(e)}"))
        
        # Process results
        for filename, result in results:
            if result['status'] == 'success':
                successful_uploads.append(filename)
            else:
                failed_uploads.append((filename, result['message']))
        
        # Force garbage collection after processing
        import gc
        gc.collect()
        
        # Final log of results
        app.logger.info(f"Upload complete: {len(successful_uploads)} successful, {len(failed_uploads)} failed, {len(skipped_files)} skipped")
        
        # Flash messages about the results
        if successful_uploads:
            flash(f'Successfully processed {len(successful_uploads)} files.', 'success')
        
        if failed_uploads:
            failure_count = len(failed_uploads)
            # Show first 5 errors with details
            for filename, error in failed_uploads[:5]:
                flash(f'Failed to process {filename}: {error}', 'error')
            
            # For larger batches, summarize remaining errors
            if failure_count > 5:
                flash(f'... and {failure_count - 5} more files failed. Check logs for details.', 'error')
        
        if skipped_files:
            flash(f'Skipped {len(skipped_files)} files due to batch size limit. Please upload them separately.', 'warning')
        
        return redirect(url_for('upload'))
        
    return render_template('upload.html')

def process_image(file_data, filename, content_type, timeout=60):
    """
    Process an image using Bytescale API and upload to S3.
    
    Args:
        file_data: The file data as bytes
        filename: The original filename
        content_type: The content type of the file
        timeout: Timeout for external API requests
        
    Returns:
        dict: Status information about the processing
    """
    start_time = time.time()
    try:
        app.logger.info(f"Processing image: {filename} ({len(file_data)/1024:.1f} KB)")
        
        # Validate file size again (5MB limit)
        if len(file_data) > 5 * 1024 * 1024:
            return {
                'status': 'error',
                'message': 'File size exceeds the 5MB limit',
                'filename': filename
            }
        
        # Quick validation of file type by checking first few bytes (magic numbers)
        # This avoids doing expensive operations on non-image files
        valid_image_signatures = {
            b'\xff\xd8\xff': 'JPEG',
            b'\x89\x50\x4e\x47': 'PNG',
            b'\x47\x49\x46': 'GIF',
            b'\x42\x4d': 'BMP',
            b'\x52\x49\x46\x46': 'WEBP'
        }
        
        is_valid_image = False
        for signature in valid_image_signatures:
            if file_data.startswith(signature):
                is_valid_image = True
                break
                
        if not is_valid_image:
            return {
                'status': 'error',
                'message': 'Invalid image format. Only JPEG, PNG, GIF, BMP and WEBP are supported.',
                'filename': filename
            }
        
        # Set up headers and files for the Bytescale API
        headers = {
            'Authorization': f'Bearer {BYTESCALE_API_KEY}'
        }
        files_data = {
            'file': (filename, file_data, content_type)
        }
        
        # Track timing of each step for performance analysis
        steps_timing = {}
        
        # Upload to Bytescale with configurable timeout
        app.logger.info(f"Uploading {filename} to Bytescale")
        upload_start = time.time()
        
        # Use thread-local session for better isolation between threads
        def get_thread_local_session():
            if not hasattr(thread_local, 'session'):
                thread_local.session = requests.Session()
                # Configure session timeouts and retries
                thread_local.session.mount('https://', requests.adapters.HTTPAdapter(
                    max_retries=3,
                    pool_connections=10,
                    pool_maxsize=10
                ))
            return thread_local.session
        
        # Get thread-local session
        session = get_thread_local_session()
        
        # Upload to Bytescale
        try:
            upload_response = session.post(
                BYTESCALE_UPLOAD_URL, 
                headers=headers, 
                files=files_data, 
                timeout=timeout
            )
            upload_response.raise_for_status()
        except Exception as e:
            app.logger.error(f"Bytescale upload failed for {filename}: {str(e)}")
            return {
                'status': 'error',
                'message': f'Bytescale API Error: {str(e)}',
                'filename': filename
            }
        
        steps_timing['bytescale_upload'] = time.time() - upload_start
        
        # Parse response to get file URL
        try:
            json_response = upload_response.json()
            file_url = None
            for file_obj in json_response.get("files", []):
                if file_obj.get("formDataFieldName") == "file":
                    file_url = file_obj.get("fileUrl")
                    break
        except Exception as e:
            app.logger.error(f"Failed to parse Bytescale response for {filename}: {str(e)}")
            return {
                'status': 'error',
                'message': f'Failed to parse API response: {str(e)}',
                'filename': filename
            }
        
        if not file_url:
            return {
                'status': 'error',
                'message': 'Could not find file URL in Bytescale response',
                'filename': filename
            }
        
        # We don't need the original file data anymore
        del file_data
        del files_data
        
        # Download the processed image
        app.logger.info(f"Downloading processed image for {filename}")
        download_start = time.time()
        processed_url = file_url.replace("/raw/", "/image/") + "?f=webp&w=464&h=510&fit=crop&crop=center"
        
        # Download the processed image with configurable timeout
        try:
            download_response = session.get(processed_url, stream=True, timeout=timeout)
            download_response.raise_for_status()
        except Exception as e:
            app.logger.error(f"Failed to download processed image for {filename}: {str(e)}")
            return {
                'status': 'error',
                'message': f'Download Error: {str(e)}',
                'filename': filename
            }
            
        steps_timing['download'] = time.time() - download_start
        
        # Upload to S3
        app.logger.info(f"Uploading {filename} to S3")
        s3_upload_start = time.time()
        upload_path = f"temp_performer_at_venue_images/{filename.rsplit('.', 1)[0]}.webp"
        
        # Create thread-local S3 client if needed
        # This prevents S3 connection issues when multiple threads are uploading
        def get_thread_local_s3_client():
            if not hasattr(thread_local, 's3_client'):
                thread_local.s3_client = boto3.client(
                    's3',
                    aws_access_key_id=AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                    region_name=AWS_REGION
                )
            return thread_local.s3_client
        
        # Get thread-local S3 client
        s3_client_thread = get_thread_local_s3_client()
        
        # Optimized S3 upload configuration for better performance
        s3_config = boto3.s3.transfer.TransferConfig(
            multipart_threshold=8 * 1024 * 1024,  # 8MB
            max_concurrency=10,
            multipart_chunksize=8 * 1024 * 1024,  # 8MB
            use_threads=True
        )
        
        try:
            with upload_lock:  # Use lock for thread safety with S3 operations
                s3_client_thread.upload_fileobj(
                    download_response.raw,
                    S3_UPLOAD_BUCKET,
                    upload_path,
                    ExtraArgs={'ContentType': 'image/webp'},
                    Config=s3_config
                )
        except Exception as e:
            app.logger.error(f"S3 upload failed for {filename}: {str(e)}")
            return {
                'status': 'error',
                'message': f'S3 Upload Error: {str(e)}',
                'filename': filename
            }
        
        steps_timing['s3_upload'] = time.time() - s3_upload_start
    
    total_time = time.time() - start_time
    app.logger.info(f"Successfully processed {filename} in {total_time:.2f}s (Bytescale: {steps_timing.get('bytescale_upload', 0):.2f}s, Download: {steps_timing.get('download', 0):.2f}s, S3: {steps_timing.get('s3_upload', 0):.2f}s)")
    
    return {
        'status': 'success',
        'message': f'Successfully processed and uploaded {filename}',
        's3_path': upload_path,
        'filename': filename,
        'timing': steps_timing,
        'total_time': total_time
    }
    
except RequestException as e:
    app.logger.error(f"Network error processing {filename}: {e}")
    return {
        'status': 'error',
        'message': f'Network Error: {str(e)}',
        'filename': filename
    }
except ClientError as e:
    app.logger.error(f"S3 upload error for {filename}: {e}")
    return {
        'status': 'error',
        'message': f'S3 Upload Error: {str(e)}',
        'filename': filename
    }
except NoCredentialsError:
    app.logger.error(f"AWS credentials not found when processing {filename}")
    return {
        'status': 'error',
        'message': 'AWS credentials not found',
        'filename': filename
    }
except Exception as e:
    app.logger.error(f"Unexpected error processing {filename}: {e}")
    return {
        'status': 'error',
        'message': f'Unexpected error: {str(e)}',
        'filename': filename
    }

def get_random_image_key(bucket_name):
    """Gets a random object key from the specified bucket."""
    try:
        if bucket_name == S3_UPLOAD_BUCKET:
            response = s3_client.list_objects_v2(
                Bucket=bucket_name,
                Prefix='temp_performer_at_venue_images/'
            )
        else:
            response = s3_client.list_objects_v2(Bucket=bucket_name)
            
        if 'Contents' in response:
            all_objects = response['Contents']
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
    
    if destination == 'bad' or (dest_bucket == S3_BAD_BUCKET and destination is None):
        if object_key.startswith('temp_performer_at_venue_images/'):
            object_key = object_key.replace('temp_performer_at_venue_images/', '', 1)
        dest_key = f"bad_images/{object_key}"
    elif destination == 'good' or (dest_bucket == S3_GOOD_BUCKET and destination is None):
        if object_key.startswith('temp_performer_at_venue_images/'):
            object_key = object_key.replace('temp_performer_at_venue_images/', '', 1)
        dest_key = f"images/performer-at-venue/detail/{object_key}"
    elif destination == 'incredible' or (dest_bucket == S3_INCREDIBLE_BUCKET and destination is None):
        if object_key.startswith('temp_performer_at_venue_images/'):
            object_key = object_key.replace('temp_performer_at_venue_images/', '', 1)
        dest_key = f"incredible_images/{object_key}"
    
    copy_source = {'Bucket': source_bucket, 'Key': original_key}
    try:
        extra_args = {'ContentType': 'image/webp' if object_key.endswith('.webp') else 'image/jpeg'}
            
        s3_client.copy_object(
            CopySource=copy_source,
            Bucket=dest_bucket,
            Key=dest_key,
            **extra_args
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
    app.logger.info(f"Session data: logged_in={session.get('logged_in')}, login_time={session.get('login_time')}")
    
    image_key = get_random_image_key(S3_UPLOAD_BUCKET)
    image_url = None
    if image_key:
        image_url = get_presigned_url(S3_UPLOAD_BUCKET, image_key)
        # Print image key to console for debugging
        app.logger.info(f"Loading image for review: {image_key}")

    return render_template('review.html', image_url=image_url, image_key=image_key)

@app.route('/move/<action>/<path:image_key>', methods=['POST'])
@login_required
def move_image_route(action, image_key):
    if not image_key:
        flash("No image key provided for move operation.", "danger")
        return redirect(url_for('review_image_route'))

    # Print image key to console for debugging
    app.logger.info(f"Moving image with key: {image_key} to {action} bucket")

    success = False
    if action == 'incredible':
        # For incredible images, we need to copy to both buckets without deleting the original
        # until both copies are successful
        
        # First, copy to the good bucket without deleting the original
        if copy_s3_object(S3_UPLOAD_BUCKET, S3_GOOD_BUCKET, image_key, destination='good'):
            # If first copy succeeds, copy to incredible bucket
            if copy_s3_object(S3_UPLOAD_BUCKET, S3_INCREDIBLE_BUCKET, image_key, destination='incredible'):
                # Now that both copies are successful, delete the original
                try:
                    s3_client.delete_object(Bucket=S3_UPLOAD_BUCKET, Key=image_key)
                    app.logger.info(f"Deleted {image_key} from {S3_UPLOAD_BUCKET} after successful copies")
                    success = True
                    flash(f"Image '{image_key}' moved to both good and incredible buckets.", "success")
                except Exception as e:
                    app.logger.error(f"Error deleting original file after copies: {e}")
                    flash("Image copied successfully but there was an error deleting the original.", "warning")
                    success = True
    else:
        # For good and bad actions, use the original logic
        destination_bucket = S3_GOOD_BUCKET if action == 'good' else S3_BAD_BUCKET
        if move_s3_object(S3_UPLOAD_BUCKET, destination_bucket, image_key, destination=action):
            success = True
            flash(f"Image '{image_key}' moved to {action} bucket.", "success")

    if not success:
        pass

    return redirect(url_for('review_image_route'))

def copy_s3_object(source_bucket, dest_bucket, object_key, destination=None):
    """Copies an object from source_bucket to dest_bucket without deleting the original."""
    dest_key = object_key
    original_key = object_key
    
    if destination == 'bad' or (dest_bucket == S3_BAD_BUCKET and destination is None):
        if object_key.startswith('temp_performer_at_venue_images/'):
            object_key = object_key.replace('temp_performer_at_venue_images/', '', 1)
        dest_key = f"bad_images/{object_key}"
    elif destination == 'good' or (dest_bucket == S3_GOOD_BUCKET and destination is None):
        if object_key.startswith('temp_performer_at_venue_images/'):
            object_key = object_key.replace('temp_performer_at_venue_images/', '', 1)
        dest_key = f"images/performer-at-venue/detail/{object_key}"
    elif destination == 'incredible' or (dest_bucket == S3_INCREDIBLE_BUCKET and destination is None):
        if object_key.startswith('temp_performer_at_venue_images/'):
            object_key = object_key.replace('temp_performer_at_venue_images/', '', 1)
        dest_key = f"incredible_images/{object_key}"
    
    copy_source = {'Bucket': source_bucket, 'Key': original_key}
    try:
        extra_args = {'ContentType': 'image/webp' if object_key.endswith('.webp') else 'image/jpeg'}
            
        s3_client.copy_object(
            CopySource=copy_source,
            Bucket=dest_bucket,
            Key=dest_key,
            **extra_args
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
    
    buckets = {
        'good': {'name': 'Good Images', 'bucket': S3_GOOD_BUCKET, 'prefix': 'images/performer-at-venue/detail/'},
        'bad': {'name': 'Bad Images', 'bucket': S3_BAD_BUCKET, 'prefix': 'bad_images/'},
        'incredible': {'name': 'Incredible Images', 'bucket': S3_INCREDIBLE_BUCKET, 'prefix': 'incredible_images/'},
        'upload': {'name': 'Upload Images', 'bucket': S3_UPLOAD_BUCKET, 'prefix': 'temp_performer_at_venue_images/'}
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
        'upload': {'name': 'Upload Images', 'bucket': S3_UPLOAD_BUCKET, 'prefix': 'temp_performer_at_venue_images/'}
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
        'upload': S3_UPLOAD_BUCKET
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
        'upload': {'name': 'Upload Images', 'bucket': S3_UPLOAD_BUCKET, 'prefix': 'temp_performer_at_venue_images/'}
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