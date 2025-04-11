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
import ssl
from celery import Celery
import uuid
import time

load_dotenv()

# Get the absolute path to the templates directory
template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
app = Flask(__name__, template_folder=template_dir)

# Generate a consistent secret key from environment or use a default for development
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    # Generate a random key for development
    app.secret_key = os.urandom(24)
    app.logger.warning('No SECRET_KEY set in environment. Using random key - sessions will not persist across restarts!')

# Determine if we're running on Heroku
is_heroku = os.environ.get('DYNO') is not None

# Session configuration optimized for Heroku
app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),  # 7 day sessions
    SESSION_COOKIE_SECURE=is_heroku,  # Only use secure cookies on Heroku (HTTPS)
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_NAME='image_interface_session',
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max file size
    # Disable Flask's default permanent session feature
    PERMANENT_SESSIONS=False
)

# Dictionary to store upload status
upload_status = {}

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
            # Set up session
            session.clear()
            session['logged_in'] = True
            session['login_time'] = datetime.now().isoformat()
            session['user_id'] = str(uuid.uuid4())
            
            # Log successful login
            app.logger.info(f"Successful login - User ID: {session['user_id']}")
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

required_env_vars = [
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION",
    "S3_UPLOAD_BUCKET", "S3_GOOD_BUCKET", "S3_BAD_BUCKET"
]
missing_vars = [var for var in required_env_vars if not os.getenv(var)]
if missing_vars:
    raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

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
        
        # Store file information for processing
        task_ids = []
        
        for file in files:
            # Read file data
            file_data = file.read()
            filename = file.filename
            content_type = file.content_type
            
            # Submit task to Celery
            task = process_image.delay(file_data, filename, content_type)
            task_ids.append(task.id)
            
            # Initialize status for this task
            upload_status[task.id] = {
                'status': 'PENDING',
                'filename': filename,
                'message': 'Task queued'
            }
        
        # Store task IDs in session for status checking
        session['upload_task_ids'] = task_ids
        
        flash(f'{len(files)} files queued for processing. You can check the status below.', 'info')
        return redirect(url_for('upload_status'))
        
    return render_template('upload.html')

@app.route('/upload-status')
def upload_status_route():
    task_ids = session.get('upload_task_ids', [])
    tasks = []
    
    for task_id in task_ids:
        if task_id in upload_status:
            task_info = upload_status[task_id]
            
            # If task is still pending, check its status
            if task_info['status'] == 'PENDING':
                task = celery.AsyncResult(task_id)
                
                if task.ready():
                    result = task.result
                    if result['status'] == 'success':
                        task_info['status'] = 'SUCCESS'
                        task_info['message'] = result['message']
                    else:
                        task_info['status'] = 'FAILED'
                        task_info['message'] = result['message']
                elif task.state == 'PROCESSING':
                    task_info['status'] = 'PROCESSING'
                    task_info['message'] = task.info.get('status', 'Processing')
            
            tasks.append({
                'id': task_id,
                'filename': task_info['filename'],
                'status': task_info['status'],
                'message': task_info['message']
            })
    
    return render_template('upload_status.html', tasks=tasks)

@app.route('/check-upload-status')
def check_upload_status():
    task_ids = session.get('upload_task_ids', [])
    tasks = []
    
    for task_id in task_ids:
        if task_id in upload_status:
            task_info = upload_status[task_id]
            
            # If task is still pending, check its status
            if task_info['status'] == 'PENDING':
                task = celery.AsyncResult(task_id)
                
                if task.ready():
                    result = task.result
                    if result['status'] == 'success':
                        task_info['status'] = 'SUCCESS'
                        task_info['message'] = result['message']
                    else:
                        task_info['status'] = 'FAILED'
                        task_info['message'] = result['message']
                elif task.state == 'PROCESSING':
                    task_info['status'] = 'PROCESSING'
                    task_info['message'] = task.info.get('status', 'Processing')
            
            tasks.append({
                'id': task_id,
                'filename': task_info['filename'],
                'status': task_info['status'],
                'message': task_info['message']
            })
    
    return jsonify({'tasks': tasks})

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
        date_to = request.args.get('date_to', '')      # Date filter to
        per_page = 100  # Reduced from 500 to 100 for better performance
        
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
    app.run(debug=True)