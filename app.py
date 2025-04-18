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
import pandas as pd

load_dotenv()

# Get the absolute path to the templates directory
template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
app = Flask(__name__, template_folder=template_dir)

# Set a fixed secret key for session management
app.secret_key = os.environ.get('SECRET_KEY', 'your-fixed-secret-key-for-development')

# Define MST timezone (UTC-7)
MST = ZoneInfo("Etc/GMT+7")

# Global performer data mapping
PERFORMER_DATA = {}

def load_performer_data():
    """Load performer data from CSV file."""
    global PERFORMER_DATA
    csv_path = os.environ.get('PERFORMER_CSV_PATH', 'performer_data.csv')
    
    if not os.path.exists(csv_path):
        app.logger.warning(f"Performer CSV file not found at: {csv_path}")
        return
    
    try:
        # Read the CSV file and create a mapping of performer_id to name_alias
        df = pd.read_csv(csv_path)
        for _, row in df.iterrows():
            performer_id = str(row.get('performer_id', '')).strip()
            name_alias = str(row.get('name_alias', '')).strip()
            if performer_id and name_alias:
                PERFORMER_DATA[performer_id] = name_alias
        
        app.logger.info(f"Loaded {len(PERFORMER_DATA)} performer records from CSV")
    except Exception as e:
        app.logger.error(f"Error loading performer data: {e}")

# Load performer data at startup
load_performer_data()

def get_performer_name(filename):
    """Extract performer ID from filename and look up the name."""
    try:
        # Extract performer_id from the filename
        # Format is typically {performer_id}.{venue_id}.webp
        if not filename:
            return "Unknown"
            
        # Extract just the filename without the path
        if '/' in filename:
            filename = filename.split('/')[-1]
            
        parts = filename.split('.')
        if len(parts) >= 2:
            performer_id = parts[0]
            return PERFORMER_DATA.get(performer_id, f"Unknown ({performer_id})")
        return "Unknown format"
    except Exception as e:
        app.logger.error(f"Error getting performer name for {filename}: {e}")
        return "Error"

# ... existing code ...

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
app.jinja_env.filters['get_performer_name'] = get_performer_name

# ... existing code ...

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
    performer_name = "Unknown"
    
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
            
            # Get performer name from filename
            filename = image_key.split('/')[-1]
            performer_name = get_performer_name(filename)
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
    performer_name = "Unknown"
    
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
            
            # Get performer name from filename
            filename = image_key.split('/')[-1]
            performer_name = get_performer_name(filename)
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
    performer_name = "Unknown"
    
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
            
            # Get performer name from filename
            filename = image_key.split('/')[-1]
            performer_name = get_performer_name(filename)
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

@app.route('/browse/<bucket_name>')
@login_required
def browse_bucket(bucket_name):
    # ... existing code ...

    # After preparing the files for display, add performer info to each file
    for file in current_page_files:
        # Extract just the filename without the path
        filename = file['key'].split('/')[-1]
        file['performer_name'] = get_performer_name(filename)

    # ... rest of the function ...
    
    # Update the return statement to include all variables
    return render_template('browse_bucket.html',
                         bucket=bucket_info,
                         bucket_name=bucket_name,
                         files=current_page_files,
                         current_page=page,
                         total_pages=total_pages,
                         total_files=total_files,
                         total_files_estimate=total_files_estimate,
                         per_page=per_page,
                         search_query=request.args.get('search', ''),
                         uploader_filter=uploader_filter_display,
                         sort_order=sort_order,
                         date_from=date_from,
                         date_to=date_to,
                         unreviewed_count=unreviewed_count)

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
        
        # Get performer name from filename
        filename = object_key.split('/')[-1]
        performer_name = get_performer_name(filename)
        
        # If it's a thumbnail request, redirect to the presigned URL
        if is_thumbnail:
            return redirect(presigned_url)
        
        # For full image view, display in a simple HTML page
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Image Preview - {performer_name}</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {{ margin: 0; padding: 20px; text-align: center; background-color: #333; }}
                .image-container {{ max-width: 100%; height: 90vh; display: flex; justify-content: center; align-items: center; }}
                img {{ max-width: 100%; max-height: 100%; object-fit: contain; }}
                .filename {{ color: white; margin-bottom: 20px; font-family: Arial, sans-serif; }}
                .performer {{ color: #ffcc00; font-weight: bold; margin-bottom: 10px; font-family: Arial, sans-serif; }}
            </style>
        </head>
        <body>
            <div class="performer">{performer_name}</div>
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

@app.route('/reload-performer-data')
@login_required
def reload_performer_data():
    """Admin route to reload performer data from CSV."""
    try:
        load_performer_data()
        flash(f"Successfully reloaded {len(PERFORMER_DATA)} performer records", "success")
    except Exception as e:
        flash(f"Error reloading performer data: {str(e)}", "danger")
    
    return redirect(url_for('browse_buckets'))

# ... rest of the code ...