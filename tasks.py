#!/usr/bin/env python3
"""
RQ task wrapper for image generation.

Enqueue with:
    from rq import Queue
    from redis import Redis
    from tasks import generate_performers

    q = Queue(connection=Redis.from_url(os.environ["REDIS_URL"]))
    job = q.enqueue(generate_performers, [118, 106, 72])
"""

import subprocess
from typing import List
from rq import get_current_job #type: ignore
import shlex
import re
import os
import boto3 #type: ignore
from botocore.exceptions import ClientError #type: ignore

# S3 Configuration for problem performers list
S3_RESOURCES_BUCKET = os.getenv("S3_RESOURCES_BUCKET")
PROBLEM_PERFORMERS_FILE_KEY = "temp/problem_performers.txt"

def _get_s3_client(): # Helper to initialize S3 client if needed
    # This could be enhanced to use regional endpoints or specific credentials if necessary
    # For Heroku, if AWS_ACCESS_KEY_ID etc. are in the environment, this should work.
    return boto3.client("s3")

def _update_problem_performers_s3(performer_id_to_add: str):
    if not S3_RESOURCES_BUCKET:
        print(f"TASK_ERROR: S3_RESOURCES_BUCKET env var not set. Cannot update problem performers list for ID {performer_id_to_add}.", flush=True)
        return

    s3_client = _get_s3_client()
    existing_ids = set()

    try:
        response = s3_client.get_object(Bucket=S3_RESOURCES_BUCKET, Key=PROBLEM_PERFORMERS_FILE_KEY)
        file_content = response['Body'].read().decode('utf-8')
        if file_content.strip():
            existing_ids.update(line.strip() for line in file_content.splitlines() if line.strip())
        print(f"TASK_INFO: Found {len(existing_ids)} existing problematic ID(s) in S3.", flush=True)
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            print(f"TASK_INFO: '{PROBLEM_PERFORMERS_FILE_KEY}' not found in S3. A new file will be created.", flush=True)
        else:
            print(f"TASK_ERROR: Could not read existing problematic IDs from S3 for ID {performer_id_to_add}. Details: {e}", flush=True)
            # Decide if we should proceed or not. For now, let's try to write even if read failed non-NoSuchKey
    except Exception as e:
        print(f"TASK_ERROR: Unexpected error reading problematic IDs from S3 for ID {performer_id_to_add}. Details: {e}", flush=True)
        # As above, attempt to write new file with just current ID

    if performer_id_to_add in existing_ids:
        print(f"TASK_INFO: Performer ID {performer_id_to_add} already in problematic list. No update needed.", flush=True)
        return

    existing_ids.add(performer_id_to_add)
    final_ids_list = sorted(list(existing_ids))
    failure_file_content = "\n".join(final_ids_list)

    try:
        s3_client.put_object(
            Bucket=S3_RESOURCES_BUCKET,
            Key=PROBLEM_PERFORMERS_FILE_KEY,
            Body=failure_file_content,
            ContentType='text/plain',
        )
        print(f"TASK_INFO: Successfully updated problematic performers list in S3. Added ID {performer_id_to_add}. Total: {len(final_ids_list)}.", flush=True)
    except Exception as e:
        print(f"TASK_ERROR: Failed to upload updated problematic performer IDs list to S3 for ID {performer_id_to_add}. Details: {e}", flush=True)

def generate_performers(performer_id: int) -> None:
    """
    Call your existing img_generate.py script and update job metadata with progress.
    Now expects a single performer_id.
    """
    job = get_current_job()

    if not isinstance(performer_id, int):
        if job:
            job.meta['current_task_description'] = f"Error: Invalid performer ID type supplied: {type(performer_id)}."
            job.save_meta()
        raise ValueError(f"Invalid performer ID type supplied: {type(performer_id)}")

    # Construct the command arguments for a single ID
    cmd_args = ["python", "img_generate.py", str(performer_id)]
    
    # For logging, create a string representation of the command
    logged_cmd = " ".join(shlex.quote(c) for c in cmd_args)
    print(f"→ Executing: {logged_cmd}", flush=True)

    if job:
        job.meta['progress_lines'] = [] # Initialize a list for progress lines
        job.meta['last_progress_line'] = f"Job initiated for ID: {performer_id}. Waiting for first log line..."
        job.meta['stderr_output'] = "" # Initialize stderr output
        job.meta['failed_generations'] = [] # Initialize list for specific generation failures
        job.save_meta()

    # Using Popen to stream output
    process = subprocess.Popen(
        cmd_args, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE, 
        text=True, 
        bufsize=1, # Line buffered
        universal_newlines=True # Ensures text mode for stdout/stderr
    )

    # Stream stdout
    if process.stdout:
        for line in iter(process.stdout.readline, ''):
            line = line.strip()
            if not line: # Skip empty lines
                continue
            print(line, flush=True) # Log to worker console
            if job:
                # ---- START DEBUG LOGGING ----
                # print(f"TASK_DEBUG: Checking line: '{line}'", flush=True)
                # ---- END DEBUG LOGGING ----
                current_progress_lines = job.meta.get('progress_lines', [])
                current_progress_lines.append(line)
                
                job.meta['progress_lines'] = current_progress_lines
                job.meta['last_progress_line'] = line 
                
                # Check for specific generation failure message
                if line.startswith("❌ Generation failed for"):
                    # ---- START DEBUG LOGGING ----
                    print(f"TASK_DEBUG: Line starts with failure emoji: '{line}'", flush=True)
                    # ---- END DEBUG LOGGING ----
                    match = re.search(r"❌ Generation failed for (.+?) \\(ID: (\\d+)\\): (.*)", line)
                    if match:
                        # ---- START DEBUG LOGGING ----
                        print(f"TASK_DEBUG: Regex MATCHED! Groups: {match.groups()}", flush=True)
                        # ---- END DEBUG LOGGING ----
                        failure_info = {
                            "name": match.group(1).strip(),
                            "id": match.group(2).strip(),
                            "reason": match.group(3).strip()
                        }
                        # ---- START DEBUG LOGGING ----
                        print(f"TASK_DEBUG: Parsed failure_info: {failure_info}", flush=True)
                        # ---- END DEBUG LOGGING ----
                        current_failures = job.meta.get('failed_generations', [])
                        # ---- START DEBUG LOGGING ----
                        # print(f"TASK_DEBUG: current_failures (before append): {current_failures}", flush=True)
                        # ---- END DEBUG LOGGING ----
                        current_failures.append(failure_info)
                        job.meta['failed_generations'] = current_failures
                        # ---- START DEBUG LOGGING ----
                        print(f"TASK_DEBUG: job.meta['failed_generations'] (after append): {job.meta['failed_generations']}", flush=True)
                        # ---- END DEBUG LOGGING ----
                    else:
                        # ---- START DEBUG LOGGING ----
                        print(f"TASK_DEBUG: Line started with emoji BUT regex FAILED to match: '{line}'", flush=True)
                        # ---- END DEBUG LOGGING ----
                
                job.save_meta()
                
                # If failure detected by parsing output, update S3 problem list
                if line.startswith("❌ Generation failed for"):
                    _update_problem_performers_s3(str(performer_id)) # Call S3 update
    
    # Wait for the process to complete and get any remaining output
    stdout_remaining, stderr_output = process.communicate()

    if stdout_remaining:
        for line in stdout_remaining.strip().split('\\n'):
            line = line.strip()
            if not line: continue
            print(line, flush=True)
            if job:
                current_progress_lines = job.meta.get('progress_lines', [])
                current_progress_lines.append(line)
                job.meta['progress_lines'] = current_progress_lines
                job.meta['last_progress_line'] = line

                # Check for specific generation failure message in remaining output
                if line.startswith("❌ Generation failed for"):
                    # ---- START DEBUG LOGGING ----
                    print(f"TASK_DEBUG (REMAINING_OUTPUT): Line starts with failure emoji: '{line}'", flush=True)
                    # ---- END DEBUG LOGGING ----
                    match = re.search(r"❌ Generation failed for (.+?) \\(ID: (\\d+)\\): (.*)", line)
                    if match:
                        # ---- START DEBUG LOGGING ----
                        print(f"TASK_DEBUG (REMAINING_OUTPUT): Regex MATCHED! Groups: {match.groups()}", flush=True)
                        # ---- END DEBUG LOGGING ----
                        failure_info = {
                            "name": match.group(1).strip(),
                            "id": match.group(2).strip(),
                            "reason": match.group(3).strip()
                        }
                        # ---- START DEBUG LOGGING ----
                        print(f"TASK_DEBUG (REMAINING_OUTPUT): Parsed failure_info: {failure_info}", flush=True)
                        # ---- END DEBUG LOGGING ----
                        current_failures = job.meta.get('failed_generations', [])
                        current_failures.append(failure_info)
                        job.meta['failed_generations'] = current_failures
                        # ---- START DEBUG LOGGING ----
                        print(f"TASK_DEBUG (REMAINING_OUTPUT): job.meta['failed_generations'] (after append): {job.meta['failed_generations']}", flush=True)
                        # ---- END DEBUG LOGGING ----
                    else:
                        # ---- START DEBUG LOGGING ----
                        print(f"TASK_DEBUG (REMAINING_OUTPUT): Line started with emoji BUT regex FAILED to match: '{line}'", flush=True)
                        # ---- END DEBUG LOGGING ----
                
                job.save_meta()

                # If failure detected by parsing output (in remaining stdout), update S3 problem list
                if line.startswith("❌ Generation failed for"):
                    _update_problem_performers_s3(str(performer_id)) # Call S3 update

    final_stderr = ""
    if stderr_output:
        final_stderr = stderr_output.strip()
        if final_stderr:
            print(f"STDERR OUTPUT:\\n{final_stderr}", flush=True)
            if job:
                job.meta['stderr_output'] = final_stderr
                job.save_meta()

    if process.returncode != 0:
        error_message = f"Error during generation for ID: {performer_id}. Exit code: {process.returncode}."
        if final_stderr:
            error_message += f" Stderr: {final_stderr[:250]}..." # Add a snippet of stderr
        if job:
            job.meta['current_task_description'] = error_message
            job.meta['last_progress_line'] = error_message # Show error as last progress
            job.save_meta()
        # If process failed (non-zero exit code), update S3 problem list
        _update_problem_performers_s3(str(performer_id)) # Call S3 update
        raise subprocess.CalledProcessError(process.returncode, cmd_args, output=stdout_remaining, stderr=final_stderr)
    
    if job:
        success_message = f"Successfully completed generation for ID: {performer_id}"
        job.meta['current_task_description'] = success_message
        # The last line from stdout should already be in 'last_progress_line'
        # If not, or if we want to ensure a completion message:
        # job.meta['last_progress_line'] = "Processing complete." 
        job.save_meta()