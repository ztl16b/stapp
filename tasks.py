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

def generate_performers(ids: List[int]) -> None:
    """
    Call your existing img_generate.py script and update job metadata with progress.
    """
    job = get_current_job()

    if not ids:
        if job:
            job.meta['current_task_description'] = "Error: No performer IDs supplied."
            job.save_meta()
        raise ValueError("No performer IDs supplied")

    # Construct the command arguments
    cmd_args = ["python", "img_generate.py"] + [str(pid) for pid in ids]
    
    # For logging, create a string representation of the command
    logged_cmd = " ".join(shlex.quote(c) for c in cmd_args)
    print(f"→ Executing: {logged_cmd}", flush=True)

    if job:
        job.meta['current_task_description'] = f"Starting generation for IDs: {', '.join(map(str, ids))}"
        job.meta['progress_lines'] = [] # Initialize a list for progress lines
        job.meta['last_progress_line'] = "Job starting..."
        job.meta['stderr_output'] = "" # Initialize stderr output
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
                current_progress_lines = job.meta.get('progress_lines', [])
                current_progress_lines.append(line)
                
                job.meta['progress_lines'] = current_progress_lines
                job.meta['last_progress_line'] = line 
                job.save_meta()
    
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
                job.save_meta()

    final_stderr = ""
    if stderr_output:
        final_stderr = stderr_output.strip()
        if final_stderr:
            print(f"STDERR OUTPUT:\\n{final_stderr}", flush=True)
            if job:
                job.meta['stderr_output'] = final_stderr
                job.save_meta()

    if process.returncode != 0:
        error_message = f"Error during generation for IDs: {', '.join(map(str, ids))}. Exit code: {process.returncode}."
        if final_stderr:
            error_message += f" Stderr: {final_stderr[:250]}..." # Add a snippet of stderr
        if job:
            job.meta['current_task_description'] = error_message
            job.meta['last_progress_line'] = error_message # Show error as last progress
            job.save_meta()
        raise subprocess.CalledProcessError(process.returncode, cmd_args, output=stdout_remaining, stderr=final_stderr)
    
    if job:
        success_message = f"Successfully completed generation for IDs: {', '.join(map(str, ids))}"
        job.meta['current_task_description'] = success_message
        # The last line from stdout should already be in 'last_progress_line'
        # If not, or if we want to ensure a completion message:
        # job.meta['last_progress_line'] = "Processing complete." 
        job.save_meta()