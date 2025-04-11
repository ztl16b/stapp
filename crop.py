import os
import json
import requests
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

load_dotenv()
API_KEY = os.getenv("BYTESCALE_API_KEY")
UPLOAD_URL = os.getenv("BYTESCALE_UPLOAD_URL")

SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")
SLACK_CHANNEL = os.getenv("SLACK_CHANNEL")

lock = threading.Lock()
counter = 1 

def process_single_image(filename, input_folder, output_folder, text_file_path, headers):
    global counter
    file_path = os.path.join(input_folder, filename)
    try:
        with open(file_path, "rb") as image_file:
            files = {"file": image_file}
            response = requests.post(UPLOAD_URL, headers=headers, files=files)
        
        if response.ok:
            json_response = response.json()
            file_url = None
            for file_obj in json_response.get("files", []):
                if file_obj.get("formDataFieldName") == "file":
                    file_url = file_obj.get("fileUrl")
                    break
            if not file_url:
                with lock:
                    current_count = counter
                    counter += 1
                print(f"Error: file_url not found in response for {filename}   |   [{current_count}]")
                return

            processed_url = file_url.replace("/raw/", "/image/") + "?f=webp&w=464&h=510&fit=crop&crop=smart"
            download_response = requests.get(processed_url)
            if download_response.ok:
                base_name = os.path.splitext(filename)[0].replace("-", ".")
                output_filename = base_name + ".webp"
                output_path = os.path.join(output_folder, output_filename)
                with open(output_path, "wb") as out_file:
                    out_file.write(download_response.content)
                
                with lock:
                    with open(text_file_path, "a") as f:
                        f.write(output_filename + "\n")
                    current_count = counter
                    counter += 1
                print(f"[{filename}] --> [{output_filename}]      [{current_count}]")
            else:
                with lock:
                    current_count = counter
                    counter += 1
                print(f"Error downloading processed image for {filename}: {download_response.text}   |   [{current_count}]")
        else:
            with lock:
                current_count = counter
                counter += 1
            print(f"Error uploading {filename}: {response.text}   |   [{current_count}]")
    except Exception as e:
        with lock:
            current_count = counter
            counter += 1
        print(f"Error processing {filename}: {str(e)}   |   [{current_count}]")

def process_images():
    script_dir = os.getcwd() # /Users/{name}/local_files/auto_trim_gemini
    parent_dir = os.path.dirname(os.getcwd()) # /Users/zacklung/local_files
    
    input_folder = f"{parent_dir}/images"
    output_folder = f"{parent_dir}/resized_images"
    text_file_path = os.path.join(script_dir, "text_keys", "final_images.txt")
    
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    auto_trim_folder = os.path.dirname(text_file_path)
    if not os.path.exists(auto_trim_folder):
        os.makedirs(auto_trim_folder)
    
    headers = {"Authorization": f"Bearer {API_KEY}"}
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for filename in os.listdir(input_folder):
            if filename.lower().endswith(('.jpg', '.jpeg', '.png')):
                futures.append(executor.submit(process_single_image, filename, input_folder, output_folder, text_file_path, headers))
        
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"Thread raised an exception: {e}")

if __name__ == "__main__":
    process_images()
