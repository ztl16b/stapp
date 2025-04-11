import os
import shutil
from collections import defaultdict

#Combine different folders that start with 'images_'

downloads_folder = os.path.expanduser("~/Downloads")
local_files = os.path.expanduser("~/local_files")
getcwd_file_1 = os.getcwd()
getcwd_file_2 = os.path.dirname(os.getcwd())

image_files = []
folder_image_counts = defaultdict(int)
source_folders = set()

allowed_extensions = ('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff')

for root, dirs, files in os.walk(downloads_folder):
    for d in dirs:
        if d.lower().startswith("images_"):
            folder_path = os.path.join(root, d)
            source_folders.add(folder_path)
            
            for sub_root, sub_dirs, sub_files in os.walk(folder_path):
                for file in sub_files:
                    if file.lower().endswith(allowed_extensions):
                        file_path = os.path.join(sub_root, file)
                        image_files.append(file_path)
                        folder_image_counts[folder_path] += 1

print("Folder Summary:")
for folder in sorted(source_folders):
    print(f"Folder: {folder}   [{folder_image_counts[folder]}]")

total_images = len(image_files)
if total_images == 0:
    print("No images found. Exiting...")
    exit()
print("=" * 50)
print(f"Total image files found across all folders: {total_images}")
target_folder_name = f"images_{total_images}"
target_folder_path = os.path.join(downloads_folder, target_folder_name)

if not os.path.exists(target_folder_path):
    os.makedirs(target_folder_path)
    print(f"\nCreated target folder: {target_folder_path}")

for file_path in image_files:
    file_name = os.path.basename(file_path)
    target_path = os.path.join(target_folder_path, file_name)
    
    counter = 1
    base, ext = os.path.splitext(file_name)
    while os.path.exists(target_path):
        target_path = os.path.join(target_folder_path, f"{base}_{counter}{ext}")
        counter += 1

    shutil.copy2(file_path, target_path)

print("\nAll files have been copied successfully.")
print(f"Final destination: {target_folder_path}")