import os

downloads_folder = os.path.expanduser("~/Downloads")

def rename_files_in_directory(directory, prefix="1-"):
    files = os.listdir(directory)
    files.sort()
    
    counter = 1
    for file in files:
        file_path = os.path.join(directory, file)
        if os.path.isfile(file_path):
            file_root, file_ext = os.path.splitext(file)
            new_filename = f"{prefix}{counter}{file_ext}"
            new_file_path = os.path.join(directory, new_filename)
            os.rename(file_path, new_file_path)
            print(f"Renamed: {file} -> {new_filename}")
            counter += 1

folder_path = f"{downloads_folder}/drive-download-20250410T200451Z-001/04_08_JORDAN" 
prefix = "3-"

if os.path.isdir(folder_path):
    rename_files_in_directory(folder_path, prefix)
    print("Renaming complete.")
else:
    print("The provided path does not exist or is not a directory.")