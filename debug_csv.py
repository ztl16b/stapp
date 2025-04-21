import boto3
import csv
import io
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Config
bucket_name = 'etickets-content-test-bucket'
key_name = 'temp/performer-infos (1).csv'

# Initialize S3 client
s3_client = boto3.client(
    's3',
    aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
    region_name=os.environ.get('AWS_REGION')
)

def main():
    print(f"Retrieving CSV from S3: {bucket_name}/{key_name}")
    
    try:
        # Get the object
        response = s3_client.get_object(Bucket=bucket_name, Key=key_name)
        
        # Stream the body data
        csv_content = response['Body'].read()
        
        # Log file size
        print(f"CSV file size: {len(csv_content)} bytes")
        
        # Decode and process with csv
        csv_text = csv_content.decode('utf-8')
        csv_file = io.StringIO(csv_text)
        
        # Read first 5 rows to check structure
        reader = csv.reader(csv_file)
        print("\n--- First 5 rows of the CSV file ---")
        for i, row in enumerate(reader):
            if i >= 5:
                break
            print(f"Row {i}: {row}")
            
        # Reset file position
        csv_file.seek(0)
        
        # Check column names
        reader = csv.DictReader(csv_file)
        fieldnames = reader.fieldnames
        print(f"\nColumn names: {fieldnames}")
        
        # Create {performer_id: name_alias} map from the first 5 rows
        csv_file.seek(0)
        reader = csv.DictReader(csv_file)
        
        performer_map = {}
        for i, row in enumerate(reader):
            if i >= 5:
                break
            if 'performer_id' in row and 'name_alias' in row:
                performer_id = row['performer_id']
                name_alias = row['name_alias']
                performer_map[performer_id] = name_alias
                print(f"Performer {performer_id}: {name_alias}")
        
        # Now check some specific IDs
        print("\n--- Testing specific performer IDs ---")
        test_ids = ['1', '2', '3', '5', '10', '100', '5841']
        
        csv_file.seek(0)
        reader = csv.DictReader(csv_file)
        test_results = {}
        
        for row in reader:
            if 'performer_id' in row and row['performer_id'] in test_ids:
                test_results[row['performer_id']] = row['name_alias']
        
        for test_id in test_ids:
            if test_id in test_results:
                print(f"ID {test_id}: {test_results[test_id]}")
            else:
                print(f"ID {test_id}: Not found")
                
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main() 