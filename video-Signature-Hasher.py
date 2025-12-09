import hashlib
import os

def generate_video_file_hash(filepath):
    """
    Generates a secure SHA-256 hash (file signature) for a video file.
    This method is highly stable as it uses only built-in Python libraries.
    
    Args:
        filepath (str): The absolute path to the video file.
        
    Returns:
        str: The SHA-256 hash text, or an error message if the file is not found.
    """
    
    # Check if the file exists
    if not os.path.exists(filepath):
        return f"Error: File not found at path: {filepath}"
    
    hasher = hashlib.sha256()
    
    # Read the file in chunks to handle large video files efficiently
    try:
        with open(filepath, 'rb') as f:
            while True:
                # Read 8MB chunks
                chunk = f.read(8388608) 
                if not chunk:
                    break
                hasher.update(chunk)
                
        # Return the final 64-character hash string
        return hasher.hexdigest()
        
    except Exception as e:
        # Handle access issues (e.g., Termux file permissions)
        return f"Error accessing file: {e}"

# --- EXECUTION ---
# 1. IMPORTANT: Replace this path with the actual location of your video file path
video_file_path = "video_file_path" 
# 2. Generate the hash
hash_code = generate_video_file_hash(video_file_path)

# 3. Print the result
print("-" * 40)
print(f"File Path: {video_file_path}")
print(f"Video Hash Signature: {hash_code}")
print("-" * 40)
#build and programed by Nyxeara