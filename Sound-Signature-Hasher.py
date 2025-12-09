import hashlib
import os

def generate_file_hash_for_android(filepath):
    """
    Generates a secure SHA-256 hash of an audio file.
    This method uses only built-in Python libraries (hashlib) 
    making it the most stable choice for Android/APK deployments.
    
    Args:
        filepath (str): The absolute path to the audio file on the device.
        
    Returns:
        str: The SHA-256 hash text, or an error message.
    """
    
    # 1. Check if the file exists
    if not os.path.exists(filepath):
        return f"Error: File not found at path: {filepath}"
    
    hasher = hashlib.sha256()
    
    # 2. Read the file in chunks for memory efficiency
    try:
        with open(filepath, 'rb') as f:
            while True:
                # Read 8KB (8192 bytes) chunk at a time
                chunk = f.read(8192)
                if not chunk:
                    break  # End of file
                hasher.update(chunk)
                
        # 3. Return the final hash as a hexadecimal string
        return hasher.hexdigest()
        
    except Exception as e:
        # Handle file access or permission errors
        return f"Error accessing file: {e}"

# --- Example Usage ---
# You MUST replace this with the absolute path on the Android device 
# (e.g., '/storage/emulated/0/Download/audio.mp3')
android_file_path = "audio-file-path" 

hash_code = generate_file_hash_for_android(android_file_path)

# You can use 'hash_code' to store the signature or compare files.
print(f"Generated Hash: {hash_code}")
#programed by Nyxeara