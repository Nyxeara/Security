# ​🚀 Video/Audio Signature Hash Tool
​This is the first Python tool generates a unique, unforgeable digital signature for any video or audio file. It's designed to be simple, fast, and dependency-free—perfect for use on mobile platforms like Android via Termux.
​What is a File Signature?
​Think of the signature (the long string of characters) as the file's unique digital fingerprint.
​It is created by reading every single byte of data in the file (video, audio, etc.) and feeding it into a specialized mathematical algorithm (SHA-256).
​Even if you change just one pixel or one second of audio, the resulting signature will be completely different.
​How to Use the Signature: Verification
​The primary use of this tool is verification of identity.
​You calculate the signature of your original video file and send the resulting text string to a friend.
​Your friend downloads what they believe to be the original video file.
​Your friend runs this script on their downloaded file.
​If the hash signatures match exactly, they are guaranteed to have an authentic, unmodified, bit-for-bit identical copy of your original file.
