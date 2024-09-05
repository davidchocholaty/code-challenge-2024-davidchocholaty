import hashlib
import os

from Crypto.Hash import RIPEMD160

def get_filename_without_extension(file_path):
    # Get the base filename from the path
    filename = os.path.basename(file_path)
    # Remove the extension
    filename_without_extension = os.path.splitext(filename)[0]
    return filename_without_extension

def decode_hex(hex_data):
    # Decode a hex-encoded data into its raw bytecode.
    return bytes.fromhex(hex_data)

def hash160(data):
    # SHA-256 followed by RIPEMD-160 (Bitcoin's HASH160).
    sha256_hash = hashlib.sha256(data).digest()

    ripemd160 = RIPEMD160.new()
    ripemd160.update(sha256_hash)
    
    return ripemd160.digest()
