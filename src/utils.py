import os

def get_filename_without_extension(file_path):
    # Get the base filename from the path
    filename = os.path.basename(file_path)
    # Remove the extension
    filename_without_extension = os.path.splitext(filename)[0]
    return filename_without_extension