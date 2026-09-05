import zipfile
import os

files_to_zip = [
    "main.py",
    "core.py",
    "requirements.txt",
    os.path.join("static", "index.html"),
]

zip_filename = "secure_steganography_web.zip"

with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zipf:
    for file in files_to_zip:
        if os.path.exists(file):
            zipf.write(file, arcname=file)
            print(f"Added: {file}")
        else:
            print(f"Warning: {file} not found.")

print(f"\n[+] Created {zip_filename} successfully!")