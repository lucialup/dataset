import os
import subprocess
import csv
import shutil
from collections import defaultdict
from pathlib import Path

apk_folder = "Benign"
output_csv = "top_libraries_usage.csv"
temp_dir = "temp_extracted"  # Temporary directory for extracted contents
library_usage = defaultdict(lambda: {"count": 0, "apks": []})

successful_apk_count = 0

def extract_libraries(apk_path):
    apk_extract_dir = os.path.join(temp_dir, Path(apk_path).stem)
    Path(apk_extract_dir).mkdir(parents=True, exist_ok=True)
    
    try:
        subprocess.run(f"unzip -o {apk_path} -d {apk_extract_dir}", shell=True, check=True)
        
        classes_dex_path = os.path.join(apk_extract_dir, "classes.dex")
        
        libraries = []
        if os.path.exists(classes_dex_path):
            cmd = f"dexdump -d {classes_dex_path} | grep 'Class descriptor' | awk -F\"'\" '{{print $2}}' | sed -E \"s|^L([^;]+).*|\\1|\" | sed 's|/|.|g' | grep -E '^[a-zA-Z]+\\.[a-zA-Z]+' | grep -v '^[a-z]\\.[a-z]\\.' | sort | uniq"
            result = subprocess.getoutput(cmd)
            libraries = result.splitlines()
        
        shutil.rmtree(apk_extract_dir)
        
    except subprocess.CalledProcessError as e:
        print(f"Error processing {apk_path}: {e}")
        shutil.rmtree(apk_extract_dir, ignore_errors=True)
        return []
    
    return libraries

for apk_file in os.listdir(apk_folder):
    if apk_file.endswith(".apk"):
        apk_path = os.path.join(apk_folder, apk_file)
        libraries = extract_libraries(apk_path)
        
        if libraries:
            for lib in libraries:
                library_usage[lib]["count"] += 1
                library_usage[lib]["apks"].append(apk_file)
            
            successful_apk_count += 1

top_libraries = sorted(library_usage.items(), key=lambda x: x[1]["count"], reverse=True)[:50]

with open(output_csv, mode="w", newline="") as csv_file:
    writer = csv.writer(csv_file)
    writer.writerow(["Library", "Count", "APK Files"])
    for lib, data in top_libraries:
        writer.writerow([lib, data["count"], "; ".join(data["apks"])])

print(f"Top libraries usage saved to {output_csv}")
print(f"Total successfully processed APKs: {successful_apk_count}")

