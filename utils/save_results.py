import os
import json
import glob
from datetime import datetime

def save_results(results, output_folder, filename_pattern, date_format):
    """
    Saves the results dictionary to a JSON file in the output folder.
    If a JSON file already exists, it overwrites it with the current date.
    
    Args:
        results (dict): The results data to save.
        output_folder (str): Path to the folder where the file should be saved.
        filename_pattern (str): Pattern for naming the file (e.g. 'results_{date}.json').
        date_format (str): Date format string for replacing {date} in filename.
    """
    # Ensure the output folder exists
    os.makedirs(output_folder, exist_ok=True)
    
    # Look for existing JSON files in the output folder
    existing_files = glob.glob(os.path.join(output_folder, "*.json"))
    
    if existing_files:
        # Use the first existing JSON file found
        output_path = existing_files[0]
        print(f"[~] Found existing file: {os.path.basename(output_path)}")
        
        # Update the filename with current date if it follows the pattern
        base_name = os.path.basename(output_path)
        if "{date}" in filename_pattern:
            # Generate new filename with current date
            date_str = datetime.utcnow().strftime(date_format)
            new_filename = filename_pattern.replace("{date}", date_str)
            new_output_path = os.path.join(output_folder, new_filename)
            
            # If the new filename is different, rename the file
            if new_output_path != output_path:
                try:
                    os.rename(output_path, new_output_path)
                    output_path = new_output_path
                    print(f"[~] Renamed to: {os.path.basename(output_path)}")
                except OSError as e:
                    print(f"[!] Could not rename file: {e}")
                    # Continue with the original path if rename fails
    else:
        # No existing files, create new one with current date
        date_str = datetime.utcnow().strftime(date_format)
        output_filename = filename_pattern.replace("{date}", date_str)
        output_path = os.path.join(output_folder, output_filename)
        print(f"[~] No existing file found, creating: {os.path.basename(output_path)}")
    
    # Write JSON file (overwrite existing or create new)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"[✓] Results saved to: {output_path}")
