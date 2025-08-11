import os
import json
from datetime import datetime

def save_results(results, output_folder, filename_pattern, date_format):
    """
    Saves the results dictionary to a JSON file in the output folder.

    Args:
        results (dict): The results data to save.
        output_folder (str): Path to the folder where the file should be saved.
        filename_pattern (str): Pattern for naming the file (e.g. 'results_{date}.json').
        date_format (str): Date format string for replacing {date} in filename.
    """
    # Ensure the output folder exists
    os.makedirs(output_folder, exist_ok=True)

    # Prepare filename
    date_str = datetime.utcnow().strftime(date_format)
    output_filename = filename_pattern.replace("{date}", date_str)
    output_path = os.path.join(output_folder, output_filename)

    # Write JSON file
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"[✓] Results saved to: {output_path}")
