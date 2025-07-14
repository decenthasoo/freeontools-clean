import os
import re

# Directory containing HTML files
root_dir = r"C:\Users\admin\OneDrive\Desktop\tools-hub"
output_dir = r"C:\Users\admin\OneDrive\Desktop\tools-hub\output"
auth_script = '<script src="/js/auth.js" defer></script>'

# Create output directory if it doesn't exist
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Process HTML files
for filename in os.listdir(root_dir):
    if filename.endswith('.html') and filename not in ['Header.html', 'footer.html']:
        input_path = os.path.join(root_dir, filename)
        output_path = os.path.join(output_dir, filename)

        with open(input_path, 'r', encoding='utf-8') as file:
            content = file.read()

        # Check if auth.js is already included
        if auth_script not in content:
            # Add before </body>
            if '</body>' in content:
                content = content.replace('</body>', f'{auth_script}\n</body>')
            else:
                print(f"Warning: No </body> tag found in {filename}, skipping")

            # Save to output directory
            with open(output_path, 'w', encoding='utf-8') as file:
                file.write(content)
            print(f"Updated {filename}")
        else:
            print(f"Skipped {filename}, auth.js already included")

print("Processing complete. Updated files are in the 'output' folder.")