import os
import glob

# Define the directory containing HTML files (use raw string)
directory = r"C:\Users\admin\OneDrive\Desktop\docs"  # Fixed path with raw string

# Define the old and new script tags
old_scripts = [
    '<script src="../js/script.js" defer></script>',
    '<script src="/js/auth.js" defer></script>'
]
new_scripts = [
    '<script src="/js/script.js" defer></script>',
    '<script src="/js/auth.js" defer></script>'
]

# Function to replace script tags in a single file
def replace_in_file(file_path):
    try:
        # Read the file content
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        
        # Keep track if any changes were made
        modified = False
        
        # Replace old script tags with new ones
        new_content = content
        for old, new in zip(old_scripts, new_scripts):
            if old in new_content:
                new_content = new_content.replace(old, new)
                modified = True
        
        # Write back to file only if changes were made
        if modified:
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(new_content)
            print(f"Updated: {file_path}")
        else:
            print(f"No changes needed: {file_path}")
            
    except Exception as e:
        print(f"Error processing {file_path}: {str(e)}")

# Verify directory exists
if not os.path.isdir(directory):
    print(f"Error: Directory '{directory}' does not exist")
    exit(1)

# Find all HTML files in the directory
html_files = glob.glob(os.path.join(directory, "*.html"))

# Process each HTML file
for html_file in html_files:
    replace_in_file(html_file)

print(f"\nProcessed {len(html_files)} HTML files")