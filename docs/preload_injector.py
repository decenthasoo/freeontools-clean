import os

# Target directory
base_dir = r"C:\Users\admin\OneDrive\Desktop\app"

# Lines to remove
old_lines = [
    '<link rel="preload" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.6.0/css/all.min.css" as="style" onload="this.onload=null;this.rel=\'stylesheet\'">',
    '<noscript><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.6.0/css/all.min.css"></noscript>',
    '<link rel="preload" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.6.0/webfonts/fa-solid-900.woff2" as="font" type="font/woff2" crossorigin>'
]

# Lines to insert
new_lines = [
    '<link rel="preload" href="/css/all.min.css" as="style" onload="this.onload=null;this.rel=\'stylesheet\'">',
    '<noscript><link rel="stylesheet" href="/css/all.min.css"></noscript>',
    '<link rel="preload" href="/css/webfonts/fa-solid-900.woff2" as="font" type="font/woff2" crossorigin>'
]

# Loop through all HTML files
for root, dirs, files in os.walk(base_dir):
    for filename in files:
        if filename.endswith(".html"):
            file_path = os.path.join(root, filename)

            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            # Remove old lines if present
            new_content = [line for line in lines if not any(old in line for old in old_lines)]

            # Check if anything changed
            if len(new_content) != len(lines):
                # Insert new lines at the first matching old line's position (or top if not found)
                insert_index = next((i for i, line in enumerate(lines) if any(old in line for old in old_lines)), 0)
                for i, newline in enumerate(new_lines):
                    new_content.insert(insert_index + i, newline + "\n")

                # Write back modified content
                with open(file_path, "w", encoding="utf-8") as f:
                    f.writelines(new_content)
                print(f"✅ Updated: {file_path}")
            else:
                print(f"⏭️  No changes needed: {file_path}")
