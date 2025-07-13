import os
import shutil

ROOT_DIR = '.'  # Root folder where your HTML files are
BACKUP_DIR = './backup_html'

# Preload links
PRELOAD_1 = '<link rel="preload" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.6.0/webfonts/fa-solid-900.woff2" as="font" type="font/woff2" crossorigin>'
PRELOAD_2 = '<link rel="preload" href="https://fonts.gstatic.com/s/poppins/v20/pxiEyp8kv8JHgFVrJJfecg.woff2" as="font" type="font/woff2" crossorigin>'
PRELOAD_TAGS = f'\n{PRELOAD_1}\n{PRELOAD_2}\n'

def is_html_file(filename):
    return filename.endswith('.html')

def make_backup(original_path, rel_path):
    backup_path = os.path.join(BACKUP_DIR, rel_path)
    os.makedirs(os.path.dirname(backup_path), exist_ok=True)
    shutil.copy2(original_path, backup_path)

def inject_if_needed(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Case-insensitive search for </title>
    title_index = content.lower().find('</title>')
    if title_index == -1:
        print(f"⚠️ No </title> tag found in: {filepath}")
        return False

    # Check if both preload tags already exist
    if PRELOAD_1 in content and PRELOAD_2 in content:
        return False  # Already injected

    # Inject right after </title>
    insertion_point = title_index + len('</title>')
    new_content = content[:insertion_point] + PRELOAD_TAGS + content[insertion_point:]

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(new_content)

    return True

def main():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    html_files = [f for f in os.listdir(ROOT_DIR) if is_html_file(f)]

    for file in html_files:
        full_path = os.path.join(ROOT_DIR, file)
        print(f"🔍 Checking: {file}")

        make_backup(full_path, file)
        modified = inject_if_needed(full_path)

        if modified:
            print(f"✅ Injected preload links into {file}")
        else:
            print(f"⏩ Skipped (already has both links): {file}")

    print(f"\n📦 All backups stored in: {BACKUP_DIR}")

if __name__ == '__main__':
    main()
