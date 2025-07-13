import re
import os
import glob
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    filename=f'replacement_log_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Define replacements as a list of tuples: (pattern, replacement)
REPLACEMENTS = [
    (
        r'<link\s+href="https://cdnjs\.cloudflare\.com/ajax/libs/font-awesome/6\.6\.0/css/all\.min\.css"\s+rel="stylesheet"\s*/>',
        r'<link rel="preload" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.6.0/css/all.min.css" as="style" onload="this.onload=null;this.rel=\'stylesheet\'">\n<noscript><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.6.0/css/all.min.css"></noscript>'
    ),
    (
        r'<link\s+href="https://fonts\.googleapis\.com/css2\?family=Poppins:wght@400;500;700&display=swap"\s+rel="stylesheet"\s*/?>',
        r'<link rel="preconnect" href="https://fonts.googleapis.com">\n<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>\n<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;700&display=swap" rel="stylesheet" media="print" onload="this.media=\'all\'">'
    ),
    (
        r'<link\s+href="\.\./css/style\.css"\s+rel="stylesheet"\s*/>',
        r'<link rel="preload" href="../css/style.css" as="style" onload="this.onload=null;this.rel=\'stylesheet\'">\n<noscript><link rel="stylesheet" href="../css/style.css"></noscript>'
    ),
    (
        r'<script\s+src="\.\./js/script\.js"\s*(?:defer)?\s*></script>',
        r'<script src="../js/script.js" defer></script>'
    ),
    (
        r'<script\s+src="/js/auth\.js"\s*(?:defer)?\s*></script>',
        r'<script src="/js/auth.js" defer></script>'
    )
]

# Font preload tags to add below </title>
FONT_PRELOAD = '''<link rel="preload" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.6.0/webfonts/fa-solid-900.woff2" as="font" type="font/woff2" crossorigin>
<link rel="preload" href="https://fonts.gstatic.com/s/poppins/v20/pxiEyp8kv8JHgFVrJJfecg.woff2" as="font" type="font/woff2" crossorigin>'''

def process_html_file(filepath):
    """Process a single HTML file to apply replacements and add font preload tags."""
    try:
        # Read the file
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        # Track if any changes were made
        changes_made = False
        original_content = content

        # Log the content before processing (for debugging)
        logging.debug(f"Processing {filepath}. Original content snippet:\n{content[:500]}...")

        # Clean up duplicate font preload tags
        font_preload_pattern = re.escape(FONT_PRELOAD)
        content, count = re.subn(
            rf'({font_preload_pattern}\s*)+',
            FONT_PRELOAD,
            content,
            flags=re.IGNORECASE
        )
        if count > 0:
            logging.info(f"Removed {count-1} duplicate font preload tag sets in {filepath}")
            changes_made = True

        # Apply all replacements
        for pattern, replacement in REPLACEMENTS:
            if re.search(pattern, content, flags=re.IGNORECASE | re.DOTALL):
                logging.debug(f"Pattern found in {filepath}: {pattern}")
            else:
                logging.debug(f"Pattern NOT found in {filepath}: {pattern}")
            new_content, count = re.subn(pattern, replacement, content, flags=re.IGNORECASE | re.DOTALL)
            if count > 0:
                logging.info(f"Replaced {count} occurrence(s) of pattern in {filepath}: {pattern}")
                content = new_content
                changes_made = True

        # Add font preload tags below </title> only if not already present
        title_pattern = r'</title>'
        if re.search(title_pattern, content, re.IGNORECASE):
            if FONT_PRELOAD not in content:
                content = re.sub(
                    title_pattern,
                    f'</title>\n{FONT_PRELOAD}',
                    content,
                    count=1,
                    flags=re.IGNORECASE
                )
                logging.info(f"Added font preload tags below </title> in {filepath}")
                changes_made = True
            else:
                logging.info(f"Font preload tags already present in {filepath}, skipping addition")
        else:
            logging.warning(f"No </title> tag found in {filepath}. Font preload tags not added.")

        # Write the modified content back to the file if changes were made
        if changes_made:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            logging.info(f"Successfully updated {filepath}")
        else:
            logging.info(f"No changes needed in {filepath}")

        return True

    except Exception as e:
        logging.error(f"Error processing {filepath}: {str(e)}")
        return False

def main():
    """Main function to process all HTML files in the specified directory."""
    # Specify the directory containing HTML files (modify as needed)
    directory = "."  # Current directory; change to your target directory
    html_files = glob.glob(os.path.join(directory, "**/*.html"), recursive=True)

    if not html_files:
        logging.warning("No HTML files found in the specified directory.")
        print("No HTML files found.")
        return

    print(f"Found {len(html_files)} HTML file(s) to process.")
    success_count = 0
    failure_count = 0

    for filepath in html_files:
        print(f"Processing {filepath}...")
        if process_html_file(filepath):
            success_count += 1
        else:
            failure_count += 1

    print(f"Processing complete. Success: {success_count}, Failures: {failure_count}")
    logging.info(f"Processing complete. Success: {success_count}, Failures: {failure_count}")

if __name__ == "__main__":
    main()