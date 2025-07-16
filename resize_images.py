from PIL import Image
import os

# Folder where your images are located
folder_path = r"C:\Users\admin\OneDrive\Documents\GitHub\freeontools-clean\docs\images\random_animal_images"

# Target size
target_size = (300, 300)

# Allowed image types
image_extensions = (".jpg", ".jpeg", ".png", ".webp")

# Process each image
for filename in os.listdir(folder_path):
    if filename.lower().endswith(image_extensions):
        file_path = os.path.join(folder_path, filename)

        try:
            with Image.open(file_path) as img:
                # Convert to proper mode for saving
                if img.mode not in ("RGB", "RGBA"):
                    img = img.convert("RGB")

                # Resize with high-quality filter
                img = img.resize(target_size, Image.LANCZOS)

                # Format-specific save options
                ext = filename.lower().split(".")[-1]
                save_args = {}

                if ext in ["jpg", "jpeg"]:
                    save_args = {"optimize": True, "quality": 95}
                elif ext == "png":
                    save_args = {"optimize": True}
                elif ext == "webp":
                    save_args = {"lossless": True, "quality": 100}

                # Save the image (overwrite)
                img.save(file_path, **save_args)
                print(f"✅ Resized & Optimized: {filename}")

        except Exception as e:
            print(f"❌ Error with {filename}: {e}")
