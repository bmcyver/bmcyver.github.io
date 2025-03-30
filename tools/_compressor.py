import os
import re
from pathlib import Path
from PIL import Image

RESET = "\033[0m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RED = "\033[91m"

IMAGE_DIR = "assets/posts"
MARKDOWN_DIRS = ["_posts", "_drafts"]
SUPPORTED_EXTENSIONS = {".jpg", ".jpeg", ".png"}

def convert_to_webp(image_path):
    webp_path = image_path.with_suffix(".webp")
    if webp_path.exists():
        return webp_path

    with Image.open(image_path) as img:
        img.save(webp_path, "WEBP", quality=85)

    original_size_kb = image_path.stat().st_size / 1024
    webp_size_kb = webp_path.stat().st_size / 1024
    compression_ratio = (1 - (webp_size_kb / original_size_kb)) * 100

    relative_path = image_path.as_posix()

    color = RED if compression_ratio < 0 else MAGENTA
    sign = "-" if compression_ratio >= 0 else "+"

    abs_compression_ratio = abs(compression_ratio)

    print(f"{GREEN}✔ {CYAN}{relative_path}{GREEN} ({YELLOW}{original_size_kb:.1f}KB{GREEN}) → "
        f"{MAGENTA}.webp{GREEN} ({YELLOW}{webp_size_kb:.1f}KB{GREEN}) {color}[{sign}{abs_compression_ratio:.1f}%]{RESET}")

    return webp_path

def update_markdown_files(image_path):
    webp_path = image_path.with_suffix(".webp")
    original_str = f"/{image_path.as_posix()}"
    webp_str = f"/{webp_path.as_posix()}"

    for md_dir in MARKDOWN_DIRS:
        for md_path in Path(md_dir).rglob("*.md"):
            with open(md_path, "r", encoding="utf-8") as file:
                content = file.read()

            new_content = content.replace(original_str, webp_str)

            if new_content != content:
                with open(md_path, "w", encoding="utf-8") as file:
                    file.write(new_content)
                print(f"{GREEN}✔ Updated Markdown: {CYAN}{md_path}{RESET}")

    image_path.unlink(missing_ok=True)

def process_image(image_path):
    if image_path.suffix.lower() in SUPPORTED_EXTENSIONS:
        webp_path = convert_to_webp(image_path)
        update_markdown_files(image_path)

def process_images():
    for image_path in Path(IMAGE_DIR).rglob("*"):
        process_image(image_path)

if __name__ == "__main__":
    process_images()
