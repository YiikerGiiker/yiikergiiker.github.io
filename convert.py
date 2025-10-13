import datetime
import re
import os
import shutil

# --- Configuration ---
source_folder = "/home/giiker/Documents/Personal/Personal/git/notes/Hacking/CTFs/HackTheBox/0_Temp-Retired"
source_images_dir = "/home/giiker/Documents/Personal/Personal/git/notes/Hacking/Images"
blog_images_dir = "images"
posts_folder = "_posts"

os.makedirs(blog_images_dir, exist_ok=True)
os.makedirs(posts_folder, exist_ok=True)

# --- Functions ---
def sanitize_title(title):
    sanitized = re.sub(r'[^a-z0-9\-]', '', title.lower().replace(' ', '-'))
    return sanitized

def convert_obsidian_images(content):
    """
    Convert ![[image.png|optional]] to ![image](images/image.png)
    and copy the image to the blog images directory.
    Ensures image is always on a new line below the text.
    """
    def replacer(match):
        full_ref = match.group(1)
        parts = full_ref.split('|')
        image_name = parts[0].strip()  # filename
        width = parts[1].strip() if len(parts) > 1 else None

        src_path = os.path.join(source_images_dir, image_name)
        dest_path = os.path.join(blog_images_dir, image_name)

        if os.path.exists(src_path):
            shutil.copy2(src_path, dest_path)
        else:
            print(f"Warning: Image '{image_name}' not found in source folder.")

        # Always add newlines before and after to make it block-level
        if width:
            return f"\n![{image_name}](/images/{image_name}){{: .normal width=\"{width}\"}}\n"
        else:
            return f"\n![{image_name}](/images/{image_name}){{: .normal }}\n"

    return re.sub(r'!\[\[(.*?)\]\]', replacer, content)

# --- Batch process all .md files ---
for md_file in os.listdir(source_folder):
    if md_file.endswith(".md"):
        filepath_source = os.path.join(source_folder, md_file)
        title = os.path.splitext(md_file)[0]  # e.g., "Nibbles"
        filename_title = sanitize_title(title)
        today = datetime.date.today()
        date_str = today.strftime("%Y-%m-%d")
        filename = f"{date_str}-{filename_title}.md"
        filepath_post = os.path.join(posts_folder, filename)

        # Generate front matter
        front_matter = f"""---
layout: post
title: "HTB AD Medium: {title}"
description: "{title} is a Medium rated AD machine on HTB."
categories: [CTF,HTB]
tags: [AD,Medium]
author: g
---
"""

        # Read source content
        try:
            with open(filepath_source, "r") as src:
                content = src.read()
        except FileNotFoundError:
            print(f"Source file '{filepath_source}' not found.")
            continue

        # Convert Obsidian images
        content = convert_obsidian_images(content)

        # Write final post
        with open(filepath_post, "w") as file:
            file.write(front_matter + "\n" + content)

        print(f"Created Jekyll post: {filepath_post}")
