#!/usr/bin/env bash

echo "Running convert.sh"

# Check if webp is installed
command -v cwebp >/dev/null 2>&1 || { echo "Error: cwebp is not installed. Aborting." >&2; exit 1; }

# Iterate over the list of modified image files
while read -r file; do
    # Print the file being converted
    echo "Converting $file to webp"

    # Generate webp file path
    webp_path=$(sed -E "s/\.(png|jpg|jpeg)$/.webp/" <<< "$file") 

    # Convert to webp
    if [[ $file == *".png" ]]; then
        cwebp -lossless "$file" -o "$webp_path"
    else
        cwebp -q 100 "$file" -o "$webp_path"
    fi

    # Check if conversion was successful
    if [ $? -ne 0 ]; then
        echo "Error: Conversion failed for $file. Skipping file."
        rm "$webp_path"
        continue
    fi

    # Get sizes of original and webp files
    size_webp=$(stat -c %s "$webp_path")
    size_og=$(stat -c %s "$file")

    # Replace original with webp if webp file is smaller
    if [[ $size_webp -le $size_og ]]; then
        rm "$file"
        git grep --cached -Il '' | xargs sed -i "s|$file|$webp_path|g"
    else
        rm "$webp_path"
    fi
done < <(git diff-tree --no-commit-id --name-only -r HEAD | grep -E '(\.png|\.jpg|\.jpeg)$')
