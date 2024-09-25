---
layout: post
current: post
cover: assets/csaw/davidhuang/zipzipzip.webp
navigation: True
title: "Zip Zip Zip"
date: 2024-09-25 11:59:00
tags: [csaw, forensics]
class: post-template
subclass: 'post'
author: davidhuang
---

A ZIP within a ZIP within a ZIP within a ZIP... 

## "Unzipping" the Problem

We are given a ZIP file [challenge.zip](/assets/csaw/davidhuang/challenge.zip) that extracts to `chunk_0.zip`, which extracts into `chunk_0.txt` and another ZIP `chunk_1.zip`, which extracts into `chunk_1.txt` and yet another ZIP `chunk_2.zip`, and so it goes forever (much like some boring lectures).

The contents of the `.txt` files all look something like this:

```
# chunk_0.txt:
iVBOR

# chunk_1.txt:
w0KGg
```

So essentially, we are facing a ZIP within a ZIP within a ZIP within a… As we unzip, we see a trail of text files each containing a small chunk of mumble-jumble texts that will perhaps piece together into something.

### Recursive Approach

So far, it looks like a pretty straightforward recursion problem. Let’s recursively extract one ZIP at a time until there are no more ZIPs to extract.

```python
import zipfile
import os

def unzip_recursive(zip_path, output_file, current_dir='.'):
    
    # Get the extracted folder name
    extracted_folder = os.path.splitext(os.path.basename(zip_path))[0]
    extracted_folder_path = os.path.join(current_dir, extracted_folder)
    print(f"Extracted folder: {extracted_folder_path}")
    # Extract the zip file
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extracted_folder_path)
    
    # Traverse the folder
    for root, dirs, files in os.walk(extracted_folder_path):
        for file in files:
            if file.endswith('.txt'):
                # Read and record the content of .txt files
                with open(os.path.join(root, file), 'r') as txt_file:
                    content = txt_file.read()
                    with open(output_file, 'a') as out_file:
                        out_file.write(f"Content of {file}:\n")
                        out_file.write(content + "\n\n")
            elif file.endswith('.zip'):
                # Recursively unzip the next zip file
                next_zip = os.path.join(root, file)
                unzip_recursive(next_zip, output_file, root)

# Example usage
zip_path = './chunk_0.zip'  # The path to the initial zip file
output_file = './output.txt'  # The file to record the .txt contents
unzip_recursive(zip_path, output_file)
```

Well, that was easy. What? A runtime error:

```
OSError: [Errno 63] File name too long: './chunk_0/chunk_1/chunk_2/chunk_3/chunk_4/chunk_5/chunk_6/chunk_7/chunk_8/chunk_9/chunk_10/chunk_11/chunk_12/chunk_13/chunk_14/chunk_15/chunk_16/chunk_17/chunk_18/chunk_19/chunk_20/chunk_21/chunk_22/chunk_23/chunk_24/chunk_25/chunk_26/chunk_27/chunk_28/chunk_29/chunk_30/chunk_31/chunk_32/chunk_33/chunk_34/chunk_35/chunk_36/chunk_37/chunk_38/chunk_39/chunk_40/chunk_41/chunk_42/chunk_43/chunk_44/chunk_45/chunk_46/chunk_47/chunk_48/chunk_49/chunk_50/chunk_51/chunk_52/chunk_53/chunk_54/chunk_55/chunk_56/chunk_57/chunk_58/chunk_59/chunk_60/chunk_61/chunk_62/chunk_63/chunk_64/chunk_65/chunk_66/chunk_67/chunk_68/chunk_69/chunk_70/chunk_71/chunk_72/chunk_73/chunk_74/chunk_75/chunk_76/chunk_77/chunk_78/chunk_79/chunk_80/chunk_81/chunk_82/chunk_83/chunk_84/chunk_85/chunk_86/chunk_87/chunk_88/chunk_89/chunk_90/chunk_91/chunk_92/chunk_93/chunk_94/chunk_95/chunk_96/chunk_97/chunk_98/chunk_99/chunk_100/chunk_101/chunk_102/chunk_103/chunk_104/chunk_105/chunk_106/chunk_107/chunk_108/chunk_109/chunk_110/chunk_111/chunk_112.zip'
```

Em... File name too long... I didn’t know that could be a thing. No worries. Let’s just not keep the path and instead extract all of the chunk ZIPs into one folder. 

Wait, what!? Another error:

```
RecursionError: maximum recursion depth exceeded
```

Oh yeah, forgot there is a limit to the depth of our recursion. Looks like we have to make it iterative.

### Iterative Approach

How to turn our recursive approach into iterative one? No idea. But a little Chat-Oriented-Programming (asking ChatGPT) gives us the following:

```python

import zipfile
import os
import io

def unzip_iterative_in_memory(start_zip):
    # Stack to hold zip files that need to be processed
    zip_stack = [start_zip]

    while zip_stack:
        current_zip = zip_stack.pop()

        # Open the current zip file
        with zipfile.ZipFile(current_zip, 'r') as zip_ref:
            print(f"Number of files in the zip: {len(zip_ref.namelist())}")
            # Process each file in the zip
            for file in zip_ref.namelist():
                # print the number of files in the zip
                # If it's a .txt file, read and print the content
                if file.endswith('.txt'):
                    with zip_ref.open(file) as txt_file:
                        content = txt_file.read().decode('utf-8')
                        print(f"Content of {file}:\n{content}\n")
                        
                    # extract the number from the file name
                    with open(f'./result.txt', 'a') as f:
                        f.write(content)
                # If it's another .zip file, read it into memory and add to the stack
                elif file.endswith('.zip'):
                    with zip_ref.open(file) as nested_zip_file:
                        nested_zip_data = io.BytesIO(nested_zip_file.read())
                        zip_stack.append(nested_zip_data)

```

This approach works like an iterative Depth First Search. It unzips a ZIP file, notes down the content of the text file, and then adds any newly encountered ZIP files to the stack of files waiting to be unzipped. It produced the following text:

```
iVBORw0KGgoAAAANSUhEUgAABAAAAAQACAMAAABIw9uxAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAASFBMVEUSHTIPGSz8/dr5UAj7oAjxNhcMK0lNxvD0+... 
(it goes a lot longer than that. but no need to keep it all here.)
```

## Let Him (CyberChef) Cook

Em... that text still looks like a bunch of nonsense. Let's put it into [CyberChef](https://gchq.github.io/CyberChef/) and see.

Oh look, a small wand lights up on the output. Clicking on it reveals an image:

![illustration of cyberchef](/assets/csaw/davidhuang/cyberchef.webp)

![the decoded image](/assets/csaw/davidhuang/decoded-img.webp)

Well, it is inspiring to see the CSAW logo, but where is our flag? Perhaps it is hidden in some way. Let’s start by changing the contrast on the image. A good tool for this is [Aperi'Solve](https://www.aperisolve.com/). With that, we are able to finally spot our flag nice and clear:

![solved-img.png](/assets/csaw/davidhuang/solved-img.webp)

Case closed!

## Bonus: Delete Delete Delete

Well, that was fun. Now, let me just clean up those annoying ZIP files. 

![trash can not](/assets/csaw/davidhuang/path-too-long.webp)

What the freak... first time I've see my trash failing to handle a file. Might as well rename it to "Trash Can't." Don’t tell me I have to write another program just to delete those ZIP files one by one. Wait, I have an idea:


```bash
rm -rf ./chunk_0
```

It turns out, a simple terminal command that recursively deletes everything in the directory does the trick. Phew, so glad it is that easy.

Now, case officially closed!
