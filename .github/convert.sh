#!/usr/bin/env bash
FILES=$(git diff-tree --no-commit-id --name-only -r HEAD | grep -E '(\.png|\.jpg|\.jpeg)$')
for x in $FILES;
do 
    echo converting $x to webp;
    webp_path=$(sed -E "s/\.(png|jpg|jpeg)$/.webp/" <<< $x) 
    echo $webp_path
    
    if [[ $x == *".png" ]]; then
        cwebp -lossless $x -o $webp_path
    else
        cwebp -q 100 $x -o $webp_path
    fi
    
    size_webp=$(stat -c %s $webp_path)
    size_og=$(stat -c %s $x)

    if [[ $size_webp -le $size_og ]]; then
        rm $x
        git grep --cached -Il '' | xargs sed -i "s|$x|$webp_path|g"
    else
        rm $webp_path
    fi

done
