#!/usr/bin/env bash

if [ $# -ne 2 ]; then
    echo "Использование: $0 <директория> <количество>"
    exit 1
fi

DIR="$1"
COUNT="$2"
OUTPUT="hashes.csv"

find "$DIR" -type f 2>/dev/null | shuf -n "$COUNT" | while read file; do
    hash=$(md5sum "$file" 2>/dev/null | cut -d' ' -f1)
    if [ -n "$hash" ]; then
        threats=("Trojan" "Virus" "Malware" "Worm" "Spyware")
        threat=${threats[$RANDOM % ${#threats[@]}]}
        echo "$hash;$threat" >> "$OUTPUT"
    fi
done

echo "Сгенерировано: $OUTPUT"
