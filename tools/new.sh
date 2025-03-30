#!/bin/bash

POSTS_DIR="_posts"
ASSETS_DIR="assets/posts"
DATE=$(date +%Y-%m-%d)
TIMEZONE="+0900"

if [ -z "$1" ]; then
  echo "Usage: $0 \"title\""
  exit 1
fi

TITLE="$1"
FILENAME_TITLE=$(echo "$TITLE" | tr ' ' '-')
CTF=false

if [[ "$TITLE" =~ [Cc][Tt][Ff] && "$TITLE" =~ [Ww][Rr][Ii][Tt][Ee][Uu][Pp] ]]; then
  CTF=true
fi

FILEPATH="$POSTS_DIR/${DATE}-${FILENAME_TITLE}.md"

mkdir -p "$POSTS_DIR" "$ASSETS_DIR/${DATE}-${FILENAME_TITLE}"
if [ -f "$FILEPATH" ]; then
  echo "Error: File already exists -> $FILEPATH"
  exit 1
fi

touch "$FILEPATH"

if $CTF; then
  cat >"$FILEPATH" <<EOF
---
title: $TITLE
date: $DATE / $TIMEZONE
categories: [CTF Writeup]
tags: [Web]
toc: true
pin: false
comments: false
math: false
mermaid: false
---

## web/chall (solves, points)

**solver**

\`\`\`ts

\`\`\`
EOF
else
  cat >"$FILEPATH" <<EOF
---
title: $TITLE
description: DESCRIPTION
date: $DATE / $TIMEZONE
categories: []
tags: []
toc: true
pin: false
comments: false
math: false
mermaid: false
---
EOF
fi

echo "File created: $FILEPATH"
echo "Assets folder created: $ASSETS_DIR/${DATE}-${FILENAME_TITLE}"
