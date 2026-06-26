#!/usr/bin/bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "shallow-clone.sh src-dir dst-dir"
    exit 1
fi

src="$1"
dst="$2"

if [ -d "$dst" ]; then
    echo "$dst exists"
    exit 1
fi

commit=$(cd "$src" && git rev-parse HEAD)
echo "Cloning local repo $src commit $commit into $dst"

mkdir -p "$dst"
cd "$dst"
git init
git remote add origin "$src"
git fetch --depth 1 origin "$commit"
git checkout FETCH_HEAD

echo "Done"
