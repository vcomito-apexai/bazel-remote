#!/bin/bash
set -eu

repo_root="$(cd "$(dirname "$0")" && pwd)"

echo "STABLE_GIT_COMMIT $(git -C "$repo_root" rev-parse HEAD)"

git_tag_info=$(git -C "$repo_root" tag --points-at HEAD | sort -h | paste -sd "," -)
echo "GIT_TAGS $git_tag_info"
