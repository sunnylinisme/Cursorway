#!/bin/sh
# Keep only the newest $KEEP published versions (vX.Y.Z tags and their releases); older releases
# and tags are deleted. The "test-build" pre-release is never touched. Commits stay in history.
# Usage: prune-releases.sh OWNER/REPO [KEEP]   (needs gh with contents:write on the repo)
set -eu
REPO="$1"; KEEP="${2:-3}"
tags=$(gh api "repos/$REPO/tags" --paginate --jq '.[].name' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -rV || true)
releases=$(gh release list --repo "$REPO" -L 1000 --json tagName -q '.[].tagName')
n=0
for tag in $tags; do
  n=$((n + 1)); [ "$n" -le "$KEEP" ] && { echo "keep $tag"; continue; }
  if echo "$releases" | grep -qx "$tag"; then
    gh release delete "$tag" --repo "$REPO" --cleanup-tag --yes && echo "deleted release and tag $tag"
  else
    gh api -X DELETE "repos/$REPO/git/refs/tags/$tag" && echo "deleted tag $tag"
  fi
done
