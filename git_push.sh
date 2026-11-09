#!/usr/bin/env bash

set -e

# Ensure we're inside a Git repository
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Error: Not inside a Git repository."
    exit 1
fi

# Check for a commit message
if [ $# -eq 0 ]; then
    echo "Usage: ./git_push.sh \"Commit message\""
    exit 1
fi

COMMIT_MSG="$*"

echo "==> Staging changes..."
git add .

echo "==> Repository status:"
git status --short

echo
read -rp "Continue with commit? [y/N]: " CONFIRM

if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

echo "==> Creating commit..."
git commit -m "$COMMIT_MSG"

BRANCH=$(git branch --show-current)

echo "==> Pushing to origin/$BRANCH..."
git push origin "$BRANCH"

echo
echo "✅ Done!"
