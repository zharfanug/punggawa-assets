#!/bin/bash

# Script to reset git history and create a fresh main branch with latest tag
# This will permanently delete all git history - use with caution!

set -euo pipefail  # Exit on error, undefined variables, and pipe failures

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Get script and workspace directories
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
WORKSPACE_DIR=$(dirname "$SCRIPT_DIR")

log_info "Workspace directory: $WORKSPACE_DIR"

# Check if we're in a git repository
if [ ! -d "$WORKSPACE_DIR/.git" ]; then
    log_error "Not a git repository: $WORKSPACE_DIR"
    exit 1
fi

# Change to workspace directory
cd "$WORKSPACE_DIR" || {
    log_error "Failed to change to workspace directory: $WORKSPACE_DIR"
    exit 1
}

# Check if there are uncommitted changes
if ! git diff --quiet || ! git diff --cached --quiet; then
    log_warning "There are uncommitted changes in the repository"
    read -p "Do you want to continue? This will include all changes in the new commit. (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Operation cancelled by user"
        exit 0
    fi
fi

# Confirm destructive operation
log_warning "This operation will:"
log_warning "  - Delete all git history"
log_warning "  - Create a new orphaned branch"
log_warning "  - Force push to origin/main"
log_warning "  - Replace the 'latest' tag"
echo
read -p "Are you sure you want to continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log_info "Operation cancelled by user"
    exit 0
fi

log_info "Starting git history reset..."

# Store current branch name for reference
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
log_info "Current branch: $CURRENT_BRANCH"

# Check if we have a remote origin
if ! git remote get-url origin >/dev/null 2>&1; then
    log_error "No origin remote found. Please add a remote origin first."
    exit 1
fi

# Create orphaned branch
log_info "Creating orphaned branch 'latest_branch'..."
if ! git checkout --orphan latest_branch; then
    log_error "Failed to create orphaned branch"
    exit 1
fi

# Add all files (respecting .gitignore)
log_info "Adding all files..."
git add .

# Check if there are files to commit
if git diff --cached --quiet; then
    log_error "No files to commit. Repository appears to be empty."
    exit 1
fi

# Commit with timestamp
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
COMMIT_MESSAGE="Initial commit"
# Check if the first argument is provided
if [ -n "${1:-}" ]; then
    COMMIT_MESSAGE="$1"
fi

log_info "Creating initial commit: $COMMIT_MESSAGE"
git commit -m "$COMMIT_MESSAGE"

# Delete old main branch (with error handling)
log_info "Removing old main branch..."
if git branch | grep -q "main"; then
    git branch -D main || log_warning "Could not delete old main branch (may not exist)"
else
    log_info "No existing main branch to delete"
fi

# Rename current branch to main
log_info "Renaming branch to main..."
git branch -m main

# Force push to origin
log_info "Force pushing to origin/main..."
if ! git push -f origin main; then
    log_error "Failed to push to origin/main"
    exit 1
fi

log_success "Successfully pushed new main branch"

# Handle tag operations
log_info "Managing 'latest' tag..."

# Delete existing tag (local and remote)
if git tag | grep -q "^latest$"; then
    log_info "Deleting existing local 'latest' tag..."
    git tag -d latest
fi

# Check if tag exists on remote and delete it
if git ls-remote --tags origin | grep -q "refs/tags/latest"; then
    log_info "Deleting existing remote 'latest' tag..."
    git push origin :refs/tags/latest || log_warning "Could not delete remote tag"
fi

# Create new tag
log_info "Creating new 'latest' tag..."
git tag latest

# Push new tag
log_info "Pushing 'latest' tag to origin..."
if ! git push origin latest; then
    log_error "Failed to push 'latest' tag"
    exit 1
fi

log_success "Successfully created and pushed 'latest' tag"

# Final status
log_success "Git history reset completed successfully!"
log_info "Repository now has a clean history with:"
log_info "  - Single commit on main branch"
log_info "  - 'latest' tag pointing to current commit"
log_info "  - All previous history removed"

# Show final commit info
echo
log_info "Final commit details:"
git log --oneline -1
echo
log_info "Available tags:"
git tag -l
