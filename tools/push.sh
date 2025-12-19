#!/bin/bash

# Script to commit changes, push to main, and update latest tag
# Usage: ./push.sh [commit_message]

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

# Check if we have a remote origin
if ! git remote get-url origin >/dev/null 2>&1; then
    log_error "No origin remote found. Please add a remote origin first."
    exit 1
fi

# Default commit message with timestamp
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
commit_msg="Minor adjustments - $TIMESTAMP"

# Check if the first argument is provided
if [ -n "${1:-}" ]; then
    commit_msg="$1"
fi

log_info "Commit message: $commit_msg"

# Check if there are any changes to commit
if git diff --quiet && git diff --cached --quiet; then
    log_warning "No changes detected in the repository"
    read -p "Do you want to continue anyway? This will just update the tag. (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Operation cancelled by user"
        exit 0
    fi
    SKIP_COMMIT=true
else
    SKIP_COMMIT=false
fi

# Show what will be committed (if there are changes)
if [ "$SKIP_COMMIT" = false ]; then
    echo
    log_info "Changes to be committed:"
    git status --porcelain
    echo
    
    # Add all changes
    log_info "Adding all changes..."
    git add .
    
    # Commit changes
    log_info "Committing changes..."
    if ! git commit -m "$commit_msg"; then
        log_error "Failed to commit changes"
        exit 1
    fi
    
    log_success "Changes committed successfully"
fi

# Push to main branch
log_info "Pushing to origin/main..."
if ! git push origin main; then
    log_error "Failed to push to origin/main"
    exit 1
fi

log_success "Successfully pushed to origin/main"

# Handle tag operations
log_info "Managing 'latest' tag..."

# Delete existing local tag if it exists
if git tag | grep -q "^latest$"; then
    log_info "Deleting existing local 'latest' tag..."
    git tag -d latest
fi

# Create new tag
log_info "Creating new 'latest' tag..."
git tag latest

# Push new tag (force to overwrite remote tag)
log_info "Pushing 'latest' tag to origin..."
if ! git push origin latest --force; then
    log_error "Failed to push 'latest' tag"
    exit 1
fi

log_success "Successfully updated 'latest' tag"

# Final status
log_success "Push completed successfully!"
if [ "$SKIP_COMMIT" = false ]; then
    log_info "Latest commit:"
    git log --oneline -1
else
    log_info "No new commit created, only tag updated"
fi

echo
log_info "Current status:"
git status --porcelain || log_info "Working directory clean"