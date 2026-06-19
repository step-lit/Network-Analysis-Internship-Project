#!/usr/bin/env bash
#
# build-images.sh
#
# This script builds all the project's Docker images from their Dockerfiles, applying
# the correct tag for each one. If an image with the same tag already exists, Docker 
# simply replaces it (the old image becomes <none> / dangling and can be cleaned up 
# separately — see the note at the end of this script).
#
# Usage:
#   Open a terminal in the same directory as this script and run
#   the following command:
#
#     bash build-images.sh
#
# Run this script from the directory that contains the Dockerfiles, or
# adjust DOCKERFILES_DIR below to point to the correct folder.

set -euo pipefail


# Basic prerequisite check: docker must be installed and reachable.
if ! command -v docker &> /dev/null; then
    echo "Error: 'docker' command not found. Install Docker before running this script."
    exit 1
fi
 
if ! docker info &> /dev/null; then
    echo "Error: Docker daemon not reachable. Is Docker running? Do you have permission to use it (e.g. are you in the 'docker' group)?"
    exit 1
fi


# Directory containing the *.Dockerfile files (change if needed)
DOCKERFILES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Map: "<dockerfile name without extension>:<image tag>"
# Add a new line here whenever you add a new Dockerfile to the project.
declare -A IMAGES=(
    ["kathara-base-nmap"]="kathara/base-nmap:latest"
    ["kathara-base-postgresql"]="kathara/base-postgresql:latest"
    ["kathara-base-python3-nmap3"]="kathara/base-python3-nmap3:latest"
    ["kathara-base-telnet-ftp"]="kathara/base-telnet-ftp:latest"
    ["vulhub-cups-tools"]="vulhub/cups-tools:latest"
    ["vulhub-redis-tools"]="vulhub/redis-tools:latest"
    ["vulhub-tomcat-tools"]="vulhub/tomcat-tools:latest"
)

echo "================================================================="
echo "  Building ${#IMAGES[@]} Docker images from: $DOCKERFILES_DIR"
echo "================================================================="
echo

FAILED=()

for name in "${!IMAGES[@]}"; do
    dockerfile="$DOCKERFILES_DIR/${name}.Dockerfile"
    tag="${IMAGES[$name]}"

    if [[ ! -f "$dockerfile" ]]; then
        echo "Skipping '$tag': file not found ($dockerfile)"
        FAILED+=("$tag (missing Dockerfile)")
        continue
    fi

    echo "-----------------------------------------------------------------"
    echo "Building $tag"
    echo "  Dockerfile: $dockerfile"
    echo "-----------------------------------------------------------------"

    # -f: explicit Dockerfile path: -t: tag (overwrites existing tag of the same name)
    # The build context is the Dockerfiles directory itself.
    if docker build -f "$dockerfile" -t "$tag" "$DOCKERFILES_DIR"; then
        echo "Done: $tag"
    else
        echo "Build failed: $tag"
        FAILED+=("$tag")
    fi
    echo
done

echo "================================================================="
if [[ ${#FAILED[@]} -eq 0 ]]; then
    echo "  All images built successfully."
else
    echo "  Completed with errors in the following images:"
    for f in "${FAILED[@]}"; do
        echo "    - $f"
    done
fi
echo "================================================================="

# Optional cleanup hint: rebuilding with the same tag leaves the previous
# image as <none>/dangling. To remove dangling images, run:
#   docker image prune -f
