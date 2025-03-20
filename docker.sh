#!/bin/bash

IMAGE_NAME="debian_test"
CONTAINER_NAME="famine"

# Build the image if it was removed or doesn't exist
docker build -t "$IMAGE_NAME" .

# Run a new container with the updated image
docker run --rm -it --name "$CONTAINER_NAME" "$IMAGE_NAME"

