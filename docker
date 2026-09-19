#!/bin/bash

IMAGE_NAME="debian"
CONTAINER_NAME="famine"

# Build the image
docker build -t "$IMAGE_NAME" .

# Run the container
docker run -it --name "$CONTAINER_NAME" "$IMAGE_NAME"

# Clean up
docker rm -f "$CONTAINER_NAME"
