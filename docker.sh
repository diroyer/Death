#!/bin/bash

IMAGE_NAME="debian_test"
CONTAINER_NAME="famine"

# Build the image
docker build -t "$IMAGE_NAME" .

# Run the container
docker run -dit --name "$CONTAINER_NAME" "$IMAGE_NAME"

# Copy the current directory to the container
docker cp . "$CONTAINER_NAME":/root/docker

# Launch a shell in the container
docker exec -it "$CONTAINER_NAME" zsh

# Clean up
docker rm -f "$CONTAINER_NAME"
