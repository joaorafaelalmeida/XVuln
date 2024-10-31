#!/bin/bash

bash ./docker/docker-compose-check.sh
if [[ $? -eq 1 ]]; then exit 1; fi

if [ $# -eq 0 ]
then
    echo "Starting docker compose in the foreground ..."
    # Compose V2 integrates compose functions into the Docker platform,
    # continuing to support most of the previous docker-compose features
    # and flags. You can run Compose V2 by replacing the hyphen (-) with
    # a space, using docker compose, instead of docker-compose.
    docker compose -f docker/docker-compose.yml up --build --no-deps
else
    echo "Starting docker compose in the foreground with additional parameter $1 ..."
    # Compose V2 integrates compose functions into the Docker platform,
    # continuing to support most of the previous docker-compose features
    # and flags. You can run Compose V2 by replacing the hyphen (-) with
    # a space, using docker compose, instead of docker-compose.
    docker compose -f docker/docker-compose.yml up --build --no-deps $1
fi
