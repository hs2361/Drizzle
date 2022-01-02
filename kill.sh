#!/bin/bash
docker-compose down
docker image rm drizzle_server:latest
docker image rm drizzle_client:latest
