#!/bin/bash

trap "kill 0" EXIT

make grpc-server-start &
make grpc-internal-server-start &
make start-rest-api &

wait
