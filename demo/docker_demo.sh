#!/usr/bin/env bash

# build dokcer image if not built before
# docker build . -t=multi-party-ecdsa

mkdir -p ~/KZen-networks/multi-party-ecdsa/temp/
sudo cp Rocket.toml ~/KZen-networks/multi-party-ecdsa/temp/
sudo cp params ~/KZen-networks/multi-party-ecdsa/temp/
sudo cp demo/run_in_docker.sh ~/KZen-networks/multi-party-ecdsa/temp/

docker-compose up