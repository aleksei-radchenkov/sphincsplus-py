#!/bin/sh

docker build -t sphincsplus .

docker run sphincsplus pytest tests/
docker run sphincsplus

flake8 .

# add benchmarks later or whatever))
