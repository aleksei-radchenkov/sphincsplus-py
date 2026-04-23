#!/bin/sh

docker build -t sphincsplus .

docker run sphincsplus pytest tests/
docker run sphincsplus

flake8 .

docker build -t sphincsplus .
docker run --rm sphincsplus pytest tests/ -q


docker build -t sphincsplus .
docker run --rm sphincsplus pytest --benchmark-only
