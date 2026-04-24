FROM python:3.10

WORKDIR /app
COPY . .

ARG WITH_BENCH=0

RUN if [ "$WITH_BENCH" = "1" ]; then \
		apt-get update && apt-get install -y --no-install-recommends \
			swig3.0 \
			python3-dev \
			build-essential \
			cmake \
			ninja-build \
			pkg-config && \
		rm -rf /var/lib/apt/lists/* && \
		pip install -e ".[dev,bench]"; \
	else \
		pip install -e ".[dev]"; \
	fi

CMD ["python", "-m", "sphincsplus"]
