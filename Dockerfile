FROM python:3.10-bullseye

WORKDIR /app

ARG WITH_COMPARISON=0

RUN if [ "$WITH_COMPARISON" = "1" ]; then \
		apt-get update && apt-get install -y --no-install-recommends \
			swig \
			python3-dev \
			build-essential \
			cmake \
			ninja-build \
			pkg-config && \
		rm -rf /var/lib/apt/lists/*; \
	fi

COPY . .

RUN if [ "$WITH_COMPARISON" = "1" ]; then \
		pip install -e ".[dev,bench]"; \
	else \
		pip install -e ".[dev]"; \
	fi

CMD ["python", "-m", "sphincsplus"]
