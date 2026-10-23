# Use official Python 3.10 slim image as base
FROM python:3.10-slim-bullseye

# Prevent Python from writing pyc files to disk and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Avoid interactive prompts during packages installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies required for building PBC and Charm-Crypto
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    wget \
    git \
    m4 \
    flex \
    bison \
    libgmp-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Compile and install Stanford PBC (Pairing-Based Cryptography) library
WORKDIR /tmp
RUN wget --no-check-certificate https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz \
    && tar -xvf pbc-0.5.14.tar.gz \
    && cd pbc-0.5.14 \
    && ./configure \
    && make \
    && make install \
    && ldconfig \
    && cd /tmp \
    && rm -rf pbc-0.5.14*

# Clone and compile Charm-Crypto from official repository
RUN git clone https://github.com/JHUISI/charm.git \
    && cd charm \
    && ./configure.sh \
    && make \
    && make install \
    && cd /tmp \
    && rm -rf charm

# Set working directory for the application
WORKDIR /app

# Copy requirements and install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application files
COPY . .

# Expose port 5000 for the Flask API
EXPOSE 5000

# Serve the API and the prebuilt web client (client/ui/dist).
# Run the test suite instead with: docker compose run server python -m pytest tests/
ENV HOST=0.0.0.0
CMD ["python", "-m", "server.app"]
