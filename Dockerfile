FROM alpine:latest

# Install required packages
RUN apk add --no-cache \
    python3 \
    py3-pip \
    curl \
    docker-cli \
    python3-dev \
    gcc \
    musl-dev \
    && rm -rf /var/cache/apk/*

# Set working directory
WORKDIR /app

# Create and activate a virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

# Copy and install requirements
COPY requirements.txt .
RUN pip install --upgrade "pip>=25.3" && \
    pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY templates /app/templates

# Expose port for Flask
EXPOSE 5000

# Set entrypoint to run with waitress
CMD ["waitress-serve", "--host=0.0.0.0", "--port=5000", "app:app"]