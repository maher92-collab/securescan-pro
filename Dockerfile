# Multi-stage build for production
FROM node:18-alpine as frontend-build

WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# Python backend
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    libssl-dev \
    libffi-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY app/ ./app/

# Copy built frontend to static directory
COPY --from=frontend-build /app/frontend/build ./static/

# Create reports directory
RUN mkdir -p reports

# Create non-root user
RUN useradd -m -u 1000 scanner && chown -R scanner:scanner /app
USER scanner

# Use PORT environment variable from Render
CMD uvicorn app.main:app --host 0.0.0.0 --port $PORT