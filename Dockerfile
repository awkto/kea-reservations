# Dockerfile for KEA DHCP Lease Manager
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY kea_client.py .
COPY version.txt .
COPY templates/ ./templates/

# Create volume mount point for config
VOLUME ["/app/config"]

# Expose port
EXPOSE 5000

# Environment variables
ENV CONFIG_PATH=/app/config/config.yaml
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/api/health').raise_for_status()"

# Run with gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--timeout", "120", "app:app"]
