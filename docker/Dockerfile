# HPTA Security Suite - Complete Docker Container
# Frontend + Backend + CLI Server + Security Tools
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    wget \
    unzip \
    binutils \
    file \
    bsdmainutils \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /app/uploads /app/reports /app/temp_reports /app/static /app/templates

# Copy requirements first for better caching
COPY requirements_hpta.txt /app/
RUN pip install --no-cache-dir -r requirements_hpta.txt && \
    pip install --no-cache-dir gunicorn gevent

# Copy application files
COPY . /app/

# Copy security tools
COPY HexaWebScanner/ /app/HexaWebScanner/
COPY reverseengineering/ /app/reverseengineering/
COPY ryha-malware-analyzer/ /app/ryha-malware-analyzer/

# Set permissions
RUN chmod +x /app/*.py
RUN chmod +x /app/HexaWebScanner/*.py
RUN chmod +x /app/reverseengineering/*.py
RUN chmod +x /app/ryha-malware-analyzer/*.py

# Create logs directory
RUN mkdir -p /app/logs

# Create non-root user for security
RUN useradd -m -u 1000 hpta && chown -R hpta:hpta /app
USER hpta

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Environment variables
ENV FLASK_APP=hpta_security_suite.py
ENV FLASK_ENV=production
ENV PYTHONPATH=/app

# Start command
CMD ["python", "docker/docker_start.py"]