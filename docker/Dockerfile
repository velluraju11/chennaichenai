# HPTA Security Suite - Production Docker Container
# Optimized for cloud hosting and production deployment
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies for security tools
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    wget \
    unzip \
    binutils \
    file \
    bsdmainutils \
    nginx \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /app/uploads /app/reports /app/temp_reports /app/static /app/templates /app/sessions

# Copy requirements first for better Docker layer caching
COPY requirements_production.txt /app/
RUN pip install --no-cache-dir -r requirements_production.txt

# Copy application files
COPY . /app/

# Set environment variables for production
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1
ENV HOST=0.0.0.0
ENV PORT=5000

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash hpta
RUN chown -R hpta:hpta /app
USER hpta

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Start command for production
CMD ["python", "start_hpta_production.py"]

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