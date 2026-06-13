# Use a small, supported Python base image
FROM python:3.12-slim

# Create non-root user
RUN useradd --create-home --uid 1000 appuser
WORKDIR /home/appuser

# Copy minimal files and install runtime deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY flareproxy.py .
# Expose port
EXPOSE 8080

# Switch to non-root user
USER appuser

HEALTHCHECK --interval=1m --timeout=10s --start-period=10s \
  CMD curl -f http://127.0.0.1:8080/healthz || exit 1

CMD ["python", "flareproxy.py"]