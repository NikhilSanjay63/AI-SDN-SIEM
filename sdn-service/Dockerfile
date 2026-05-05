# Use the official Ryu SDN controller image (Pre-configured with Ryu)
FROM osrg/ryu:latest

# Install the Redis and Requests libraries for Python
RUN pip install redis==3.5.3 requests==2.27.1

WORKDIR /app

# Copy controllers and tests
COPY controllers/ /app/controllers/
COPY tests/ /app/tests/

# Ensure PYTHONPATH is set so Ryu can find the modules
ENV PYTHONPATH=/app
