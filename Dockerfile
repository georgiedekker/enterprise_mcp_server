FROM python:3.12-slim

LABEL description="Enterprise MCP Gateway Server (No Operational Tools)"
LABEL version="1.0"
LABEL maintainer="George Dekker"

WORKDIR /app

# Install system dependencies and clean up
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements files
COPY requirements.txt /app/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . /app/

# Expose the port that the app runs on
EXPOSE 8033

# Set environment variables for database connection
ENV PORT=8033
ENV HOST=0.0.0.0
ENV POSTGRES_HOST=postgres
ENV POSTGRES_PORT=5432
ENV POSTGRES_DB=enterprise_mcp_server
ENV POSTGRES_USER=postgres
ENV POSTGRES_PASSWORD=postgres

# Run the Enterprise MCP ASGI application using Uvicorn
CMD ["uvicorn", "src.asgi:app", "--host", "0.0.0.0", "--port", "8033"]