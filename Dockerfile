FROM python:3.12-slim

LABEL description="Enterprise MCP Gateway Server with Claude Code CLI"
LABEL version="1.3"
LABEL maintainer="George Dekker"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VERSION=1.8.3 \
    POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_CACHE_DIR=/var/cache/pypoetry \
    POETRY_NO_INTERACTION=1

# Add Poetry to PATH
ENV PATH="$POETRY_HOME/bin:$PATH"

WORKDIR /app

# Install system dependencies including Node.js, Poetry and clean up
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    ca-certificates \
    gnupg \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list \
    && apt-get update \
    && apt-get install -y nodejs \
    && curl -sSL https://install.python-poetry.org | python3 - --version $POETRY_VERSION \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Claude Code CLI globally
RUN npm install -g @anthropic-ai/claude-code

# Create directory for Claude configuration
RUN mkdir -p /root/.claude

# Copy Poetry configuration files
COPY pyproject.toml poetry.lock* ./

# Install Python dependencies using Poetry
RUN poetry config virtualenvs.create false && \
    poetry lock && \
    poetry install --no-interaction --no-ansi && \
    poetry cache clear --all .

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