#!/bin/bash
# init_db.sh

# Load environment variables from .env file
set -a
source .env
set +a

docker exec -it enterprise_mcp_server-postgres-1 psql -U postgres -d enterprise_mcp_server -c "
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    api_key_hash TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    email TEXT
);

CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT
);
"
# Add admin user

# Check if DEFAULT_ADMIN_PASSWORD_HASH is set
if [ -z "${DEFAULT_ADMIN_PASSWORD_HASH}" ]; then
  echo "Error: DEFAULT_ADMIN_PASSWORD_HASH environment variable is not set."
  echo "Please define it in your .env file and ensure it is loaded into your shell's environment."
  echo "Example: export DEFAULT_ADMIN_PASSWORD_HASH=\'$2b$12$SomeHashValueHere...'" 
  exit 1
fi

docker exec -it enterprise_mcp_server-postgres-1 psql -U postgres -d enterprise_mcp_server -c "
INSERT INTO users (username, password_hash, is_active, created_at)
VALUES ('admin', '${DEFAULT_ADMIN_PASSWORD_HASH}', TRUE, NOW())
ON CONFLICT (username) DO NOTHING;
"