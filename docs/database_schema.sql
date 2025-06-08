# Database Schema for Enterprise MCP Server

This file outlines the PostgreSQL database schema used by the Enterprise MCP server.

## `mcp_tools` Table

Stores the main definition of registered tools.

```sql
CREATE TABLE IF NOT EXISTS mcp_tools (
    id SERIAL PRIMARY KEY,
    tool_id UUID NOT NULL UNIQUE,            -- Unique identifier for the tool across versions
    name TEXT NOT NULL UNIQUE,               -- User-defined name for the tool
    description TEXT NOT NULL,               -- Description of the tool's purpose
    code TEXT NOT NULL,                      -- The latest version of the tool's code (for single-file tools)
    is_multi_file BOOLEAN NOT NULL DEFAULT FALSE, -- Flag indicating if it's a multi-file tool
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);
```

## `mcp_tool_versions` Table

Stores historical versions of tools (optional, currently seems unused in main logic but table exists).

```sql
CREATE TABLE IF NOT EXISTS mcp_tool_versions (
    id SERIAL PRIMARY KEY,
    tool_id UUID NOT NULL REFERENCES mcp_tools(tool_id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL,
    code TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_by INTEGER REFERENCES users(id), -- Link to the user who created this version
    description TEXT,
    UNIQUE(tool_id, version_number)
);
```

## `mcp_tool_files` Table

Stores the content of individual files for multi-file tools.

```sql
CREATE TABLE IF NOT EXISTS mcp_tool_files (
    id SERIAL PRIMARY KEY,
    tool_id UUID NOT NULL REFERENCES mcp_tools(tool_id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    UNIQUE(tool_id, filename)             -- Ensure unique filenames per tool
);
```

## `users` Table

Stores user information for authentication and authorization.

```sql
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,          -- Unique username for login
    password_hash TEXT,                     -- Hashed password for standard login
    api_key_hash TEXT,                      -- Hashed API key (alternative auth)
    is_active BOOLEAN DEFAULT TRUE,         -- Flag to enable/disable user accounts
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);
```

## `roles` Table

Defines roles for grouping permissions.

```sql
CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,              -- Name of the role (e.g., 'admin', 'developer')
    description TEXT
);
```

## `permissions` Table

Defines specific permissions within the system.

```sql
CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,              -- Name of the permission (e.g., 'tool:create', 'user:manage')
    description TEXT
);
```

## `role_permissions` Table

Junction table linking roles to their assigned permissions.

```sql
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)    -- Many-to-many relationship
);
```

## `user_roles` Table

Junction table linking users to their assigned roles.

```sql
CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)          -- Many-to-many relationship
);
```

## `audit_logs` Table

Records significant events and actions within the system.

```sql
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL, -- When the event occurred
    actor_id INTEGER REFERENCES users(id),       -- User performing the action (nullable for system actions)
    actor_type TEXT NOT NULL,                  -- 'human', 'ai_agent', 'system'
    action_type TEXT NOT NULL,                 -- 'create', 'read', 'update', 'delete', 'execute', 'login', 'logout' etc.
    resource_type TEXT NOT NULL,               -- 'tool', 'user', 'role', 'permission' etc.
    resource_id TEXT,                          -- The ID of the affected resource (can be string/UUID)
    status TEXT NOT NULL,                      -- 'success', 'failure'
    details JSONB,                             -- Additional context (e.g., parameters used, error messages)
    request_id TEXT,                           -- ID to trace requests across services
    ip_address TEXT                            -- IP address of the actor
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS audit_logs_timestamp_idx ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS audit_logs_actor_id_idx ON audit_logs(actor_id);
CREATE INDEX IF NOT EXISTS audit_logs_resource_type_resource_id_idx ON audit_logs(resource_type, resource_id);
```

## OAuth Tables

These tables support OAuth 2.0 authentication flows (currently seems unused by the main MCP client config).

```sql
-- OAuth clients table
CREATE TABLE IF NOT EXISTS oauth_clients (
    id SERIAL PRIMARY KEY,
    client_id TEXT UNIQUE NOT NULL,
    client_secret TEXT NOT NULL,            -- Hashed client secret
    client_name TEXT NOT NULL,
    redirect_uris JSONB NOT NULL,         -- List of allowed redirect URIs
    client_uri TEXT,
    logo_uri TEXT,
    scope TEXT,                             -- Space-separated list of allowed scopes
    contacts JSONB,
    client_id_issued_at BIGINT NOT NULL,
    client_secret_expires_at BIGINT NOT NULL -- 0 means never expires
);
CREATE INDEX IF NOT EXISTS oauth_clients_client_id_idx ON oauth_clients(client_id);

-- OAuth authorization codes table
CREATE TABLE IF NOT EXISTS oauth_auth_codes (
    id SERIAL PRIMARY KEY,
    code TEXT UNIQUE NOT NULL,              -- The authorization code itself
    client_id TEXT NOT NULL,
    user_id INTEGER REFERENCES users(id),
    scope TEXT,
    code_challenge TEXT NOT NULL,           -- PKCE code challenge
    code_challenge_method TEXT NOT NULL,    -- PKCE method (e.g., 'S256')
    redirect_uri TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX IF NOT EXISTS oauth_auth_codes_code_idx ON oauth_auth_codes(code);
CREATE INDEX IF NOT EXISTS oauth_auth_codes_expires_at_idx ON oauth_auth_codes(expires_at);

-- OAuth access tokens table
CREATE TABLE IF NOT EXISTS oauth_access_tokens (
    id SERIAL PRIMARY KEY,
    token TEXT UNIQUE NOT NULL,             -- The access token
    client_id TEXT NOT NULL,
    user_id INTEGER REFERENCES users(id),
    scope TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX IF NOT EXISTS oauth_access_tokens_token_idx ON oauth_access_tokens(token);
CREATE INDEX IF NOT EXISTS oauth_access_tokens_expires_at_idx ON oauth_access_tokens(expires_at);

-- OAuth refresh tokens table
CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    id SERIAL PRIMARY KEY,
    token TEXT UNIQUE NOT NULL,             -- The refresh token
    client_id TEXT NOT NULL,
    user_id INTEGER REFERENCES users(id),
    scope TEXT,
    access_token_id INTEGER REFERENCES oauth_access_tokens(id) ON DELETE CASCADE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_token_idx ON oauth_refresh_tokens(token);
``` 