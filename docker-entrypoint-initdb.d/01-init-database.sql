-- PostgreSQL initialization script for enterprise_mcp_server
-- This script runs automatically when the Postgres container first starts
-- It ensures the database exists and is properly configured

-- Note: The POSTGRES_DB environment variable should create the database,
-- but this script provides a failsafe and additional setup

-- Ensure database exists (this is mostly redundant with POSTGRES_DB but provides safety)
SELECT 'CREATE DATABASE enterprise_mcp_server'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'enterprise_mcp_server')\gexec

-- Log confirmation
DO $$
BEGIN
    RAISE NOTICE 'Database enterprise_mcp_server is ready';
END $$;
