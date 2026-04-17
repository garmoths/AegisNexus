-- PostgreSQL Setup Script for AegisNexus
-- Run as postgres user: sudo -u postgres psql -f scripts/db_setup.sql
-- OR: sudo -u postgres psql < scripts/db_setup.sql

-- Create database if not exists
CREATE DATABASE IF NOT EXISTS phishing_db OWNER postgres ENCODING 'UTF8';

-- Connect to database
\c phishing_db

-- Grant all privileges on public schema to postgres user
GRANT ALL PRIVILEGES ON SCHEMA public TO postgres;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO postgres;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO postgres;

-- Create necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Verify setup
SELECT 'Tables:' as info;
\dt
SELECT 'Extensions:' as info;
\dx
