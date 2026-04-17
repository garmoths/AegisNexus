-- PostgreSQL Setup Script for AegisNexus
-- Run as superuser (postgres): psql -U postgres -f scripts/db_setup.sql

-- Create database if not exists
CREATE DATABASE phishing_db OWNER postgres ENCODING 'UTF8' LC_COLLATE 'en_US.UTF-8' LC_CTYPE 'en_US.UTF-8';

-- Connect to database
\c phishing_db

-- Grant all privileges on public schema to postgres user
GRANT ALL PRIVILEGES ON SCHEMA public TO postgres;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO postgres;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO postgres;

-- Create necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Verify setup
\dt
\l
