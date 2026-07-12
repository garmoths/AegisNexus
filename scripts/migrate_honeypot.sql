CREATE TABLE IF NOT EXISTS honeypot_events (
    id SERIAL PRIMARY KEY,
    client_ip VARCHAR(128),
    user_agent VARCHAR(512),
    path VARCHAR(256),
    referer VARCHAR(512),
    note TEXT,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (NOW() AT TIME ZONE 'utc')
);
CREATE INDEX IF NOT EXISTS ix_honeypot_events_client_ip ON honeypot_events (client_ip);
CREATE INDEX IF NOT EXISTS ix_honeypot_events_created_at ON honeypot_events (created_at);
