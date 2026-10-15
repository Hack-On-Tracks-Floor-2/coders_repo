-- ========================================================
-- VOID Security Events Database Schema (Person 3 Reference)
-- Compatible with SQLite and PostgreSQL
-- ========================================================

-- --------------------------------------------------------
-- 1. SQLite Schema DDL
-- --------------------------------------------------------

CREATE TABLE IF NOT EXISTS security_events (
    event_id VARCHAR(36) PRIMARY KEY,
    timestamp TEXT NOT NULL,
    path TEXT NOT NULL,
    method VARCHAR(10) NOT NULL,
    attack_type VARCHAR(32) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    decoy_triggered BOOLEAN NOT NULL DEFAULT 0,
    source_ip VARCHAR(64) NOT NULL,
    reason TEXT NOT NULL,
    action VARCHAR(32) NOT NULL,
    rule_ids TEXT NOT NULL DEFAULT '[]',     -- JSON-serialized list of strings: ["DECOY-001"]
    evidence TEXT NOT NULL DEFAULT '[]',     -- JSON-serialized list of strings
    request_id VARCHAR(64) NOT NULL,
    is_simulated BOOLEAN NOT NULL DEFAULT 0,
    ground_truth_label TEXT,
    scenario_id VARCHAR(64),
    session_id VARCHAR(64),
    user_agent TEXT,
    http_status INTEGER,
    response_time_ms REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Fast lookup indexes for common queries and dashboard filtering
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_events_attack_type ON security_events(attack_type);
CREATE INDEX IF NOT EXISTS idx_events_decoy ON security_events(decoy_triggered);
CREATE INDEX IF NOT EXISTS idx_events_ip ON security_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_is_simulated ON security_events(is_simulated);


-- --------------------------------------------------------
-- 2. PostgreSQL Schema DDL (Alternative)
-- --------------------------------------------------------

/*
CREATE TABLE IF NOT EXISTS security_events (
    event_id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    path TEXT NOT NULL,
    method VARCHAR(10) NOT NULL,
    attack_type VARCHAR(32) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    risk_score SMALLINT NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    decoy_triggered BOOLEAN NOT NULL DEFAULT FALSE,
    source_ip INET NOT NULL,
    reason TEXT NOT NULL,
    action VARCHAR(32) NOT NULL,
    rule_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    request_id VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pg_events_timestamp ON security_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_pg_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_pg_events_attack_type ON security_events(attack_type);
CREATE INDEX IF NOT EXISTS idx_pg_events_decoy ON security_events(decoy_triggered);
CREATE INDEX IF NOT EXISTS idx_pg_events_ip ON security_events(source_ip);
*/

-- --------------------------------------------------------
-- 3. Useful Verification / Analytical Queries
-- --------------------------------------------------------

-- Total events count
-- SELECT COUNT(*) FROM security_events;

-- Event breakdown by severity
-- SELECT severity, COUNT(*) AS count FROM security_events GROUP BY severity ORDER BY count DESC;

-- Decoy interactions count
-- SELECT COUNT(*) AS decoy_hits FROM security_events WHERE decoy_triggered = 1;

-- Top source IPs by incident count and average threat score
-- SELECT source_ip, COUNT(*) AS event_count, AVG(risk_score) AS avg_score, MAX(risk_score) AS peak_score
-- FROM security_events GROUP BY source_ip ORDER BY peak_score DESC, event_count DESC;
