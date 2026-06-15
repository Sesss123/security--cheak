-- Security Platform Database Schema
-- PostgreSQL 16

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm"; -- for text search

-- ── Users ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email         VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  name          VARCHAR(255) NOT NULL,
  role          VARCHAR(50)  NOT NULL DEFAULT 'user', -- 'admin' | 'user'
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ── Scans ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scans (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_url      TEXT NOT NULL,
  status          VARCHAR(50) NOT NULL DEFAULT 'pending', -- pending|running|completed|failed
  scan_types      TEXT[] NOT NULL DEFAULT '{}',
  options         JSONB NOT NULL DEFAULT '{}',
  started_at      TIMESTAMPTZ,
  completed_at    TIMESTAMPTZ,
  risk_score      DECIMAL(4,2),
  total_vulns     INT DEFAULT 0,
  critical_count  INT DEFAULT 0,
  high_count      INT DEFAULT 0,
  medium_count    INT DEFAULT 0,
  low_count       INT DEFAULT 0,
  info_count      INT DEFAULT 0,
  raw_result      JSONB,                    -- full Rust scanner JSON output
  error_message   TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scans_user_id  ON scans(user_id);
CREATE INDEX idx_scans_status   ON scans(status);
CREATE INDEX idx_scans_created  ON scans(created_at DESC);

-- ── Vulnerabilities ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vulnerabilities (
  id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id             UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  title               TEXT NOT NULL,
  description         TEXT NOT NULL,
  severity            VARCHAR(20) NOT NULL, -- CRITICAL|HIGH|MEDIUM|LOW|INFO
  category            VARCHAR(100),
  cvss_score          DECIMAL(4,2),
  cvss_vector         VARCHAR(255),
  affected_url        TEXT,
  affected_parameter  TEXT,
  owasp_category      VARCHAR(100),
  cwe_id              INT,
  evidence            JSONB DEFAULT '[]',
  remediation         TEXT,
  "references"        TEXT[] DEFAULT '{}',
  cve_id              VARCHAR(50),
  exploit_available   BOOLEAN DEFAULT FALSE,
  -- AI enrichment
  ai_explanation      TEXT,
  ai_business_impact  TEXT,
  ai_remediation_steps JSONB DEFAULT '[]',
  ai_code_example     TEXT,
  fix_priority        INT,
  attack_path         JSONB DEFAULT '[]',
  attack_probability  VARCHAR(20),
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vulns_scan_id  ON vulnerabilities(scan_id);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);

-- ── Reports ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS reports (
  id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id           UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  user_id           UUID NOT NULL REFERENCES users(id),
  title             TEXT NOT NULL,
  executive_summary TEXT,
  risk_rating       VARCHAR(20),
  pdf_path          TEXT,               -- path to generated PDF
  generated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── API Keys ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_keys (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name        VARCHAR(255) NOT NULL,
  key_hash    VARCHAR(255) NOT NULL UNIQUE,
  last_used   TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Seed: default admin user (password: admin123 - change in prod!) ──
INSERT INTO users (email, password_hash, name, role)
VALUES (
  'admin@securityplatform.local',
  '$2b$10$rQJ5qJ3z3z3z3z3z3z3z3uXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
  'Admin',
  'admin'
) ON CONFLICT DO NOTHING;
