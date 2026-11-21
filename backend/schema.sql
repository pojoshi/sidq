CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS campaigns (
  id           BIGSERIAL PRIMARY KEY,
  name         TEXT        NOT NULL,
  first_seen   TIMESTAMPTZ NOT NULL,
  last_seen    TIMESTAMPTZ NOT NULL,
  report_count INT         NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS reports (
  id          BIGSERIAL PRIMARY KEY,
  observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  channel     TEXT        NOT NULL,
  sender      TEXT,
  verdict     TEXT        NOT NULL CHECK (verdict IN ('scam','careful','ok')),
  score       INT         NOT NULL CHECK (score BETWEEN 0 AND 100),
  signs       TEXT[]      NOT NULL DEFAULT '{}',
  masked_text TEXT        NOT NULL,
  indicators  TEXT[]      NOT NULL DEFAULT '{}',
  embedding   vector(256) NOT NULL,
  campaign_id BIGINT REFERENCES campaigns(id)
);

CREATE TABLE IF NOT EXISTS cases (
  id         TEXT PRIMARY KEY,
  report_id  BIGINT NOT NULL REFERENCES reports(id),
  answers    JSONB  NOT NULL DEFAULT '{}',
  timeline   JSONB  NOT NULL DEFAULT '[]',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS reports_embedding_hnsw ON reports USING hnsw (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS reports_indicators_gin ON reports USING gin (indicators);
CREATE INDEX IF NOT EXISTS reports_campaign ON reports (campaign_id);
