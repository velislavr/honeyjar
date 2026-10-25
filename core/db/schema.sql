-- Idempotent schema, applied on API/worker startup.
CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS events (
    ts            timestamptz NOT NULL,
    sensor_id     text        NOT NULL,
    honeypot      text        NOT NULL,
    proto         text,
    event_type    text        NOT NULL,
    src_ip        inet        NOT NULL,
    src_port      integer,
    dst_port      integer,
    session_id    text,
    username      text,
    password      text,
    login_success boolean,
    command       text,
    http_method   text,
    http_path     text,
    http_ua       text,
    http_body     text,
    payload_hash  text,
    download_url  text,
    country_code  text,
    country       text,
    city          text,
    lat           double precision,
    lon           double precision,
    asn           integer,
    as_org        text,
    cves          text[]      NOT NULL DEFAULT '{}',
    tags          text[]      NOT NULL DEFAULT '{}',
    techniques    text[]      NOT NULL DEFAULT '{}',
    extra         jsonb       NOT NULL DEFAULT '{}'
);

SELECT create_hypertable('events', 'ts', if_not_exists => TRUE, chunk_time_interval => INTERVAL '1 day');

CREATE INDEX IF NOT EXISTS events_src_ip_ts   ON events (src_ip, ts DESC);
CREATE INDEX IF NOT EXISTS events_type_ts     ON events (event_type, ts DESC);
CREATE INDEX IF NOT EXISTS events_session     ON events (session_id, ts) WHERE session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS events_cves        ON events USING gin (cves);
CREATE INDEX IF NOT EXISTS events_techniques  ON events USING gin (techniques);

-- Compress chunks older than 7 days (columnar, typically 10-20x smaller).
DO $$
BEGIN
    IF NOT (SELECT compression_enabled FROM timescaledb_information.hypertables
            WHERE hypertable_name = 'events') THEN
        ALTER TABLE events SET (timescaledb.compress, timescaledb.compress_segmentby = 'event_type');
    END IF;
END $$;
SELECT add_compression_policy('events', INTERVAL '7 days', if_not_exists => TRUE);

-- Per-minute rollup used for long-range timelines.
CREATE MATERIALIZED VIEW IF NOT EXISTS events_1m
WITH (timescaledb.continuous) AS
SELECT time_bucket(INTERVAL '1 minute', ts) AS bucket,
       count(*) FILTER (WHERE event_type IN ('connect', 'http_request', 'exploit')) AS attacks,
       count(*) FILTER (WHERE cardinality(cves) > 0) AS exploits,
       count(*) FILTER (WHERE event_type = 'login_attempt') AS logins,
       count(*) AS events
FROM events
GROUP BY bucket
WITH NO DATA;

SELECT add_continuous_aggregate_policy('events_1m',
    start_offset => INTERVAL '2 hours', end_offset => INTERVAL '1 minute',
    schedule_interval => INTERVAL '1 minute', if_not_exists => TRUE);

-- CVE metadata: curated rule names + CISA KEV + FIRST EPSS.
CREATE TABLE IF NOT EXISTS cve_info (
    cve_id            text PRIMARY KEY,
    name              text,
    description       text,
    vendor            text,
    product           text,
    cvss              real,
    kev               boolean NOT NULL DEFAULT false,
    kev_date_added    date,
    kev_ransomware    boolean,
    epss              real,
    epss_percentile   real,
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS malware (
    sha256      text PRIMARY KEY,
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL,
    hits        integer NOT NULL DEFAULT 1,
    source_url  text,
    src_ips     inet[] NOT NULL DEFAULT '{}',
    family      text,
    file_type   text,
    intel_tags  text[],
    checked_at  timestamptz
);

CREATE TABLE IF NOT EXISTS ip_intel (
    ip            inet PRIMARY KEY,
    abuse_score   integer,
    total_reports integer,
    usage_type    text,
    isp           text,
    is_tor        boolean,
    checked_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sensors (
    id         text PRIMARY KEY,
    last_seen  timestamptz
);
