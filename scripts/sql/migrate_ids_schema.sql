-- IDS MySQL schema migration (run once against ids_db)
-- Compatible with MariaDB / MySQL 8+

CREATE TABLE IF NOT EXISTS ids_statistics (
    id INT PRIMARY KEY DEFAULT 1,
    total_events BIGINT NOT NULL DEFAULT 0,
    safe_count BIGINT NOT NULL DEFAULT 0,
    suspicious_count BIGINT NOT NULL DEFAULT 0,
    dangerous_count BIGINT NOT NULL DEFAULT 0,
    unique_attackers_count INT NOT NULL DEFAULT 0,
    dangerous_ips_count INT NOT NULL DEFAULT 0,
    unique_attackers_json LONGTEXT NULL,
    dangerous_ips_json LONGTEXT NULL,
    dangerous_urls_json LONGTEXT NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO ids_statistics (id) VALUES (1);

CREATE TABLE IF NOT EXISTS packet_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp DOUBLE NOT NULL,
    captured_at_ms BIGINT NULL,
    src_ip VARCHAR(45) NULL,
    dst_ip VARCHAR(45) NULL,
    src_port INT NULL,
    dst_port INT NULL,
    protocol VARCHAR(16) NULL,
    duration DOUBLE NULL,
    packets INT NULL,
    bytes INT NULL,
    url TEXT NULL,
    classification VARCHAR(16) NOT NULL,
    ai_label VARCHAR(16) NULL,
    confidence DOUBLE NULL,
    anomaly_score DOUBLE NULL,
    ai_score DOUBLE NULL,
    risk_score DOUBLE NULL,
    reasons_json LONGTEXT NULL,
    ti_ip_json LONGTEXT NULL,
    ti_url_json LONGTEXT NULL,
    http_json LONGTEXT NULL,
    dns_json LONGTEXT NULL,
    payload_preview TEXT NULL,
    ai_explanation_json LONGTEXT NULL,
    INDEX ix_packet_logs_timestamp (timestamp),
    INDEX ix_packet_logs_ts_cls (timestamp, classification),
    INDEX ix_packet_logs_src_ts (src_ip, timestamp),
    INDEX ix_packet_logs_classification (classification),
    INDEX ix_packet_logs_dst_port (dst_port)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ai_analysis_history (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    analyzed_at DATETIME(6) NOT NULL,
    src_ip VARCHAR(45) NULL,
    dst_ip VARCHAR(45) NULL,
    classification VARCHAR(16) NOT NULL,
    ai_score DOUBLE NULL,
    risk_score DOUBLE NULL,
    rf_prob DOUBLE NULL,
    anomaly_strength DOUBLE NULL,
    features_json LONGTEXT NULL,
    explanation_json LONGTEXT NULL,
    INDEX ix_ai_history_ts (analyzed_at),
    INDEX ix_ai_history_src (src_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS threat_intel_cache (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    lookup_key VARCHAR(512) NOT NULL,
    lookup_type VARCHAR(16) NOT NULL,
    verdict VARCHAR(32) NULL,
    score DOUBLE NULL,
    payload_json LONGTEXT NULL,
    cached_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    UNIQUE KEY uq_ti_lookup (lookup_key, lookup_type),
    INDEX ix_ti_expires (expires_at),
    INDEX ix_ti_key (lookup_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dangerous_ips (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    first_seen DATETIME(6) NOT NULL,
    last_seen DATETIME(6) NOT NULL,
    event_count INT NOT NULL DEFAULT 1,
    max_risk_score DOUBLE NULL,
    reasons_json LONGTEXT NULL,
    UNIQUE KEY uq_dangerous_ip (ip_address),
    INDEX ix_dangerous_ip (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS training_data (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    created_at DOUBLE NOT NULL,
    features_json LONGTEXT NOT NULL,
    label VARCHAR(32) NOT NULL,
    INDEX ix_training_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- Legacy logs table additive columns
ALTER TABLE logs ADD COLUMN IF NOT EXISTS risk_score DOUBLE NULL;
ALTER TABLE logs ADD COLUMN IF NOT EXISTS ai_explanation_json LONGTEXT NULL;

