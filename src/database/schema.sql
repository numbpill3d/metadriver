-- WiFi Logger Database Schema
-- SQLite3 compatible

-- Networks table (unique WiFi networks)
CREATE TABLE IF NOT EXISTS networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bssid TEXT NOT NULL,
    essid TEXT,
    essid_hash TEXT,  -- For hidden networks (SHA256 of empty string or ESSID)
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    security_type TEXT CHECK(security_type IN ('open', 'wpa', 'wpa2', 'wpa3', 'wpa2/wpa', 'wpa2/wpa3', 'wep', 'mixed', 'unknown')),
    cipher TEXT,
    vendor TEXT,
    channel_width INTEGER,
    max_rate REAL,
    capabilities TEXT,
    ht_caps TEXT,
    vht_caps TEXT,
    he_caps TEXT,
    notes TEXT,
    is_hidden BOOLEAN DEFAULT 0,
    UNIQUE(bssid)
);

-- Observations table (individual sightings)
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id INTEGER NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    latitude REAL,
    longitude REAL,
    altitude REAL,
    accuracy REAL,  -- HDOP for GPS
    rssi INTEGER NOT NULL DEFAULT 0,
    channel INTEGER,
    frequency INTEGER,
    noise_level INTEGER,
    data_rate REAL,
    gps_speed REAL,
    gps_heading REAL,
    gps_fix_type INTEGER,
    device_mac TEXT,  -- Your adapter MAC
    FOREIGN KEY (network_id) REFERENCES networks(id) ON DELETE CASCADE
);

-- Devices table (vendor info)
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    oui TEXT NOT NULL,  -- First 3 bytes of MAC
    vendor_name TEXT,
    vendor_address TEXT,
    country_code TEXT,
    last_updated TIMESTAMP,
    UNIQUE(oui)
);

-- GPS tracks table
CREATE TABLE IF NOT EXISTS gps_tracks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    latitude REAL NOT NULL,
    longitude REAL NOT NULL,
    altitude REAL,
    speed REAL,
    heading REAL,
    hdop REAL,  -- Horizontal dilution of precision
    satellites INTEGER,
    fix_type INTEGER,
    device_name TEXT
);

-- Capture sessions table
CREATE TABLE IF NOT EXISTS capture_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP,
    interface TEXT,
    gps_device TEXT,
    total_packets INTEGER DEFAULT 0,
    total_networks INTEGER DEFAULT 0,
    file_path TEXT,
    notes TEXT
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_observations_network_time ON observations(network_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_observations_location ON observations(latitude, longitude);
CREATE INDEX IF NOT EXISTS idx_observations_rssi ON observations(rssi);
CREATE INDEX IF NOT EXISTS idx_networks_bssid ON networks(bssid);
CREATE INDEX IF NOT EXISTS idx_networks_last_seen ON networks(last_seen);
CREATE INDEX IF NOT EXISTS idx_gps_tracks_time ON gps_tracks(timestamp);

-- Trigger to update last_seen in networks table
CREATE TRIGGER IF NOT EXISTS update_network_last_seen 
AFTER INSERT ON observations
BEGIN
    UPDATE networks 
    SET last_seen = NEW.timestamp 
    WHERE id = NEW.network_id;
END;
