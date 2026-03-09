#!/usr/bin/env python3
"""
Database manager for WiFi Logger
Handles all database operations
"""

import sqlite3
import json
import hashlib
from datetime import datetime
from typing import Optional, Dict, List, Tuple
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class WiFiDatabase:
    def __init__(self, db_path: str = "/var/lib/wifi-logger/wifi_data.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = None
        self._init_database()
        
    def _init_database(self):
        """Initialize database with schema"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            # Read and execute schema
            schema_path = Path(__file__).parent / "schema.sql"
            if schema_path.exists():
                with open(schema_path, 'r') as f:
                    schema = f.read()
                cursor.executescript(schema)
            else:
                # Fallback to inline schema
                self._create_tables(cursor)
            
            conn.commit()
            logger.info(f"Database initialized at {self.db_path}")
    
    def _create_tables(self, cursor):
        """Create tables if schema file not found"""
        tables = [
            """
            CREATE TABLE IF NOT EXISTS networks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid TEXT NOT NULL,
                essid TEXT,
                essid_hash TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                security_type TEXT,
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
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network_id INTEGER NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                latitude REAL,
                longitude REAL,
                altitude REAL,
                accuracy REAL,
                rssi INTEGER NOT NULL,
                channel INTEGER,
                frequency INTEGER,
                noise_level INTEGER,
                data_rate REAL,
                gps_speed REAL,
                gps_heading REAL,
                gps_fix_type INTEGER,
                device_mac TEXT,
                FOREIGN KEY (network_id) REFERENCES networks(id) ON DELETE CASCADE
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS gps_tracks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                latitude REAL NOT NULL,
                longitude REAL NOT NULL,
                altitude REAL,
                speed REAL,
                heading REAL,
                hdop REAL,
                satellites INTEGER,
                fix_type INTEGER,
                device_name TEXT
            )
            """
        ]
        
        for table_sql in tables:
            cursor.execute(table_sql)
    
    def get_connection(self):
        """Get a reusable database connection"""
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def close(self):
        """Close the database connection"""
        if self._conn:
            try:
                self._conn.close()
            except Exception as e:
                logger.error(f"Error closing database: {e}")
            finally:
                self._conn = None
        logger.info("Database connection closed")
    
    def get_network_id(self, bssid: str, essid: Optional[str] = None) -> int:
        """Get or create network ID for a BSSID"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            # Check if network exists
            cursor.execute("SELECT id FROM networks WHERE bssid = ?", (bssid,))
            result = cursor.fetchone()
            
            if result:
                return result[0]
            else:
                # Create new network
                essid_hash = hashlib.sha256(
                    (essid or "").encode('utf-8')
                ).hexdigest() if essid else None
                
                is_hidden = 1 if not essid or essid.strip() == "" else 0
                
                cursor.execute("""
                    INSERT INTO networks 
                    (bssid, essid, essid_hash, is_hidden, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    bssid, 
                    essid if essid and essid.strip() else None,
                    essid_hash,
                    is_hidden,
                    datetime.utcnow(),
                    datetime.utcnow()
                ))
                
                return cursor.lastrowid
    
    def add_observation(self, network_data: Dict, observation_data: Dict) -> int:
        """Add a new observation"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            # Get or create network
            network_id = self.get_network_id(
                network_data['bssid'],
                network_data.get('essid')
            )
            
            # Update network info if needed
            update_fields = []
            update_values = []
            
            for field in ['security_type', 'cipher', 'vendor', 'channel_width', 
                         'max_rate', 'capabilities', 'ht_caps', 'vht_caps', 'he_caps']:
                if field in network_data and network_data[field]:
                    update_fields.append(f"{field} = ?")
                    update_values.append(network_data[field])
            
            if update_fields:
                update_values.extend([datetime.utcnow(), network_id])
                cursor.execute(f"""
                    UPDATE networks 
                    SET {', '.join(update_fields)}, last_seen = ?
                    WHERE id = ?
                """, update_values)
            
            # Add observation - rssi can be None for some capture methods
            rssi = observation_data.get('rssi')
            if rssi is None:
                rssi = 0  # Default to 0 if no signal info available
            
            cursor.execute("""
                INSERT INTO observations 
                (network_id, timestamp, latitude, longitude, altitude, 
                 accuracy, rssi, channel, frequency, noise_level,
                 data_rate, gps_speed, gps_heading, gps_fix_type, device_mac)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                network_id,
                observation_data.get('timestamp', datetime.utcnow()),
                observation_data.get('latitude'),
                observation_data.get('longitude'),
                observation_data.get('altitude'),
                observation_data.get('accuracy'),
                rssi,
                observation_data.get('channel'),
                observation_data.get('frequency'),
                observation_data.get('noise_level'),
                observation_data.get('data_rate'),
                observation_data.get('gps_speed'),
                observation_data.get('gps_heading'),
                observation_data.get('gps_fix_type'),
                observation_data.get('device_mac')
            ))
            
            obs_id = cursor.lastrowid
            conn.commit()
            return obs_id
    
    def add_gps_point(self, gps_data: Dict) -> int:
        """Add GPS tracking point"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO gps_tracks 
                (timestamp, latitude, longitude, altitude, speed, 
                 heading, hdop, satellites, fix_type, device_name)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                gps_data.get('timestamp', datetime.utcnow()),
                gps_data['latitude'],
                gps_data['longitude'],
                gps_data.get('altitude'),
                gps_data.get('speed'),
                gps_data.get('heading'),
                gps_data.get('hdop'),
                gps_data.get('satellites'),
                gps_data.get('fix_type'),
                gps_data.get('device_name')
            ))
            
            point_id = cursor.lastrowid
            conn.commit()
            return point_id
    
    def query_networks(self, filters: Optional[Dict] = None) -> List[Dict]:
        """Query networks with optional filters"""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = "SELECT * FROM networks WHERE 1=1"
            params = []
            
            if filters:
                for key, value in filters.items():
                    if key == 'bssid_like':
                        query += " AND bssid LIKE ?"
                        params.append(f"%{value}%")
                    elif key == 'essid_like':
                        query += " AND (essid LIKE ? OR essid_hash = ?)"
                        params.extend([f"%{value}%", hashlib.sha256(value.encode()).hexdigest()])
                    elif key == 'vendor_like':
                        query += " AND vendor LIKE ?"
                        params.append(f"%{value}%")
                    elif key == 'min_last_seen':
                        query += " AND last_seen >= ?"
                        params.append(value)
                    elif key == 'security_type':
                        query += " AND security_type = ?"
                        params.append(value)
                    elif key == 'is_hidden':
                        query += " AND is_hidden = ?"
                        params.append(value)
            
            query += " ORDER BY last_seen DESC"
            cursor.execute(query, params)
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_network_observations(self, network_id: int, limit: int = 1000) -> List[Dict]:
        """Get observations for a specific network"""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT o.*, n.bssid, n.essid, n.vendor
                FROM observations o
                JOIN networks n ON o.network_id = n.id
                WHERE n.id = ?
                ORDER BY o.timestamp DESC
                LIMIT ?
            """, (network_id, limit))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_stats(self) -> Dict:
        """Get database statistics"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            stats = {}
            
            # Network stats
            cursor.execute("SELECT COUNT(*) FROM networks")
            stats['total_networks'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM networks WHERE is_hidden = 1")
            stats['hidden_networks'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(DISTINCT vendor) FROM networks WHERE vendor IS NOT NULL")
            stats['unique_vendors'] = cursor.fetchone()[0]
            
            # Observation stats
            cursor.execute("SELECT COUNT(*) FROM observations")
            stats['total_observations'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM gps_tracks")
            stats['gps_points'] = cursor.fetchone()[0]
            
            # Recent activity
            cursor.execute("""
                SELECT COUNT(*) FROM networks 
                WHERE last_seen >= datetime('now', '-24 hours')
            """)
            stats['networks_seen_24h'] = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT security_type, COUNT(*) as count 
                FROM networks 
                GROUP BY security_type 
                ORDER BY count DESC
            """)
            stats['security_distribution'] = dict(cursor.fetchall())
            
            return stats
    
    def export_geojson(self, network_ids: Optional[List[int]] = None) -> Dict:
        """Export observations as GeoJSON"""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            if network_ids:
                placeholders = ','.join('?' for _ in network_ids)
                query = f"""
                    SELECT o.*, n.bssid, n.essid, n.vendor, n.security_type
                    FROM observations o
                    JOIN networks n ON o.network_id = n.id
                    WHERE n.id IN ({placeholders}) 
                    AND o.latitude IS NOT NULL 
                    AND o.longitude IS NOT NULL
                    ORDER BY o.timestamp DESC
                """
                cursor.execute(query, network_ids)
            else:
                cursor.execute("""
                    SELECT o.*, n.bssid, n.essid, n.vendor, n.security_type
                    FROM observations o
                    JOIN networks n ON o.network_id = n.id
                    WHERE o.latitude IS NOT NULL 
                    AND o.longitude IS NOT NULL
                    ORDER BY o.timestamp DESC
                    LIMIT 10000
                """)
            
            features = []
            for row in cursor.fetchall():
                row_dict = dict(row)
                feature = {
                    "type": "Feature",
                    "geometry": {
                        "type": "Point",
                        "coordinates": [row_dict['longitude'], row_dict['latitude']]
                    },
                    "properties": {
                        "bssid": row_dict['bssid'],
                        "essid": row_dict['essid'] or "Hidden",
                        "vendor": row_dict['vendor'],
                        "security": row_dict['security_type'],
                        "rssi": row_dict['rssi'],
                        "channel": row_dict['channel'],
                        "timestamp": str(row_dict['timestamp']),
                        "network_id": row_dict['network_id']
                    }
                }
                features.append(feature)
            
            return {
                "type": "FeatureCollection",
                "features": features
            }
