#!/usr/bin/env python3
"""
Kismet integration for WiFi capture
Automatically processes Kismet logs into our database
"""

import json
import xml.etree.ElementTree as ET
import sqlite3
from pathlib import Path
from datetime import datetime
import logging
import time
import subprocess
from typing import Optional
import hashlib

logger = logging.getLogger(__name__)

class KismetIntegration:
    def __init__(self, db_manager, kismet_log_dir: str = "/var/log/kismet"):
        self.db = db_manager
        self.kismet_dir = Path(kismet_log_dir)
        self.last_processed = {}
        
    def start_kismet(self, interface: str = "wlan0mon", gps: Optional[str] = None):
        """Start Kismet with proper configuration"""
        config = {
            'source': interface,
            'log_prefix': '/var/log/kismet',
            'gps': gps,
            'silent': True
        }
        
        cmd = ['kismet', '-c', interface, '--daemonize']
        if gps:
            cmd.extend(['-g', gps])
        
        try:
            subprocess.run(cmd, check=True)
            logger.info(f"Started Kismet on interface {interface}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to start Kismet: {e}")
            raise
    
    def process_kismet_logs(self, log_file: Optional[str] = None):
        """Process Kismet log files (netxml or kismetdb)"""
        if log_file:
            files = [Path(log_file)]
        else:
            # Find latest kismet log
            kismet_files = list(self.kismet_dir.glob("*.kismet"))
            kismet_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            
            if not kismet_files:
                logger.warning("No Kismet log files found")
                return
            
            files = kismet_files
        
        for log_path in files:
            if log_path.suffix == '.kismet':
                self._process_kismetdb(log_path)
            elif log_path.suffix == '.netxml':
                self._process_netxml(log_path)
    
    def _process_kismetdb(self, db_path: Path):
        """Process Kismet SQLite database"""
        try:
            kismet_conn = sqlite3.connect(db_path)
            kismet_conn.row_factory = sqlite3.Row
            cursor = kismet_conn.cursor()
            
            # Get devices
            cursor.execute("""
                SELECT d.devkey AS bssid, d.type, 
                       d.first_time, d.last_time,
                       d.datasize, d.device,
                       d.strongest_signal AS rssi,
                       d.channel, d.frequency,
                       d.packets, d.crypt,
                       json_extract(d.device, '$.kismet.device.base.name') as essid,
                       json_extract(d.device, '$.kismet.device.base.manuf') as vendor,
                       json_extract(d.device, '$.kismet.device.base.location') as location
                FROM devices d
                WHERE d.type = 0  -- WiFi devices
            """)
            
            processed = 0
            for row in cursor.fetchall():
                device = dict(row)
                
                # Extract location if available
                lat = lon = alt = None
                if device['location']:
                    try:
                        loc_data = json.loads(device['location'])
                        lat = loc_data.get('kismet.common.location.lat')
                        lon = loc_data.get('kismet.common.location.lon')
                        alt = loc_data.get('kismet.common.location.alt')
                    except:
                        pass
                
                # Network data
                network_data = {
                    'bssid': device['bssid'],
                    'essid': device['essid'],
                    'vendor': device['vendor'],
                    'security_type': self._parse_kismet_crypt(device['crypt'])
                }
                
                # Observation data
                observation_data = {
                    'timestamp': datetime.fromtimestamp(device['last_time']),
                    'latitude': lat,
                    'longitude': lon,
                    'altitude': alt,
                    'rssi': device['rssi'],
                    'channel': device['channel'],
                    'frequency': device['frequency']
                }
                
                try:
                    self.db.add_observation(network_data, observation_data)
                    processed += 1
                except Exception as e:
                    logger.error(f"Error processing device {device['bssid']}: {e}")
            
            logger.info(f"Processed {processed} devices from {db_path}")
            kismet_conn.close()
            
        except Exception as e:
            logger.error(f"Error processing Kismet DB {db_path}: {e}")
    
    def _process_netxml(self, xml_path: Path):
        """Process Kismet netxml file"""
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            processed = 0
            for wireless_node in root.findall('.//wireless-network'):
                bssid = wireless_node.find('BSSID')
                if bssid is None:
                    continue
                
                bssid_text = bssid.text.strip().upper()
                
                # Get ESSID
                ssid_elem = wireless_node.find('SSID')
                essid = None
                if ssid_elem is not None:
                    essid_elem = ssid_elem.find('essid')
                    if essid_elem is not None and essid_elem.get('cloaked', 'false') == 'false':
                        essid = essid_elem.text
                
                # Get vendor
                manuf_elem = wireless_node.find('manuf')
                vendor = manuf_elem.text if manuf_elem is not None else None
                
                # Get security info
                encryption = []
                for enc in wireless_node.findall('.//encryption'):
                    encryption.append(enc.text)
                security_type = self._parse_encryption(encryption)
                
                # Get GPS info
                gps_info = wireless_node.find('.//gps-info')
                lat = lon = alt = None
                if gps_info is not None:
                    lat_elem = gps_info.find('avg-lat')
                    lon_elem = gps_info.find('avg-lon')
                    alt_elem = gps_info.find('avg-alt')
                    
                    if lat_elem is not None:
                        lat = float(lat_elem.text)
                    if lon_elem is not None:
                        lon = float(lon_elem.text)
                    if alt_elem is not None:
                        alt = float(alt_elem.text)
                
                # Get signal info
                snr_info = wireless_node.find('.//snr-info')
                rssi = None
                if snr_info is not None:
                    max_rssi = snr_info.find('max_signal_dbm')
                    if max_rssi is not None:
                        rssi = int(max_rssi.text)
                
                # Get channel info
                channel_info = wireless_node.find('.//channel')
                channel = freq = None
                if channel_info is not None:
                    channel = channel_info.text
                    freq = int(channel_info.get('freq', '0'))
                
                # Network data
                network_data = {
                    'bssid': bssid_text,
                    'essid': essid,
                    'vendor': vendor,
                    'security_type': security_type
                }
                
                # Observation data
                observation_data = {
                    'timestamp': datetime.utcnow(),
                    'latitude': lat,
                    'longitude': lon,
                    'altitude': alt,
                    'rssi': rssi,
                    'channel': channel,
                    'frequency': freq
                }
                
                try:
                    self.db.add_observation(network_data, observation_data)
                    processed += 1
                except Exception as e:
                    logger.error(f"Error processing network {bssid_text}: {e}")
            
            logger.info(f"Processed {processed} networks from {xml_path}")
            
        except Exception as e:
            logger.error(f"Error processing netxml {xml_path}: {e}")
    
    def _parse_kismet_crypt(self, crypt_flags: int) -> str:
        """Parse Kismet crypt flags"""
        if crypt_flags == 0:
            return 'open'
        elif crypt_flags & 0x01:  # WEP
            return 'wep'
        elif crypt_flags & 0x02:  # WPA
            return 'wpa'
        elif crypt_flags & 0x04:  # WPA2
            return 'wpa2'
        elif crypt_flags & 0x08:  # WPA3
            return 'wpa3'
        else:
            return 'mixed'
    
    def _parse_encryption(self, encryption_list: list) -> str:
        """Parse encryption list to security type"""
        if not encryption_list:
            return 'open'
        
        enc_str = ','.join(encryption_list).lower()
        
        if 'wpa3' in enc_str:
            return 'wpa3'
        elif 'wpa2' in enc_str:
            if 'wpa' in enc_str:
                return 'wpa2/wpa'
            return 'wpa2'
        elif 'wpa' in enc_str:
            return 'wpa'
        elif 'wep' in enc_str:
            return 'wep'
        else:
            return 'mixed'