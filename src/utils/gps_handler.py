#!/usr/bin/env python3
"""
GPS integration for location tracking
"""

import gpsd
from datetime import datetime
import time
import logging
from typing import Optional, Dict
from threading import Thread

logger = logging.getLogger(__name__)

class GPSHandler:
    def __init__(self, db_manager, gps_device: str = "/dev/ttyUSB0"):
        self.db = db_manager
        self.gps_device = gps_device
        self.running = False
        self.thread = None
        self.current_fix = None
        
    def connect(self):
        """Connect to GPSD"""
        try:
            gpsd.connect()
            logger.info("Connected to GPSD")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to GPSD: {e}")
            return False
    
    def get_fix(self) -> Optional[Dict]:
        """Get current GPS fix"""
        try:
            packet = gpsd.get_current()
            
            if packet.mode >= 2:  # 2D or 3D fix
                fix = {
                    'timestamp': datetime.utcnow(),
                    'latitude': packet.lat,
                    'longitude': packet.lon,
                    'altitude': packet.alt if packet.mode == 3 else None,
                    'speed': packet.hspeed if hasattr(packet, 'hspeed') else None,
                    'heading': packet.track if hasattr(packet, 'track') else None,
                    'hdop': packet.hdop if hasattr(packet, 'hdop') else None,
                    'satellites': len(packet.sats) if hasattr(packet, 'sats') else None,
                    'fix_type': packet.mode,
                    'device_name': self.gps_device
                }
                self.current_fix = fix
                return fix
            else:
                logger.debug("No GPS fix available")
                return None
                
        except Exception as e:
            logger.error(f"Error getting GPS fix: {e}")
            return None
    
    def start_tracking(self, interval: int = 5):
        """Start continuous GPS tracking"""
        if not self.connect():
            return
        
        self.running = True
        self.thread = Thread(target=self._tracking_loop, args=(interval,))
        self.thread.daemon = True
        self.thread.start()
        logger.info(f"Started GPS tracking with {interval}s interval")
    
    def _tracking_loop(self, interval: int):
        """GPS tracking loop"""
        while self.running:
            fix = self.get_fix()
            if fix:
                try:
                    self.db.add_gps_point(fix)
                    logger.debug(f"Logged GPS point: {fix['latitude']}, {fix['longitude']}")
                except Exception as e:
                    logger.error(f"Error logging GPS point: {e}")
            
            time.sleep(interval)
    
    def stop_tracking(self):
        """Stop GPS tracking"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("GPS tracking stopped")