#!/usr/bin/env python3
"""
Direct packet capture using Scapy
For when you want more control than Kismet
"""

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, RadioTap
import logging
from datetime import datetime
from typing import Dict, Optional
import hashlib
from .db_manager import WiFiDatabase

logger = logging.getLogger(__name__)

class ScapyCapture:
    def __init__(self, db_manager, interface: str = "wlan0mon"):
        self.db = db_manager
        self.interface = interface
        self.networks_seen = set()
        
    def packet_handler(self, packet):
        """Handle captured packets"""
        try:
            if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
                self._process_beacon(packet)
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _process_beacon(self, packet):
        """Process beacon or probe response frames"""
        # Get BSSID
        if packet.addr3:  # BSSID is typically addr3
            bssid = packet.addr3.upper()
        else:
            return
        
        # Check if we have RadioTap layer for signal info
        rssi = noise = None
        if packet.haslayer(RadioTap):
            rtap = packet[RadioTap]
            # Try to extract RSSI (varies by driver)
            if hasattr(rtap, 'dBm_AntSignal'):
                rssi = rtap.dBm_AntSignal
            elif hasattr(rtap, 'dBm_AntNoise'):
                noise = rtap.dBm_AntNoise
        
        # Get ESSID
        essid = None
        if packet.haslayer(Dot11Beacon):
            beacon = packet[Dot11Beacon]
            if beacon.info:
                try:
                    essid = beacon.info.decode('utf-8', errors='ignore').strip()
                except:
                    essid = str(beacon.info)
        
        # Get capabilities
        capabilities = None
        if packet.haslayer(Dot11Beacon):
            cap = packet[Dot11Beacon].cap
            capabilities = self._parse_capabilities(cap)
        
        # Get channel from RadioTap
        channel = None
        if packet.haslayer(RadioTap):
            rtap = packet[RadioTap]
            if hasattr(rtap, 'ChannelFrequency'):
                freq = rtap.ChannelFrequency
                channel = self._frequency_to_channel(freq)
        
        # Network data
        network_data = {
            'bssid': bssid,
            'essid': essid,
            'capabilities': capabilities,
            'security_type': self._get_security_type(capabilities)
        }
        
        # Observation data
        observation_data = {
            'timestamp': datetime.utcnow(),
            'rssi': rssi,
            'noise_level': noise,
            'channel': channel,
            'frequency': freq if 'freq' in locals() else None
        }
        
        # Add to database
        try:
            self.db.add_observation(network_data, observation_data)
            
            # Log new networks
            if bssid not in self.networks_seen:
                self.networks_seen.add(bssid)
                logger.info(f"New network: {essid or 'Hidden'} ({bssid}) RSSI: {rssi}dBm")
                
        except Exception as e:
            logger.error(f"Error adding observation for {bssid}: {e}")
    
    def _parse_capabilities(self, cap):
        """Parse 802.11 capabilities"""
        cap_dict = {
            'ess': bool(cap & 0x01),
            'ibss': bool(cap & 0x02),
            'cf_pollable': bool(cap & 0x04),
            'cf_poll_req': bool(cap & 0x08),
            'privacy': bool(cap & 0x10),
            'short_preamble': bool(cap & 0x20),
            'pbcc': bool(cap & 0x40),
            'channel_agility': bool(cap & 0x80),
            'spectrum_mgmt': bool(cap & 0x0100),
            'qos': bool(cap & 0x0200),
            'short_slot_time': bool(cap & 0x0400),
            'apsd': bool(cap & 0x0800),
            'radio_measurement': bool(cap & 0x1000),
            'dsss_ofdm': bool(cap & 0x2000),
            'delayed_block_ack': bool(cap & 0x4000),
            'immediate_block_ack': bool(cap & 0x8000)
        }
        return json.dumps(cap_dict)
    
    def _get_security_type(self, capabilities_json: Optional[str]) -> str:
        """Determine security type from capabilities"""
        if not capabilities_json:
            return 'unknown'
        
        try:
            caps = json.loads(capabilities_json)
            if caps.get('privacy'):
                # This is simplified - real detection needs more analysis
                return 'wpa2'  # Default assumption
            else:
                return 'open'
        except:
            return 'unknown'
    
    def _frequency_to_channel(self, freq: int) -> Optional[int]:
        """Convert frequency to channel number"""
        if 2412 <= freq <= 2484:
            return (freq - 2407) // 5
        elif 5170 <= freq <= 5825:
            return (freq - 5000) // 5
        return None
    
    def start_capture(self, count: Optional[int] = None):
        """Start capturing packets"""
        logger.info(f"Starting capture on {self.interface}")
        
        try:
            # Start sniffing
            sniff(iface=self.interface,
                  prn=self.packet_handler,
                  store=0,
                  count=count,
                  monitor=True)
        except KeyboardInterrupt:
            logger.info("Capture stopped by user")
        except Exception as e:
            logger.error(f"Capture error: {e}")