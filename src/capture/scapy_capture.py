#!/usr/bin/env python3
"""
Direct packet capture using Scapy
For when you want more control than Kismet
"""

import json
import logging
import subprocess
import time
from datetime import datetime
from threading import Thread
from typing import Dict, Optional

try:
    from scapy.all import sniff, conf as scapy_conf
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, RadioTap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger(__name__)

class ScapyCapture:
    def __init__(self, db_manager, interface: str = "wlan0mon", min_rssi: int = -90):
        self.db = db_manager
        self.interface = interface
        self.min_rssi = min_rssi
        self.networks_seen = set()
        self._hopping = False
        self.session_id: Optional[int] = None
        self.total_packets: int = 0

        if not SCAPY_AVAILABLE:
            logger.warning("Scapy is not installed. Install with: pip install scapy")
        
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
        freq = None
        if packet.haslayer(RadioTap):
            rtap = packet[RadioTap]
            # Try to extract RSSI (varies by driver)
            if hasattr(rtap, 'dBm_AntSignal'):
                rssi = rtap.dBm_AntSignal
            if hasattr(rtap, 'dBm_AntNoise'):
                noise = rtap.dBm_AntNoise
        
        # Apply min_rssi filter
        if rssi is not None and rssi < self.min_rssi:
            return

        # Get ESSID
        essid = None
        if packet.haslayer(Dot11Beacon):
            beacon = packet[Dot11Beacon]
            if beacon.info:
                try:
                    essid = beacon.info.decode('utf-8', errors='ignore').strip()
                except Exception:
                    essid = str(beacon.info)
        elif packet.haslayer(Dot11ProbeResp):
            probe = packet[Dot11ProbeResp]
            if probe.info:
                try:
                    essid = probe.info.decode('utf-8', errors='ignore').strip()
                except Exception:
                    essid = str(probe.info)
        
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

        security_type = self._parse_security_from_packet(packet)

        # Network data
        network_data = {
            'bssid': bssid,
            'essid': essid,
            'capabilities': capabilities,
            'security_type': security_type,
            'vendor': self._get_oui_vendor(bssid)
        }
        
        # Observation data
        observation_data = {
            'timestamp': datetime.utcnow(),
            'rssi': rssi,
            'noise_level': noise,
            'channel': channel,
            'frequency': freq
        }
        
        # Add to database
        try:
            self.db.add_observation(network_data, observation_data)
            self.total_packets += 1

            # Log new networks
            if bssid not in self.networks_seen:
                self.networks_seen.add(bssid)
                logger.info(f"New network: {essid or 'Hidden'} ({bssid}) RSSI: {rssi}dBm")
                
        except Exception as e:
            logger.error(f"Error adding observation for {bssid}: {e}")
    
    def _parse_capabilities(self, cap) -> str:
        """Store raw capability integer as JSON for later use"""
        return json.dumps({'raw': int(cap), 'privacy': bool(cap & 0x10)})

    def _parse_security_from_packet(self, packet) -> str:
        """Parse security type from RSN IE (tag 48) and WPA IE (tag 221/OUI 00:50:f2:01).
        Falls back to capability Privacy bit only if no IEs found."""
        try:
            from scapy.layers.dot11 import Dot11Elt
            has_rsn = False
            has_wpa_ie = False
            has_wpa3 = False
            privacy = False

            # Check capability privacy bit
            if packet.haslayer(Dot11Beacon):
                privacy = bool(packet[Dot11Beacon].cap & 0x10)
            elif packet.haslayer(Dot11ProbeResp):
                privacy = bool(packet[Dot11ProbeResp].cap & 0x10)

            # Walk tagged parameters
            elt = packet.getlayer(Dot11Elt)
            while elt:
                # Tag 48 = RSN (WPA2/WPA3)
                if elt.ID == 48 and elt.len and elt.len > 0:
                    has_rsn = True
                    # Check AKM suites for WPA3 (SAE = 00-0F-AC:8)
                    try:
                        raw = bytes(elt.info)
                        # RSN: 2 version + 4 group + 2 pairwise count
                        if len(raw) >= 8:
                            pw_count = int.from_bytes(raw[6:8], 'little')
                            offset = 8 + pw_count * 4
                            if len(raw) >= offset + 2:
                                akm_count = int.from_bytes(raw[offset:offset+2], 'little')
                                offset += 2
                                for _ in range(akm_count):
                                    if len(raw) >= offset + 4:
                                        suite = raw[offset:offset+4]
                                        # 00-0F-AC:8 = SAE (WPA3)
                                        if suite == b'\x00\x0f\xac\x08':
                                            has_wpa3 = True
                                        offset += 4
                    except Exception:
                        pass

                # Tag 221 = Vendor Specific; WPA IE = OUI 00:50:f2 type 01
                elif elt.ID == 221 and elt.len and elt.len >= 4:
                    try:
                        info = bytes(elt.info)
                        if info[:4] == b'\x00\x50\xf2\x01':
                            has_wpa_ie = True
                    except Exception:
                        pass

                elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

            if has_wpa3 and has_rsn:
                return 'wpa3' if not has_wpa_ie else 'wpa2/wpa3'
            elif has_rsn and has_wpa_ie:
                return 'wpa2/wpa'
            elif has_rsn:
                return 'wpa2'
            elif has_wpa_ie:
                return 'wpa'
            elif privacy:
                return 'wep'
            else:
                return 'open'
        except Exception:
            return 'unknown'
    
    def _frequency_to_channel(self, freq: int) -> Optional[int]:
        """Convert frequency to channel number"""
        if 2412 <= freq <= 2484:
            if freq == 2484:
                return 14
            return (freq - 2407) // 5
        elif 5170 <= freq <= 5825:
            return (freq - 5000) // 5
        elif 5955 <= freq <= 7115:
            # 6 GHz band (WiFi 6E)
            return (freq - 5950) // 5
        return None
    
    def _get_oui_vendor(self, bssid: str) -> Optional[str]:
        """Look up vendor from OUI prefix via macvendors API (cached in DB)"""
        oui = bssid.replace(':', '').upper()[:6]
        try:
            import sqlite3
            with sqlite3.connect(str(self.db.db_path)) as conn:
                row = conn.execute(
                    "SELECT vendor_name FROM devices WHERE oui = ?", (oui,)
                ).fetchone()
                if row:
                    return row[0]
            import urllib.request
            url = f"https://api.macvendors.com/{bssid[:8]}"
            with urllib.request.urlopen(url, timeout=3) as resp:
                vendor = resp.read().decode().strip()
            with sqlite3.connect(str(self.db.db_path)) as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO devices (oui, vendor_name) VALUES (?, ?)",
                    (oui, vendor)
                )
                conn.commit()
            return vendor
        except Exception:
            return None

    def _channel_hopper(self, channels: list, dwell_time: float):
        """Hop through channels on the monitor interface"""
        while self._hopping:
            for ch in channels:
                if not self._hopping:
                    break
                try:
                    subprocess.run(
                        ['iw', 'dev', self.interface, 'set', 'channel', str(ch)],
                        check=False, capture_output=True
                    )
                except Exception:
                    pass
                time.sleep(dwell_time)

    def start_capture(self, count: Optional[int] = None, channels: Optional[list] = None,
                      dwell_time: float = 0.5):
        """Start capturing packets"""
        if not SCAPY_AVAILABLE:
            logger.error("Cannot start capture: scapy is not installed")
            return

        logger.info(f"Starting capture on {self.interface}")

        if channels:
            self._hopping = True
            hop_thread = Thread(target=self._channel_hopper, args=(channels, dwell_time))
            hop_thread.daemon = True
            hop_thread.start()
            logger.info(f"Channel hopping across {len(channels)} channels")

        try:
            sniff(iface=self.interface,
                  prn=self.packet_handler,
                  store=0,
                  count=count,
                  monitor=True)
        except KeyboardInterrupt:
            logger.info("Capture stopped by user")
        except Exception as e:
            logger.error(f"Capture error: {e}")
        finally:
            self._hopping = False
