#!/usr/bin/env python3
"""
Main WiFi Logger Application
"""

import argparse
import csv
import json
import logging
import logging.handlers
import signal
import subprocess
import sys
import time
from pathlib import Path
import yaml
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from database.db_manager import WiFiDatabase
from capture.kismet_capture import KismetIntegration
from capture.scapy_capture import ScapyCapture
from utils.gps_handler import GPSHandler
from web.app import create_app

logger = logging.getLogger(__name__)

class WiFiLogger:
    def __init__(self, config_path: str = "/opt/wifi-logger/config/config.yaml"):
        self.config_path = Path(config_path)
        self.load_config()
        self.setup_logging()
        
        self.db = WiFiDatabase(self.config['database']['path'])
        self.gps = None
        self.capture = None
        self.running = False
        self.last_backup = datetime.utcnow()
        self.last_cleanup = datetime.utcnow()
        
        logger.info("WiFi Logger initialized")
    
    def load_config(self):
        """Load configuration from YAML file"""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        else:
            # Default configuration
            self.config = {
                'database': {'path': '/var/lib/wifi-logger/wifi_data.db'},
                'capture': {
                    'interface': 'wlan0mon',
                    'method': 'kismet'
                },
                'logging': {'level': 'INFO'},
                'gps': {'enabled': False},
                'web': {'enabled': False},
                'retention': {
                    'keep_observations_days': 90,
                    'keep_networks_days': 365,
                    'cleanup_interval': 86400
                }
            }
    
    def setup_logging(self):
        """Setup logging configuration"""
        log_config = self.config.get('logging', {})
        log_level = getattr(logging, log_config.get('level', 'INFO'))

        log_file = log_config.get('file', '/var/log/wifi-logger/wifi.log')
        log_dir = Path(log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)

        rotating = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=log_config.get('max_size', 10485760),
            backupCount=log_config.get('backup_count', 5)
        )
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[rotating, logging.StreamHandler()]
        )
    
    def setup_interface(self):
        """Setup monitor mode interface"""
        interface = self.config['capture']['interface']
        
        # Check if interface exists
        if not Path(f"/sys/class/net/{interface}").exists():
            logger.info(f"Interface {interface} not found, trying to create monitor mode")
            
            # Find physical interface (assuming wlan0)
            phys_iface = "wlan0"
            
            # Bring down
            subprocess.run(['ip', 'link', 'set', phys_iface, 'down'], check=False)
            
            # Set monitor mode
            subprocess.run(['iw', 'dev', phys_iface, 'set', 'type', 'monitor'], check=False)
            
            # Bring up
            subprocess.run(['ip', 'link', 'set', phys_iface, 'up'], check=False)
            
            # Rename to desired interface name
            subprocess.run(['ip', 'link', 'set', phys_iface, 'name', interface], check=False)
    
    def start_gps(self):
        """Start GPS tracking if enabled"""
        gps_config = self.config.get('gps', {})
        if gps_config.get('enabled', False):
            self.gps = GPSHandler(self.db, gps_config.get('device'))
            self.gps.start_tracking(gps_config.get('tracking_interval', 5))
            logger.info("GPS tracking started")
    
    def start_capture(self):
        """Start WiFi capture based on configured method"""
        capture_config = self.config['capture']
        method = capture_config.get('method', 'kismet')
        
        if method == 'kismet':
            self.capture = KismetIntegration(self.db)
            
            kismet_config = capture_config.get('kismet', {})
            if kismet_config.get('auto_start', True):
                gps_device = kismet_config.get('gps_device')
                self.capture.start_kismet(capture_config['interface'], gps_device)
            
            # Process existing logs
            self.capture.process_kismet_logs()
            
        elif method == 'scapy':
            min_rssi = capture_config.get('min_rssi', -90)
            self.capture = ScapyCapture(self.db, capture_config['interface'], min_rssi=min_rssi)
            channels = capture_config.get('scan_channels')
            dwell = capture_config.get('channel_dwell_time', 0.5)
            from threading import Thread
            t = Thread(target=self.capture.start_capture,
                       kwargs={'channels': channels, 'dwell_time': dwell})
            t.daemon = True
            t.start()
        
        logger.info(f"Started {method} capture on {capture_config['interface']}")
    
    def start_web_interface(self):
        """Start web interface if enabled"""
        web_config = self.config.get('web', {})
        if web_config.get('enabled', False):
            app = create_app(self.db, web_config.get('api_key', ''))
            from threading import Thread
            try:
                from waitress import serve
                target = serve
                kwargs = {
                    'app': app,
                    'host': web_config.get('host', '127.0.0.1'),
                    'port': web_config.get('port', 8080)
                }
            except ImportError:
                logger.warning("waitress not installed, falling back to Flask dev server")
                target = app.run
                kwargs = {
                    'host': web_config.get('host', '127.0.0.1'),
                    'port': web_config.get('port', 8080),
                    'debug': False,
                    'use_reloader': False
                }
            web_thread = Thread(target=target, kwargs=kwargs)
            web_thread.daemon = True
            web_thread.start()
            logger.info(f"Web interface started on {web_config.get('host')}:{web_config.get('port')}")
    
    def run(self):
        """Main run loop"""
        self.running = True
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        try:
            # Setup interface
            self.setup_interface()
            
            # Start GPS
            self.start_gps()
            
            # Start capture
            self.start_capture()
            
            # Start web interface
            self.start_web_interface()
            
            logger.info("WiFi Logger running. Press Ctrl+C to stop.")
            
            # Main loop
            while self.running:
                # Periodic tasks
                self.periodic_tasks()
                time.sleep(60)
                
        except KeyboardInterrupt:
            logger.info("Shutdown requested")
        except Exception as e:
            logger.error(f"Error in main loop: {e}", exc_info=True)
        finally:
            self.shutdown()
    
    def periodic_tasks(self):
        """Perform periodic maintenance tasks"""
        now = datetime.utcnow()
        
        # Process Kismet logs periodically if using Kismet
        if isinstance(self.capture, KismetIntegration):
            self.capture.process_kismet_logs()
        
        # Database backup
        backup_config = self.config.get('database', {})
        backup_interval = backup_config.get('backup_interval', 86400)
        if (now - self.last_backup).total_seconds() >= backup_interval:
            self.backup_database()
            self.last_backup = now
        
        # Data cleanup
        retention_config = self.config.get('retention', {})
        cleanup_interval = retention_config.get('cleanup_interval', 86400)
        if (now - self.last_cleanup).total_seconds() >= cleanup_interval:
            self.cleanup_old_data()
            self.last_cleanup = now
    
    def backup_database(self):
        """Backup database"""
        backup_dir = Path(self.config['database'].get('backup_dir', '/var/lib/wifi-logger/backups'))
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        backup_file = backup_dir / f"wifi_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        
        try:
            import shutil
            shutil.copy2(self.config['database']['path'], backup_file)
            logger.info(f"Database backed up to {backup_file}")
            
            # Remove old backups (keep last 30)
            backups = sorted(backup_dir.glob("wifi_backup_*.db"))
            if len(backups) > 30:
                for old_backup in backups[:-30]:
                    old_backup.unlink()
                    
        except Exception as e:
            logger.error(f"Failed to backup database: {e}")
    
    def cleanup_old_data(self):
        """Clean up old data based on retention policy"""
        retention = self.config.get('retention', {})
        obs_days = retention.get('keep_observations_days', 90)
        network_days = retention.get('keep_networks_days', 365)

        try:
            import sqlite3
            with sqlite3.connect(str(self.db.db_path)) as conn:
                cursor = conn.cursor()
                if obs_days > 0:
                    cursor.execute("""
                        DELETE FROM observations
                        WHERE timestamp < datetime('now', ?)
                    """, (f'-{obs_days} days',))
                    logger.info(f"Cleaned up observations older than {obs_days} days")
                cursor.execute("""
                    DELETE FROM networks
                    WHERE last_seen < datetime('now', ?)
                    AND id NOT IN (
                        SELECT DISTINCT network_id FROM observations
                        WHERE timestamp > datetime('now', ?)
                    )
                """, (f'-{network_days} days', f'-{obs_days} days'))
                conn.commit()
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
    
    def shutdown(self):
        """Clean shutdown"""
        logger.info("Shutting down WiFi Logger...")
        
        if self.gps:
            self.gps.stop_tracking()
        
        # Any other cleanup needed
        self.db.close()
        
        logger.info("WiFi Logger shutdown complete")

def main():
    parser = argparse.ArgumentParser(description="WiFi Logger System")
    parser.add_argument('--service', action='store_true', help='Run as service/daemon')
    parser.add_argument('--config', default='/opt/wifi-logger/config/config.yaml', help='Configuration file path')
    parser.add_argument('--scan', action='store_true', help='Run single scan and exit')
    parser.add_argument('--export', help='Export data to file (geojson, csv)')
    parser.add_argument('--stats', action='store_true', help='Show database statistics')
    
    args = parser.parse_args()
    
    wifi_logger = WiFiLogger(args.config)
    
    if args.stats:
        stats = wifi_logger.db.get_stats()
        print(json.dumps(stats, indent=2))
        return
    
    if args.export:
        export_path = Path(args.export)
        if export_path.suffix.lower() == '.csv':
            networks = wifi_logger.db.query_networks()
            with open(export_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'bssid', 'essid', 'vendor', 'security_type',
                    'first_seen', 'last_seen', 'observation_count'
                ])
                writer.writeheader()
                for n in networks:
                    writer.writerow({
                        'bssid': n['bssid'],
                        'essid': n['essid'] or 'Hidden',
                        'vendor': n['vendor'] or 'Unknown',
                        'security_type': n['security_type'] or 'Unknown',
                        'first_seen': n['first_seen'],
                        'last_seen': n['last_seen'],
                        'observation_count': n.get('observation_count', 0)
                    })
        else:
            data = wifi_logger.db.export_geojson()
            with open(export_path, 'w') as f:
                json.dump(data, f)
        print(f"Exported data to {args.export}")
        return
    
    if args.scan:
        # Single scan mode
        wifi_logger.setup_interface()
        wifi_logger.start_capture()
        # Run for 30 seconds
        time.sleep(30)
        wifi_logger.shutdown()
        return
    
    if args.service:
        # Run as daemon
        try:
            from daemon.pidfile import PIDLockFile
            import daemon
            
            pidfile = PIDLockFile('/var/run/wifi-logger.pid')
            
            with daemon.DaemonContext(
                pidfile=pidfile,
                working_directory='/opt/wifi-logger',
                umask=0o002,
                detach_process=True
            ):
                wifi_logger.run()
        except ImportError:
            logger.warning("python-daemon not installed, running in foreground")
            wifi_logger.run()
    else:
        # Run in foreground
        wifi_logger.run()

if __name__ == "__main__":
    main()
