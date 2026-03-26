#!/usr/bin/env python3
"""
Main WiFi Logger Application
"""

import argparse
import csv
import curses
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
        self.session_id = None
        self.last_backup = datetime.utcnow()
        self.last_cleanup = datetime.utcnow()

        logger.info("WiFi Logger initialized")

    def load_config(self):
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        else:
            self.config = {
                'database': {'path': '/var/lib/wifi-logger/wifi_data.db'},
                'capture': {'interface': 'wlan0mon', 'method': 'kismet'},
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
        interface = self.config['capture']['interface']
        if not Path(f"/sys/class/net/{interface}").exists():
            logger.info(f"Interface {interface} not found, trying to create monitor mode")
            phys_iface = "wlan0"
            subprocess.run(['ip', 'link', 'set', phys_iface, 'down'], check=False)
            subprocess.run(['iw', 'dev', phys_iface, 'set', 'type', 'monitor'], check=False)
            subprocess.run(['ip', 'link', 'set', phys_iface, 'up'], check=False)
            subprocess.run(['ip', 'link', 'set', phys_iface, 'name', interface], check=False)

    def start_gps(self):
        gps_config = self.config.get('gps', {})
        if gps_config.get('enabled', False):
            self.gps = GPSHandler(self.db, gps_config.get('device'))
            self.gps.start_tracking(gps_config.get('tracking_interval', 5))
            logger.info("GPS tracking started")

    def start_capture(self):
        capture_config = self.config['capture']
        method = capture_config.get('method', 'kismet')
        interface = capture_config['interface']
        gps_device = self.config.get('gps', {}).get('device') if self.config.get('gps', {}).get('enabled') else None

        self.session_id = self.db.start_session(interface=interface, gps_device=gps_device)
        logger.info(f"Started capture session #{self.session_id}")

        if method == 'kismet':
            self.capture = KismetIntegration(self.db)
            self.capture.session_id = self.session_id

            kismet_config = capture_config.get('kismet', {})
            if kismet_config.get('auto_start', True):
                gps_dev = kismet_config.get('gps_device')
                self.capture.start_kismet(interface, gps_dev)

            self.capture.process_kismet_logs()

        elif method == 'scapy':
            min_rssi = capture_config.get('min_rssi', -90)
            self.capture = ScapyCapture(self.db, interface, min_rssi=min_rssi)
            self.capture.session_id = self.session_id
            channels = capture_config.get('scan_channels')
            dwell = capture_config.get('channel_dwell_time', 0.5)
            from threading import Thread
            t = Thread(target=self.capture.start_capture,
                       kwargs={'channels': channels, 'dwell_time': dwell})
            t.daemon = True
            t.start()

        logger.info(f"Started {method} capture on {interface}")

    def start_web_interface(self):
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
        self.running = True
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        try:
            self.setup_interface()
            self.start_gps()
            self.start_capture()
            self.start_web_interface()
            logger.info("WiFi Logger running. Press Ctrl+C to stop.")

            while self.running:
                self.periodic_tasks()
                time.sleep(60)

        except KeyboardInterrupt:
            logger.info("Shutdown requested")
        except Exception as e:
            logger.error(f"Error in main loop: {e}", exc_info=True)
        finally:
            self.shutdown()

    def periodic_tasks(self):
        now = datetime.utcnow()

        if isinstance(self.capture, KismetIntegration):
            self.capture.process_kismet_logs()

        backup_config = self.config.get('database', {})
        backup_interval = backup_config.get('backup_interval', 86400)
        if (now - self.last_backup).total_seconds() >= backup_interval:
            self.backup_database()
            self.last_backup = now

        retention_config = self.config.get('retention', {})
        cleanup_interval = retention_config.get('cleanup_interval', 86400)
        if (now - self.last_cleanup).total_seconds() >= cleanup_interval:
            self.cleanup_old_data()
            self.last_cleanup = now

    def backup_database(self):
        backup_dir = Path(self.config['database'].get('backup_dir', '/var/lib/wifi-logger/backups'))
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_file = backup_dir / f"wifi_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        try:
            import shutil
            shutil.copy2(self.config['database']['path'], backup_file)
            logger.info(f"Database backed up to {backup_file}")
            backups = sorted(backup_dir.glob("wifi_backup_*.db"))
            if len(backups) > 30:
                for old_backup in backups[:-30]:
                    old_backup.unlink()
        except Exception as e:
            logger.error(f"Failed to backup database: {e}")

    def cleanup_old_data(self):
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
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False

    def shutdown(self):
        logger.info("Shutting down WiFi Logger...")

        if self.gps:
            self.gps.stop_tracking()

        if self.session_id and self.capture:
            self.db.end_session(self.session_id, self.capture.total_packets)
            logger.info(f"Session #{self.session_id} closed")

        self.db.close()
        logger.info("WiFi Logger shutdown complete")


def _monitor_loop(stdscr, wifi_logger):
    """Curses live monitor display."""
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()
    stdscr.nodelay(True)
    stdscr.timeout(1000)

    session_start = datetime.utcnow()
    recent = []
    MAX_RECENT = 30
    prev_seen = set()

    def safe(y, x, text, attr=0):
        h, w = stdscr.getmaxyx()
        if y < 0 or y >= h - 1 or x < 0:
            return
        text = str(text)[:max(0, w - x - 1)]
        try:
            stdscr.addstr(y, x, text, attr)
        except curses.error:
            pass

    while wifi_logger.running:
        key = stdscr.getch()
        if key == ord('q'):
            wifi_logger.running = False
            break

        stdscr.erase()
        h, w = stdscr.getmaxyx()
        now = datetime.utcnow()
        elapsed = int((now - session_start).total_seconds())
        elapsed_str = f"{elapsed//3600:02d}:{(elapsed%3600)//60:02d}:{elapsed%60:02d}"

        # header
        hdr = f" METADRIVER // MONITOR   {now.strftime('%Y-%m-%d %H:%M:%S')} UTC   [q] quit "
        safe(0, 0, hdr.ljust(w), curses.A_REVERSE)

        # stats
        try:
            stats = wifi_logger.db.get_stats()
        except Exception:
            stats = {}

        packets = wifi_logger.capture.total_packets if wifi_logger.capture else 0
        iface   = wifi_logger.config['capture']['interface']
        method  = wifi_logger.config['capture'].get('method', '?')

        DIM  = curses.A_DIM
        BOLD = curses.A_BOLD
        NORM = curses.A_NORMAL

        # left column — session info
        r = 2
        safe(r,   2, "SESSION ", DIM);  safe(r,   12, f"#{wifi_logger.session_id}   {elapsed_str}", NORM)
        safe(r+1, 2, "IFACE   ", DIM);  safe(r+1, 12, f"{iface}  [{method}]", NORM)
        safe(r+2, 2, "PACKETS ", DIM);  safe(r+2, 12, str(packets), BOLD)
        safe(r+3, 2, "NETWORKS", DIM);  safe(r+3, 12, str(stats.get('total_networks', 0)), BOLD)
        safe(r+4, 2, "HIDDEN  ", DIM);  safe(r+4, 12, str(stats.get('hidden_networks', 0)), NORM)
        safe(r+5, 2, "ACTIVE  ", DIM);  safe(r+5, 12, str(stats.get('networks_seen_24h', 0)), NORM)
        safe(r+6, 2, "OBS     ", DIM);  safe(r+6, 12, str(stats.get('total_observations', 0)), NORM)

        # right column — GPS
        gc = w // 2
        if wifi_logger.gps and wifi_logger.gps.current_fix:
            fix = wifi_logger.gps.current_fix
            safe(r,   gc, "GPS     ", DIM); safe(r,   gc+10, "LOCKED", BOLD)
            safe(r+1, gc, "LAT     ", DIM); safe(r+1, gc+10, f"{fix['latitude']:.6f}", NORM)
            safe(r+2, gc, "LON     ", DIM); safe(r+2, gc+10, f"{fix['longitude']:.6f}", NORM)
            safe(r+3, gc, "ALT     ", DIM); safe(r+3, gc+10, f"{fix.get('altitude') or '—'}", NORM)
            safe(r+4, gc, "SPEED   ", DIM); safe(r+4, gc+10, f"{fix.get('speed') or '—'} m/s", NORM)
            safe(r+5, gc, "FIX     ", DIM); safe(r+5, gc+10, f"{fix.get('fix_type', '?')}D", NORM)
            safe(r+6, gc, "SATS    ", DIM); safe(r+6, gc+10, f"{fix.get('satellites') or '—'}", NORM)
        else:
            safe(r,   gc, "GPS     ", DIM); safe(r, gc+10, "NO FIX", DIM)

        # enc distribution
        sec_dist = stats.get('security_distribution', {})
        safe(r+8, 2, "ENC  ", DIM)
        col = 9
        for sec_type, count in sec_dist.items():
            label = f"{(sec_type or 'n/a').upper()}:{count}  "
            if col + len(label) >= w - 2:
                break
            safe(r+8, col, label, NORM)
            col += len(label)

        # divider
        div = r + 10
        safe(div, 0, '─' * w, DIM)
        safe(div, 2, " RECENT ", DIM)

        # recent networks — poll DB for newest, track new ones
        try:
            nets = wifi_logger.db.query_networks({'limit': MAX_RECENT, 'offset': 0})
            for net in reversed(nets):
                bssid = net['bssid']
                if bssid not in prev_seen:
                    prev_seen.add(bssid)
                    ts     = now.strftime('%H:%M:%S')
                    essid  = (net['essid'] or '\u2205')[:22]
                    sec    = (net['security_type'] or '?').upper()[:8]
                    vendor = (net['vendor'] or '')[:16]
                    recent.insert(0, f"  {ts}  {bssid}  {essid:<22}  {sec:<8}  {vendor}")
                    if len(recent) > MAX_RECENT:
                        recent.pop()
        except Exception:
            pass

        list_start = div + 1
        max_lines  = h - list_start - 2
        for i, line in enumerate(recent[:max_lines]):
            safe(list_start + i, 0, line, BOLD if i == 0 else DIM)

        # footer
        safe(h - 1, 0, " [q] quit ".ljust(w), curses.A_REVERSE)

        stdscr.refresh()


def main():
    parser = argparse.ArgumentParser(description="WiFi Logger System")
    parser.add_argument('--service', action='store_true', help='Run as service/daemon')
    parser.add_argument('--config', default='/opt/wifi-logger/config/config.yaml', help='Configuration file path')
    parser.add_argument('--scan', action='store_true', help='Run single 30s scan and exit')
    parser.add_argument('--monitor', action='store_true', help='Live terminal monitor')
    parser.add_argument('--export', help='Export data to file (.geojson or .csv)')
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

    if args.monitor:
        wifi_logger.setup_interface()
        wifi_logger.start_gps()
        wifi_logger.start_capture()
        try:
            curses.wrapper(lambda stdscr: _monitor_loop(stdscr, wifi_logger))
        except KeyboardInterrupt:
            pass
        finally:
            wifi_logger.shutdown()
        return

    if args.scan:
        wifi_logger.setup_interface()
        wifi_logger.start_capture()
        logger.info("Scanning for 30 seconds...")
        time.sleep(30)
        if isinstance(wifi_logger.capture, KismetIntegration):
            wifi_logger.capture.process_kismet_logs()
        wifi_logger.shutdown()
        return

    if args.service:
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
        wifi_logger.run()


if __name__ == "__main__":
    main()
