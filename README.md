# MetaDriver

**WiFi Logger & Wardriving System** — A comprehensive tool for capturing, logging, and mapping WiFi networks with GPS correlation.

Built for Arch Linux with support for Kismet and Scapy capture backends.

## Features

- **Dual Capture Backends** — Kismet integration for passive monitoring, or direct Scapy capture for fine-grained control
- **GPS Tracking** — Correlate WiFi observations with GPS coordinates via `gpsd`
- **SQLite Database** — Efficient local storage with full query support
- **Web Dashboard** — Real-time stats, network browser, and interactive map view
- **GeoJSON Export** — Export geolocated observations for use in mapping tools
- **CSV Export** — Bulk export network data for analysis
- **Systemd Service** — Run as a background daemon with auto-restart
- **Data Retention** — Configurable automatic cleanup of old observations

## Project Structure

```
metadriver/
├── config/
│   └── config.yaml          # Main configuration file
├── scripts/
│   ├── install.sh            # Installation script (Arch Linux)
│   └── systemd/
│       └── wifi-logger.service
├── src/
│   ├── main.py               # Application entry point
│   ├── capture/
│   │   ├── kismet_capture.py  # Kismet log processing
│   │   └── scapy_capture.py   # Direct packet capture
│   ├── database/
│   │   ├── db_manager.py      # Database operations
│   │   └── schema.sql         # SQLite schema
│   ├── utils/
│   │   └── gps_handler.py     # GPS/GPSD integration
│   └── web/
│       ├── app.py             # Flask web application
│       └── templates/
│           ├── index.html     # Dashboard
│           └── map.html       # Map view
└── requirements.txt
```

## Installation

### Quick Install (Arch Linux)

```bash
sudo bash scripts/install.sh
```

### Manual Install

```bash
# Install system dependencies
sudo pacman -S python kismet gpsd sqlite tshark

# Install Python dependencies
pip install -r requirements.txt
```

## Configuration

Edit `config/config.yaml` to set your capture interface, GPS device, and preferences:

```yaml
capture:
  interface: "wlan0mon"
  method: "kismet"       # kismet or scapy

gps:
  enabled: true
  device: "/dev/ttyUSB0"

web:
  enabled: true
  host: "127.0.0.1"
  port: 8080
```

## Usage

```bash
# Run in foreground
python3 src/main.py --config config/config.yaml

# Run a single 30-second scan
python3 src/main.py --config config/config.yaml --scan

# Show database statistics
python3 src/main.py --config config/config.yaml --stats

# Export data to GeoJSON
python3 src/main.py --config config/config.yaml --export output.geojson

# Export data to CSV
python3 src/main.py --config config/config.yaml --export output.csv

# Run as daemon
python3 src/main.py --config config/config.yaml --service
```

### Import OUI Vendor Database (recommended, one-time)

```bash
# Downloads IEEE OUI CSV (~5MB) and imports into the database
python3 scripts/import_oui.py --db /var/lib/wifi-logger/wifi_data.db

# Or use a local file
python3 scripts/import_oui.py --db /var/lib/wifi-logger/wifi_data.db --file oui.csv
```

### Systemd Service

```bash
sudo cp scripts/systemd/wifi-logger.service /etc/systemd/system/
sudo systemctl enable wifi-logger
sudo systemctl start wifi-logger
```

## Web Interface

When `web.enabled` is `true` in the config, the dashboard is available at `http://127.0.0.1:8080`:

- **Dashboard** — Live stats, network table with filtering, security distribution
- **Map** (`/api/map`) — Interactive dark-themed map with color-coded security markers
- **API Endpoints**:
  - `GET /api/stats` — Database statistics
  - `GET /api/networks` — Query networks (supports `essid`, `vendor`, `security`, `page`, `limit` filters)
  - `GET /api/network/<id>` — Observations for a specific network
  - `GET /api/sessions` — Recent capture sessions
  - `GET /api/geojson` — GeoJSON export
  - `GET /api/export/csv` — CSV download

## License

MIT
