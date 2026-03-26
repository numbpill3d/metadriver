#!/bin/bash
# Installation script for WiFi Logger System

set -e

echo "=== WiFi Logger Installation ==="
echo "For Arch Linux L15 with Brostrend AXE5400"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root or with sudo"
    exit 1
fi

# Update system
echo "Updating system..."
pacman -Syu --noconfirm

# Install dependencies
echo "Installing dependencies..."
pacman -S --noconfirm \
    python python-pip \
    sqlite \
    tshark wireshark-cli \
    kismet \
    gpsd gpsd-clients \
    networkmanager \
    git base-devel \
    systemd

# Install Python packages
echo "Installing Python packages..."
pip install --upgrade pip
pip install \
    scapy \
    flask \
    waitress \
    pyyaml \
    gpsd-py3 \
    python-daemon \
    requests

# Clone or create project structure
PROJECT_DIR="/opt/wifi-logger"
echo "Creating project structure at $PROJECT_DIR..."
mkdir -p $PROJECT_DIR
mkdir -p $PROJECT_DIR/{config,src/{capture,database,parser,utils,web},logs,data,scripts/systemd}

# Set permissions
chown -R $SUDO_USER:$SUDO_USER $PROJECT_DIR
chmod 755 $PROJECT_DIR

# Create database directory with proper permissions
mkdir -p /var/lib/wifi-logger
chown -R $SUDO_USER:$SUDO_USER /var/lib/wifi-logger
chmod 755 /var/lib/wifi-logger

echo "Installation complete!"
echo "Please configure your settings in $PROJECT_DIR/config/config.yaml"