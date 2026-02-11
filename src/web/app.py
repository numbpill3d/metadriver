#!/usr/bin/env python3
"""
Web interface for WiFi Logger
"""

from flask import Flask, render_template, jsonify, request, send_file
import json
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3

def create_app(db_manager):
    app = Flask(__name__)
    
    @app.route('/')
    def index():
        return render_template('index.html')
    
    @app.route('/api/stats')
    def get_stats():
        stats = db_manager.get_stats()
        return jsonify(stats)
    
    @app.route('/api/networks')
    def get_networks():
        filters = {}
        
        # Apply filters from query parameters
        if request.args.get('essid'):
            filters['essid_like'] = request.args.get('essid')
        if request.args.get('vendor'):
            filters['vendor_like'] = request.args.get('vendor')
        if request.args.get('security'):
            filters['security_type'] = request.args.get('security')
        if request.args.get('hidden'):
            filters['is_hidden'] = bool(request.args.get('hidden'))
        
        networks = db_manager.query_networks(filters)
        return jsonify(networks)
    
    @app.route('/api/network/<int:network_id>')
    def get_network(network_id):
        observations = db_manager.get_network_observations(network_id)
        return jsonify(observations)
    
    @app.route('/api/geojson')
    def get_geojson():
        network_ids = request.args.getlist('network_ids[]')
        if network_ids:
            network_ids = [int(id) for id in network_ids]
        
        geojson = db_manager.export_geojson(network_ids if network_ids else None)
        return jsonify(geojson)
    
    @app.route('/api/export/csv')
    def export_csv():
        # Generate CSV export
        import csv
        import io
        
        filters = {}
        if request.args.get('days'):
            days = int(request.args.get('days'))
            filters['min_last_seen'] = datetime.utcnow() - timedelta(days=days)
        
        networks = db_manager.query_networks(filters)
        
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=[
            'bssid', 'essid', 'vendor', 'security_type',
            'first_seen', 'last_seen', 'observation_count'
        ])
        
        writer.writeheader()
        for network in networks:
            writer.writerow({
                'bssid': network['bssid'],
                'essid': network['essid'] or 'Hidden',
                'vendor': network['vendor'] or 'Unknown',
                'security_type': network['security_type'] or 'Unknown',
                'first_seen': network['first_seen'],
                'last_seen': network['last_seen']
            })
        
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode()),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'wifi_export_{datetime.now().strftime("%Y%m%d")}.csv'
        )
    
    @app.route('/api/map')
    def map_view():
        return render_template('map.html')
    
    return app