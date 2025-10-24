#!/usr/bin/env python3
"""Utilities for generating forensic reports from Apple Maps tiles."""

from __future__ import annotations

import html
import json
import logging
import sqlite3
import struct
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Iterator


TILE_SELECT_QUERY = """
        SELECT 
            d.rowid,
            d.data,
            d.size,
            t.key_a,
            t.key_b,
            t.key_c,
            t.key_d,
            t.tileset,
            t.insert_timestamp,
            a.timestamp as access_timestamp
        FROM data d
        LEFT JOIN tiles t ON d.rowid = t.data_pk
        LEFT JOIN access_times a ON d.rowid = a.data_pk
        WHERE d.data IS NOT NULL
        ORDER BY d.rowid
    """


class MapTilesRepository:
    """SQLite helper that centralises read-only queries for map tile analysis."""

    def __init__(self, database: Path | str) -> None:
        self.database = Path(database).expanduser().resolve()

    def validate(self) -> None:
        """Ensure the database exists and contains the expected schema."""

        if not self.database.exists():
            raise ValueError(f"Database file not found: {self.database}")
        if not self.database.is_file():
            raise ValueError(f"Database path is not a file: {self.database}")

        try:
            connection = sqlite3.connect(self.database.as_posix())
            try:
                cursor = connection.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tiles'")
                if cursor.fetchone() is None:
                    raise ValueError("Database does not contain required 'tiles' table")
            finally:
                connection.close()
        except sqlite3.Error as exc:  # pragma: no cover - defensive logging
            raise ValueError(f"Cannot open database: {exc}") from exc

    def iterate_tiles(self) -> Iterator[tuple]:
        """Yield tile rows with joined metadata."""

        connection = sqlite3.connect(self.database.as_posix())
        try:
            cursor = connection.cursor()
            cursor.execute(TILE_SELECT_QUERY)
            for row in cursor:
                yield row
        finally:
            connection.close()

logger = logging.getLogger(__name__)

def calculate_tile_bounds(lat, lon, zoom):
    """
    The bounding box for a tile at the given center point and zoom level. This is probabaly not correct though as it may be a corner.
    Calculate the bounding box for a tile at the given center point and zoom level.
    
    In tile-based mapping systems, each tile represents a rectangular area.
    The size of the area depends on the zoom level:
    - Zoom 0: Each tile = entire world
    - Zoom 12: Each tile ≈ 20km × 20km at equator
    - Zoom 16: Each tile ≈ 1.2km × 1.2km at equator
    
    Returns: (north, south, east, west) boundaries in degrees
    """
    import math
    
    # At each zoom level, the world is divided into 2^zoom × 2^zoom tiles
    n = 2 ** zoom
    
    # Approximate tile size in degrees (simplified calculation)
    # Each tile is 256×256 pixels in Web Mercator projection
    tile_size_lon = 360.0 / n  # Longitude degrees per tile
    
    # Latitude is more complex due to Mercator projection
    # Approximate using the tile height at this latitude
    lat_rad = math.radians(lat)
    tile_size_lat = (360.0 / n) * math.cos(lat_rad)  # Adjusted for latitude
    
    # Calculate bounds (approximate tile coverage)
    half_lon = tile_size_lon / 2
    half_lat = tile_size_lat / 2
    
    north = min(lat + half_lat, 90)
    south = max(lat - half_lat, -90)
    east = min(lon + half_lon, 180)
    west = max(lon - half_lon, -180)
    
    return {
        'north': north,
        'south': south,
        'east': east,
        'west': west,
        'center_lat': lat,
        'center_lon': lon
    }

def decode_apple_tile_key(key_a, key_b, key_c, key_d):
    """
    Decode Apple's tile coordinate system to latitude/longitude with bounding box.
    
    It looks like Apple uses multiple encoding schemes based on key magnitudes.
    
    Discovered via MapKit tile grid analysis (inspired by MapKit zoom = log2(360*width/(longitudeDelta*128))):
    
    ENCODING TYPE 1: HIGH key_c (>100M) - Web Mercator projection
      - Uses continuous x_scale/y_scale division
      - x_scale = ±258.35, y_scale = 64.00
      - Most accurate for zoom 16 tiles
      - Accuracy: ±0.1° to ±0.2°
    
    ENCODING TYPE 2: LOW key_c (<100M) - Tile Index system
      - Keys encode tile indices in a 2^zoom × 2^zoom grid
      - Adaptive divisors based on key_b magnitude:
        * Low key_b (<1B): div_x=65536 (2^16), div_y=1024 (2^10)
        * High key_b (>1B): div_x=4096 (2^12), div_y=16384 (2^14)
      - Accuracy: ±1° to ±5°
    
    This explains the "Arctic false positives" 
    """
    import struct
    import math
    
    try:
        # Extract zoom from byte 1 of key_d
        key_d_bytes = struct.pack('<I', key_d & 0xFFFFFFFF)
        zoom = key_d_bytes[1]
        # Skip non-standard zooms
        if zoom == 0:
            return None
        
        # For very high zoom values (>100), treat as zoom 12 (common fallback)
        if zoom > 100:
            zoom = 12
        
        # Convert to signed integers
        key_b_signed = struct.unpack('i', struct.pack('I', key_b & 0xFFFFFFFF))[0]
        key_c_signed = struct.unpack('i', struct.pack('I', key_c & 0xFFFFFFFF))[0]
        
        # CRITICAL DISCOVERY: Use ratio (key_b/key_c) as primary discriminator!
        # Tiles with ratio ~1 (key_b ≈ key_c) use TILE INDEX encoding
        # Tiles with ratio >>1 (key_b >> key_c) use Web Mercator encoding
        ratio = abs(key_b_signed) / abs(key_c_signed) if abs(key_c_signed) > 0 else 999
        
        
        # Example: Tile #954 (Birmingham UK): key_b=91M, key_c=88M, ratio=1.04
        #          → 52.48°N, -1.90°W ✓
        if 0.5 <= ratio <= 2.0 and abs(key_c_signed) > 20_000_000:
            n = 2 ** 12
            x_scale = 176.36
            y_scale = 256.0
            
            # Calculate normalized coordinates
            x_norm = key_b_signed / (x_scale if key_b_signed >= 0 else -x_scale) / (256 * n)
            lon = x_norm * 360 - 180
            
            y_norm = key_c_signed / y_scale / (256 * n)
            
            # Standard Web Mercator latitude from y_norm
            if 0 <= y_norm <= 1:
                lat_rad = math.atan(math.sinh(math.pi * (1 - 2 * y_norm)))
                lat = math.degrees(lat_rad)
                
                # Validate result is reasonable
                if -90 <= lat <= 90 and -180 <= lon <= 180:
                    bounds = calculate_tile_bounds(lat, lon, zoom)
                    return {
                        'lat': lat,
                        'lon': lon,
                        'zoom': zoom,
                        'accuracy': 'Medium (±4°)',
                        'bounds': bounds,
                        'tileset': key_a  # Store key_a as tileset identifier
                    }
        
        # SPECIAL CASE: Very small key_c (<1M) - These are low-zoom world tiles
        # These tiles typically have place names from large geographic regions
        # They should NOT be plotted as they represent continental/world views
        if abs(key_c_signed) < 1_000_000:
            return {
                'latitude': None,
                'longitude': None,
                'zoom': zoom,
                'accuracy': 'Unknown - Low zoom world tile',
                'confidence': 'Low',
                'encoding_type': 'World Tile (key_c < 1M)',
                'notes': f'Very small key_c ({abs(key_c_signed):,}) indicates world/continent view tile. Check place names for regional context but coordinates cannot be reliably decoded.'
            }
        
        # Determine encoding type by key_c magnitude
        is_low_key_c = abs(key_c_signed) < 150_000_000  # 150 million threshold
        
        if is_low_key_c:
            # ENCODING TYPE 2: Multiple approaches for low key_c tiles
            lat = None
            lon = None
            accuracy = None
            
            # VARIANT A: Very high key_b with moderate-to-high key_c
            # x_scale varies: 516, 1033, or 2067 (2x, 4x, or 8x standard 258)
            # KEY INSIGHT: Use ratio (key_b/key_c) to distinguish formulas!
            if abs(key_b_signed) > 1_300_000_000:
                # Calculate ratio to determine formula
                ratio = abs(key_b_signed) / abs(key_c_signed) if abs(key_c_signed) > 0 else 999
                
                # High ratio (>70) means use standard formula, not multi-scale
                if ratio > 70:
                    # Skip VARIANT A, fall through to standard formula
                    pass
                else:
                    # Low to medium ratio: use multi-scale formulas
                    if abs(key_c_signed) > 100_000_000:
                        # Very high key_c (>100M): use n=2^16, x=556, y=16
                        n = 2 ** 16
                        x_scale = 556.05 if key_b_signed >= 0 else -556.05
                        y_scale = 16.0
                    elif abs(key_c_signed) > 50_000_000:
                        # High key_c (50-100M): use n=2^16, x=517, y=8
                        n = 2 ** 16
                        x_scale = 516.70 if key_b_signed >= 0 else -516.70
                        y_scale = 8.0
                    elif 20_000_000 < abs(key_c_signed) <= 50_000_000:
                        # Moderate key_c with LOW ratio: use n=2^12, x=2067, y=64
                        n = 2 ** 12
                        x_scale = 2066.80 if key_b_signed >= 0 else -2066.80
                        y_scale = 64.0
                    else:
                        # Lower key_c: use n=2^12, x=1033, y=16
                        n = 2 ** 12
                        x_scale = 1033.40 if key_b_signed >= 0 else -1033.40
                        y_scale = 16.0
                    
                    x_norm = key_b_signed / x_scale / (256 * n)
                    lon = x_norm * 360 - 180
                    
                    # Hemisphere correction for high key_c tiles (abs(key_c) > 50M)
                    # Pattern: key_b < 2B represents eastern hemisphere, needs +180° correction
                    if abs(key_c_signed) > 50_000_000 and abs(key_b_signed) < 2_000_000_000:
                        lon += 180
                    
                    y_norm = key_c_signed / y_scale / (256 * n)
                    
                    if 0 <= y_norm <= 1:
                        lat_rad = math.atan(math.sinh(math.pi * (1 - 2 * y_norm)))
                        lat = math.degrees(lat_rad)
                        accuracy = 'Medium (±4°)'
            
            # VARIANT B: High key_b (700-1300M) with low key_c (<20M)
            # Use x_scale=1033 (4x standard) for very low key_c
            # Tiles #803-805: key_b ~709M, key_c ~7M
            if lat is None and 700_000_000 < abs(key_b_signed) <= 1_300_000_000 and abs(key_c_signed) < 10_000_000:
                n = 2 ** 12
                x_scale = 1033.40 if key_b_signed >= 0 else -1033.40
                y_scale = 16.0
                
                x_norm = key_b_signed / x_scale / (256 * n)
                lon = x_norm * 360 - 180
                
                y_norm = key_c_signed / y_scale / (256 * n)
                
                if 0 <= y_norm <= 1:
                    lat_rad = math.atan(math.sinh(math.pi * (1 - 2 * y_norm)))
                    lat = math.degrees(lat_rad)
                    accuracy = 'Medium (±4°)'
            
            # VARIANT C: Medium key_b (500-700M) with low key_c (<10M)
            # Use x_scale=516 (2x standard)
            if lat is None and 500_000_000 < abs(key_b_signed) <= 700_000_000 and abs(key_c_signed) < 10_000_000:
                n = 2 ** 12
                x_scale = 516.70 if key_b_signed >= 0 else -516.70
                y_scale = 8.0
                
                x_norm = key_b_signed / x_scale / (256 * n)
                lon = x_norm * 360 - 180
                
                y_norm = key_c_signed / y_scale / (256 * n)
                
                if 0 <= y_norm <= 1:
                    lat_rad = math.atan(math.sinh(math.pi * (1 - 2 * y_norm)))
                    lat = math.degrees(lat_rad)
                    accuracy = 'Medium (±4°)'
            
            # VARIANT D: Medium-high key_b (700-900M) with medium-high key_c (50-150M)
            # Use zoom 16 with custom scales: x_scale ~152 (less than standard 258), y_scale=16
            if lat is None and 700_000_000 < abs(key_b_signed) <= 900_000_000 and 50_000_000 < abs(key_c_signed) < 150_000_000:
                n = 2 ** 16
                x_scale = 152.40 if key_b_signed >= 0 else -152.40
                y_scale = 16.0  # Medium-high key_c uses 16.0
                
                x_norm = key_b_signed / x_scale / (256 * n)
                lon = x_norm * 360 - 180
                
                y_norm = key_c_signed / y_scale / (256 * n)
                
                if 0 <= y_norm <= 1:
                    lat_rad = math.atan(math.sinh(math.pi * (1 - 2 * y_norm)))
                    lat = math.degrees(lat_rad)
                    accuracy = 'Medium (±2°)'
            
            # VARIANT E: Try Web Mercator with y_scale=4.0 (most common low key_c)
            if lat is None:
                n = 2 ** 16
                x_scale = 258.35 if key_b_signed >= 0 else -258.35
                y_scale = 4.0  # Low key_c uses 4.0 instead of 64.0
                
                x_norm = key_b_signed / x_scale / (256 * n)
                lon = x_norm * 360 - 180
                
                y_norm = key_c_signed / y_scale / (256 * n)
                
                if 0 <= y_norm <= 1:
                    # Web Mercator formula worked - but check if result makes sense
                    lat_rad = math.atan(math.sinh(math.pi * (1 - 2 * y_norm)))
                    lat = math.degrees(lat_rad)
                    
                    # If latitude is in polar regions (>80° or <-80°) with very low key_c,
                    # it's likely a false positive - try tile index instead
                    if abs(lat) > 80 and abs(key_c_signed) < 10_000_000:
                        # Likely false positive, fallback to tile index with zoom 12
                        is_low_key_b = abs(key_b_signed) < 500_000_000
                        
                        if is_low_key_b:
                            # Use zoom 12 for very low key values
                            n_zoom = 2 ** 12  # Force zoom 12 instead of stored zoom
                            div_x = 65536  # 2^16
                            div_y = 1024   # 2^10
                            
                            x_tile = (key_b_signed // div_x) % n_zoom
                            y_tile = (key_c_signed // div_y) % n_zoom
                            
                            lon = (x_tile / n_zoom) * 360 - 180
                            lat_rad = math.atan(math.sinh(math.pi * (1 - 2 * y_tile / n_zoom)))
                            lat = math.degrees(lat_rad)
                            accuracy = 'Medium (±4°)'
                        else:
                            # For higher key_b, use standard method
                            n_zoom = 2 ** zoom
                            div_x = 4096
                            div_y = 16384
                            
                            x_tile = (key_b_signed // div_x) % n_zoom
                            y_tile = (key_c_signed // div_y) % n_zoom
                            
                            lon = (x_tile / n_zoom) * 360 - 180
                            lat_rad = math.atan(math.sinh(math.pi * (1 - 2 * y_tile / n_zoom)))
                            lat = math.degrees(lat_rad)
                            accuracy = 'Medium (±2-4°)'
                    else:
                        accuracy = 'Medium (±1°)'
                else:
                    # VARIANT C: Fallback to tile index method
                    is_low_key_b = abs(key_b_signed) < 500_000_000  # 500 million threshold
                    
                    n_zoom = 2 ** zoom
                    
                    if is_low_key_b:
                        # Very low key_b: use 65536/1024
                        div_x = 65536  # 2^16
                        div_y = 1024   # 2^10
                    else:
                        # Higher key_b: use 4096/16384
                        div_x = 4096   # 2^12
                        div_y = 16384  # 2^14
                    
                    # Calculate tile indices with modulo wrapping
                    x_tile = (key_b_signed // div_x) % n_zoom
                    y_tile = (key_c_signed // div_y) % n_zoom
                    
                    # Convert tile indices to lat/lon
                    lon = (x_tile / n_zoom) * 360 - 180
                    lat_rad = math.atan(math.sinh(math.pi * (1 - 2 * y_tile / n_zoom)))
                    lat = math.degrees(lat_rad)
                    accuracy = 'Medium (±2-4°)'
            
        else:
            # ENCODING TYPE 1: Web Mercator Projection
            lat = None
            lon = None
            accuracy = None
            
            # Special case: VERY high key_c with specific patterns            
            # Use custom scales: x=131.30, y=128.00 at zoom 16
            if abs(key_c_signed) > 900_000_000 and 0.3 <= ratio <= 0.5:
                n = 2 ** 16
                x_scale = 131.30 if key_b_signed >= 0 else -131.30
                y_scale = 128.00
                
                x_norm = key_b_signed / x_scale / (256 * n)
                lon = x_norm * 360 - 180
                
                # Hemisphere correction for eastern locations
                if abs(key_b_signed) < 2_000_000_000:
                    lon += 180
                
                y_norm = key_c_signed / y_scale / (256 * n)
                
                if 0 <= y_norm <= 1:
                    lat_rad = math.atan(math.sinh(math.pi * (1 - 2 * y_norm)))
                    lat = math.degrees(lat_rad)
                    accuracy = 'Medium (±2°)'
            
            # Use custom scales: x=354.00, y=128.00 at zoom 16
            elif 800_000_000 <= abs(key_c_signed) <= 820_000_000 and 2.0 <= ratio <= 2.3:
                n = 2 ** 16
                x_scale = 354.00 if key_b_signed >= 0 else -354.00
                y_scale = 128.00
                
                x_norm = key_b_signed / x_scale / (256 * n)
                lon = x_norm * 360 - 180
                
                y_norm = key_c_signed / y_scale / (256 * n)
                
                if 0 <= y_norm <= 1:
                    lat_rad = math.atan(math.sinh(math.pi * (1 - 2 * y_norm)))
                    lat = math.degrees(lat_rad)
                    accuracy = 'Medium (±2°)'
            
            # PATTERN 2: Composite Index (key_c > 800M, very low ratio < 0.1)
            # These tiles have key_b as composite index, not standard coordinates
            # Return None coordinates - will appear in table but not plotted on map.
            elif (abs(key_c_signed) > 800_000_000 and ratio < 0.1):
                return {
                    'latitude': None,
                    'longitude': None,
                    'accuracy': 'Unknown - key_b encodes composite index not coordinates',
                    'confidence': 'Low',
                    'encoding_type': 'Composite Index (key_c > 800M)',
                    'notes': f'key_c={abs(key_c_signed):,} suggests specific location but key_b={abs(key_b_signed):,} does not encode standard longitude. Check VMP4 place names for actual location.'
                }
            
            # Standard Web Mercator formula
            if lat is None:
                # Try zoom 16 formula first (most common and accurate)
                n = 2 ** 16
                x_scale = 258.35 if key_b_signed >= 0 else -258.35
                y_scale = 64.00
                
                x_norm = key_b_signed / x_scale / (256 * n)
                lon = x_norm * 360 - 180
                
                y_norm = key_c_signed / y_scale / (256 * n)
            
            # Validate y_norm is in valid range
            if 0 <= y_norm <= 1:
                lat_rad = math.atan(math.sinh(math.pi * (1 - 2 * y_norm)))
                lat = math.degrees(lat_rad)
                accuracy = 'High (±0.1°)'
            else:
                # Try zoom 12 formula as fallback
                n = 2 ** 12
                x_scale = 4095.10
                y_scale = 63.99
                
                x_norm = key_b_signed / x_scale / (256 * n)
                lon = x_norm * 360 - 180
                
                y_norm = key_c_signed / y_scale / (256 * n)
                
                if 0 <= y_norm <= 1:
                    lat_rad = math.atan(math.sinh(math.pi * (1 - 2 * y_norm)))
                    lat = math.degrees(lat_rad)
                    accuracy = 'High (±0.2°)'
                else:
                    return None
        
        # Validation: Must be within valid Earth coordinates
        if abs(lat) > 90 or abs(lon) > 180:
            return None
        
        # Relaxed filtering: only exclude extreme polar regions
        if abs(lat) > 85:
            return None
        
        # Calculate the bounding box for this tile
        bounds = calculate_tile_bounds(lat, lon, zoom)
        
        # accuracy was already set by the working formula
        
        return {
            'tileset': key_a,
            'zoom': zoom,
            'lat': lat,
            'lon': lon,
            'bounds': bounds,
            'accuracy': accuracy
        }
    except:
        return None

def parse_vmp4_metadata(blob_data):
    """Extract metadata from VMP4 BLOB."""
    if len(blob_data) < 8 or blob_data[0:4] != b'VMP4':
        return None
    
    section_count = struct.unpack('<H', blob_data[6:8])[0]
    sections = []
    offset = 8
    
    for i in range(section_count):
        if offset + 10 > len(blob_data):
            break
            
        section_type = struct.unpack('<H', blob_data[offset:offset+2])[0]
        section_offset = struct.unpack('<I', blob_data[offset+2:offset+6])[0]
        section_size = struct.unpack('<I', blob_data[offset+6:offset+10])[0]
        
        compressed = False
        if section_offset + section_size <= len(blob_data):
            raw_data = blob_data[section_offset:section_offset + section_size]
            if len(raw_data) > 0 and raw_data[0] in (0x01, 0xC1):
                compressed = True
        
        sections.append({
            'type': section_type,
            'size': section_size,
            'compressed': compressed
        })
        
        offset += 10
    
    return {'section_count': section_count, 'sections': sections, 'total_size': len(blob_data)}

def extract_place_names(blob_data):
    """Extract readable place names from section 0x0A."""
    if len(blob_data) < 8 or blob_data[0:4] != b'VMP4':
        return []
    
    section_count = struct.unpack('<H', blob_data[6:8])[0]
    offset = 8
    
    for i in range(section_count):
        if offset + 10 > len(blob_data):
            break
            
        section_type = struct.unpack('<H', blob_data[offset:offset+2])[0]
        section_offset = struct.unpack('<I', blob_data[offset+2:offset+6])[0]
        section_size = struct.unpack('<I', blob_data[offset+6:offset+10])[0]
        
        if section_type == 0x0A:
            if section_offset + section_size <= len(blob_data):
                raw_data = blob_data[section_offset:section_offset + section_size]
                
                if len(raw_data) > 5 and raw_data[0] in (0x01, 0xC1):
                    import zlib
                    try:
                        decompressed = zlib.decompress(raw_data[5:])
                        text = decompressed.decode('utf-8', errors='ignore')
                        names = [n.strip() for n in text.split('\x00') if n.strip() and len(n.strip()) > 2]
                        return names  # Return all names, not just first 10
                    except:
                        pass
        
        offset += 10
    
    return []

def extract_locale_info(blob_data):
    """Extract locale/language info from section 0x0B."""
    if len(blob_data) < 8 or blob_data[0:4] != b'VMP4':
        return ""
    
    section_count = struct.unpack('<H', blob_data[6:8])[0]
    offset = 8
    
    for i in range(section_count):
        if offset + 10 > len(blob_data):
            break
            
        section_type = struct.unpack('<H', blob_data[offset:offset+2])[0]
        section_offset = struct.unpack('<I', blob_data[offset+2:offset+6])[0]
        section_size = struct.unpack('<I', blob_data[offset+6:offset+10])[0]
        
        if section_type == 0x0B:
            if section_offset + section_size <= len(blob_data):
                raw_data = blob_data[section_offset:section_offset + section_size]
                try:
                    text = raw_data.decode('utf-8', errors='ignore')
                    return text.strip('\x00').strip()
                except:
                    pass
        
        offset += 10
    
    return ""

def extract_languages(blob_data):
    """Extract language codes from section 0x0D."""
    if len(blob_data) < 8 or blob_data[0:4] != b'VMP4':
        return []
    
    section_count = struct.unpack('<H', blob_data[6:8])[0]
    offset = 8
    
    for i in range(section_count):
        if offset + 10 > len(blob_data):
            break
            
        section_type = struct.unpack('<H', blob_data[offset:offset+2])[0]
        section_offset = struct.unpack('<I', blob_data[offset+2:offset+6])[0]
        section_size = struct.unpack('<I', blob_data[offset+6:offset+10])[0]
        
        if section_type == 0x0D:
            if section_offset + section_size <= len(blob_data):
                raw_data = blob_data[section_offset:section_offset + section_size]
                
                if len(raw_data) > 5 and raw_data[0] in (0x01, 0xC1):
                    import zlib
                    try:
                        decompressed = zlib.decompress(raw_data[5:])
                        text = decompressed.decode('utf-8', errors='ignore')
                        # Extract language codes (usually 2-5 chars separated by nulls)
                        langs = [l.strip() for l in text.split('\x00') if l.strip() and 2 <= len(l.strip()) <= 8 and l.strip().replace('-', '').isalnum()]
                        return langs[:30]  # Return up to 30 language codes
                    except:
                        pass
        
        offset += 10
    
    return []

# ===== WOOP ADVANCED VMP4 PARSERS =====

def decompress_vmp4_section(raw_data):
    """Helper to decompress VMP4 section data."""
    if len(raw_data) > 5 and raw_data[0] in (0x01, 0xC1):
        import zlib
        try:
            return zlib.decompress(raw_data[5:])
        except:
            try:
                return zlib.decompress(raw_data)
            except:
                return None
    return raw_data

def parse_all_vmp4_sections(blob_data):
    """Parse all sections from VMP4 blob and return as dict."""
    if len(blob_data) < 8 or blob_data[0:4] != b'VMP4':
        return {}
    
    section_count = struct.unpack('<H', blob_data[6:8])[0]
    sections = {}
    offset = 8
    
    for i in range(section_count):
        if offset + 10 > len(blob_data):
            break
            
        section_type = struct.unpack('<H', blob_data[offset:offset+2])[0]
        section_offset = struct.unpack('<I', blob_data[offset+2:offset+6])[0]
        section_size = struct.unpack('<I', blob_data[offset+6:offset+10])[0]
        
        if section_offset + section_size <= len(blob_data):
            raw_data = blob_data[section_offset:section_offset + section_size]
            sections[section_type] = raw_data
        
        offset += 10
    
    return sections

def extract_tile_metadata_advanced(blob_data):
    """Extract detailed metadata from section 0x01."""
    sections = parse_all_vmp4_sections(blob_data)
    
    if 0x01 not in sections:
        return None
    
    raw_data = sections[0x01]
    decompressed = decompress_vmp4_section(raw_data)
    
    if not decompressed or len(decompressed) < 8:
        return None
    
    metadata = {
        'section_type': '0x01',
        'size': len(decompressed)
    }
    
    # Extract timestamp (even though they may not mean much )
    try:
        from datetime import datetime
        for offset in [0, 4, 8, 12, 16]:
            if offset + 4 <= len(decompressed):
                timestamp = struct.unpack('<I', decompressed[offset:offset+4])[0]
                if 0 < timestamp < 2000000000:
                    try:
                        dt = datetime.fromtimestamp(timestamp)
                        if 2000 < dt.year < 2030:
                            metadata['timestamp'] = dt.strftime('%Y-%m-%d %H:%M:%S')
                            metadata['timestamp_unix'] = timestamp
                            break
                    except:
                        pass
    except:
        pass
    
    # Extract version
    try:
        if len(decompressed) >= 4:
            version_bytes = decompressed[:4]
            version = '.'.join(str(b) for b in version_bytes if b < 100)
            if version:
                metadata['version'] = version
    except:
        pass
    
    return metadata

def extract_geometry_data(blob_data):
    """
    Extract vector geometry metadata from section 0x14.
    
    NOTE: This section contains ENCODED vector data (roads, buildings, etc.)
    in a proprietary binary format. Proper parsing requires reverse engineering
    the format specification. Current implementation only extracts size/presence
    as a complexity indicator.

    Its a nonissue anyway because this did not contain historical route data like I hoped.
    
    See GEOMETRY_ANALYSIS_FINDINGS.md for details.
    """
    sections = parse_all_vmp4_sections(blob_data)
    
    if 0x14 not in sections:
        return None
    
    raw_data = sections[0x14]
    decompressed = decompress_vmp4_section(raw_data)
    
    if not decompressed:
        return None
    
    result = {
        'section_type': '0x14',
        'compressed_size': len(raw_data),
        'decompressed_size': len(decompressed),
        'has_geometry': True,
        'compression_ratio': round(len(decompressed) / len(raw_data), 2) if len(raw_data) > 0 else 1.0
    }
    
    # Classify complexity based on decompressed size
    size_kb = len(decompressed) / 1024
    if size_kb < 1:
        result['complexity'] = 'minimal'
    elif size_kb < 10:
        result['complexity'] = 'moderate'
    elif size_kb < 50:
        result['complexity'] = 'high'
    else:
        result['complexity'] = 'very_high'
    
    return result

def extract_coordinate_bounds(blob_data):
    """Extract precise coordinate bounds from sections 0x1E or 0x02."""
    sections = parse_all_vmp4_sections(blob_data)
    
    for section_type in [0x1E, 0x02]:
        if section_type not in sections:
            continue
        
        raw_data = sections[section_type]
        decompressed = decompress_vmp4_section(raw_data)
        
        if not decompressed or len(decompressed) < 16:
            continue
        
        # Try as doubles
        try:
            if len(decompressed) >= 32:
                values = struct.unpack('<4d', decompressed[:32])
                
                if all(-180 <= v <= 180 for v in values):
                    return {
                        'section_type': hex(section_type),
                        'lat_min': values[0],
                        'lat_max': values[1],
                        'lon_min': values[2],
                        'lon_max': values[3],
                        'center_lat': (values[0] + values[1]) / 2,
                        'center_lon': (values[2] + values[3]) / 2
                    }
        except:
            pass
        
        # Try as floats
        try:
            if len(decompressed) >= 16:
                values = struct.unpack('<4f', decompressed[:16])
                if all(-180 <= v <= 180 for v in values):
                    return {
                        'section_type': hex(section_type),
                        'lat_min': float(values[0]),
                        'lat_max': float(values[1]),
                        'lon_min': float(values[2]),
                        'lon_max': float(values[3]),
                        'center_lat': (values[0] + values[1]) / 2,
                        'center_lon': (values[2] + values[3]) / 2
                    }
        except:
            pass
    
    return None

def extract_poi_data(blob_data):
    """Extract POI/business data from various sections."""
    sections = parse_all_vmp4_sections(blob_data)
    
    for section_type in [0x32, 0x28, 0x46, 0x50]:
        if section_type not in sections:
            continue
        
        raw_data = sections[section_type]
        decompressed = decompress_vmp4_section(raw_data)
        
        if not decompressed:
            continue
        
        try:
            text = decompressed.decode('utf-8', errors='ignore')
            strings = [s.strip() for s in text.split('\x00') if s.strip() and len(s.strip()) > 2]
            
            addresses = []
            phones = []
            names = []
            
            for s in strings:
                if any(c.isdigit() for c in s) and ('-' in s or '(' in s or ')' in s):
                    phones.append(s)
                elif any(word in s.lower() for word in ['st', 'ave', 'rd', 'blvd', 'street', 'road', 'drive', 'lane', 'way', 'court', 'plaza']):
                    addresses.append(s)
                elif s.replace(' ', '').replace('-', '').isalnum() and len(s) > 3:
                    names.append(s)
            
            if addresses or phones or names:
                return {
                    'section_type': hex(section_type),
                    'addresses': addresses[:10],
                    'phone_numbers': phones[:5],
                    'names': names[:20]
                }
        except:
            pass
    
    return None

def generate_html_report(repo: MapTilesRepository, output_file: str | Path) -> None:
    """Generate interactive HTML map report with correct coordinates and timestamps."""

    tiles_data = []
    section_type_stats = defaultdict(int)
    compression_stats = {'compressed': 0, 'uncompressed': 0}
    
    for row in repo.iterate_tiles():
        rowid, blob_data, size_field, key_a, key_b, key_c, key_d, tileset, insert_ts, access_ts = row
        
        # Check if this is a JPEG tile
        is_jpeg = blob_data[:3] == b'\xff\xd8\xff' if len(blob_data) >= 3 else False
        
        metadata = parse_vmp4_metadata(blob_data)
        
        if metadata:
            # VMP4 tile processing
            place_names = extract_place_names(blob_data)
            locale_info = extract_locale_info(blob_data)
            languages = extract_languages(blob_data)
            
            # Advanced parsing
            tile_metadata_adv = extract_tile_metadata_advanced(blob_data)
            geometry_data = extract_geometry_data(blob_data)
            coord_bounds = extract_coordinate_bounds(blob_data)
            poi_data = extract_poi_data(blob_data)
            
            # Extract zoom level from key_d
            zoom = None
            if key_d is not None:
                try:
                    key_d_bytes = struct.pack('<I', key_d & 0xFFFFFFFF)
                    zoom = key_d_bytes[1]
                except:
                    pass
            
            # Decode coordinates from tile keys
            coords = None
            if key_a is not None and key_b is not None and key_c is not None:
                coords = decode_apple_tile_key(key_a, key_b, key_c, key_d)
            
            # Format timestamps
            insert_time = datetime.fromtimestamp(insert_ts).strftime('%Y-%m-%d %H:%M:%S') if insert_ts else None
            access_time = datetime.fromtimestamp(access_ts).strftime('%Y-%m-%d %H:%M:%S') if access_ts else None
            
            tile_info = {
                'rowid': rowid,
                'format': 'VMP4',
                'zoom': zoom,
                'section_count': metadata['section_count'],
                'total_size': metadata['total_size'],
                'place_names': place_names,
                'locale_info': locale_info,
                'languages': list(languages) if isinstance(languages, set) else languages,
                'coords': coords,
                'insert_time': insert_time,
                'access_time': access_time,
                'tileset': tileset,
                'sections': [],
                # Advanced data
                'metadata_adv': tile_metadata_adv,
                'geometry': geometry_data,
                'bounds': coord_bounds,
                'poi': poi_data
            }
            
            for section in metadata['sections']:
                section_type_stats[section['type']] += 1
                if section['compressed']:
                    compression_stats['compressed'] += 1
                else:
                    compression_stats['uncompressed'] += 1
                
                tile_info['sections'].append({
                    'type': f"0x{section['type']:02X}",
                    'size': section['size'],
                    'compressed': section['compressed']
                })
            
            tiles_data.append(tile_info)
        
        elif is_jpeg:
            # JPEG tile processing
            # Format timestamps
            insert_time = datetime.fromtimestamp(insert_ts).strftime('%Y-%m-%d %H:%M:%S') if insert_ts else None
            access_time = datetime.fromtimestamp(access_ts).strftime('%Y-%m-%d %H:%M:%S') if access_ts else None
            
            # Try to decode coordinates from tile keys
            coords = None
            if key_a is not None and key_b is not None and key_c is not None:
                coords = decode_apple_tile_key(key_a, key_b, key_c, key_d)
            
            # Encode JPEG data as base64 for inline display
            import base64
            jpeg_base64 = base64.b64encode(blob_data).decode('utf-8')
            
            # Create JPEG tile info
            tile_info = {
                'rowid': rowid,
                'format': 'JPEG',
                'zoom': None,
                'section_count': 0,
                'total_size': len(blob_data),
                'place_names': [],
                'locale_info': {},
                'languages': [],
                'coords': coords,
                'insert_time': insert_time,
                'access_time': access_time,
                'tileset': tileset,
                'sections': [],
                'metadata_adv': {},
                'geometry': None,
                'bounds': None,
                'poi': None,
                'jpeg_data': jpeg_base64  # Store base64 encoded image
            }
            
            tiles_data.append(tile_info)
    
    # Section type descriptions
    section_descriptions = {
        0x01: "Header/Metadata", 0x0A: "Place Names", 0x0B: "Locale Info",
        0x0D: "Language/Localization", 0x14: "Geometry Data", 0x1E: "Coordinates",
        0x1F: "Additional Geometry", 0x20: "Map Layer Data", 0x26: "Label Data",
        0x33: "Text/Glyph Data", 0x34: "Street Names", 0x64: "Tile Image Data",
        0x65: "Tile Metadata", 0x67: "Large Tile Image", 0x70: "POI Data",
        0x83: "Attribution", 0x87: "Unknown (0x87)", 0x8D: "Rendering Parameters",
        0x8E: "Elevation Data", 0x90: "Building Data", 0x91: "Traffic Data",
        0x93: "3D Model Data", 0x95: "Transit Data", 0x97: "Environmental Data",
        0x98: "Road Network", 0x9A: "Vector Tile Data", 0x9B: "Raster Tile Data",
        0xA0: "Search Index", 0xA7: "Route Data", 0x3C: "Unknown (0x3C)"
    }
    
    # Generate HTML
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>iOS Map Tiles Analysis Report</title>

    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #f5f5f7;
            color: #1d1d1f;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .header h1 {{ font-size: 2.5rem; margin-bottom: 0.5rem; }}
        .header p {{ font-size: 1.1rem; opacity: 0.9; }}
        
        .container {{ max-width: 1400px; margin: 0 auto; padding: 2rem; }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        
        .stat-card {{
            background: white;
            padding: 1.5rem;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            transition: transform 0.2s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-4px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }}
        
        .stat-card h3 {{
            font-size: 0.875rem;
            text-transform: uppercase;
            color: #86868b;
            margin-bottom: 0.5rem;
            font-weight: 600;
        }}
        
        .stat-card .value {{
            font-size: 2.5rem;
            font-weight: 700;
            color: #667eea;
        }}
        
        .stat-card .label {{
            font-size: 0.875rem;
            color: #86868b;
            margin-top: 0.25rem;
        }}
        

        
        .section {{
            background: white;
            padding: 2rem;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            margin-bottom: 2rem;
        }}
        
        .section h2 {{
            font-size: 1.75rem;
            margin-bottom: 1.5rem;
            color: #1d1d1f;
        }}
        
        .tiles-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.875rem;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
        }}
        
        .tiles-table thead {{ background: #f5f5f7; }}
        
        .tiles-table th {{
            padding: 1rem;
            text-align: left;
            font-weight: 600;
            color: #1d1d1f;
            border-bottom: 2px solid #d2d2d7;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
        }}
        
        .tiles-table td {{
            padding: 0.875rem 1rem;
            border-bottom: 1px solid #e5e5ea;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
        }}
        
        .tiles-table tbody tr:hover {{ background: #f9f9f9; cursor: pointer; }}
        
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
        }}
        
        .badge-compressed {{ background: #d1f4e0; color: #0d894f; }}
        .badge-uncompressed {{ background: #ffeab6; color: #996800; }}
        
        .place-names {{ display: flex; flex-wrap: wrap; gap: 0.5rem; }}
        
        .place-tag {{
            background: #e8e8ed;
            padding: 0.25rem 0.75rem;
            border-radius: 8px;
            font-size: 0.75rem;
            color: #1d1d1f;
            white-space: nowrap;
        }}
        
        .section-types {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }}
        
        .section-type-card {{
            background: #f5f5f7;
            padding: 1rem;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        
        .section-type-card .type {{
            font-family: 'Courier New', monospace;
            font-weight: 700;
            color: #667eea;
            font-size: 1rem;
        }}
        
        .section-type-card .count {{
            font-size: 1.5rem;
            font-weight: 700;
            color: #1d1d1f;
            margin: 0.5rem 0;
        }}
        
        .section-type-card .desc {{
            font-size: 0.8rem;
            color: #86868b;
        }}
        
        .coords {{
            font-family: 'Courier New', monospace;
            font-size: 0.875rem;
            color: #667eea;
        }}
        
        .timestamp {{
            font-family: 'Courier New', monospace;
            font-size: 0.75rem;
            color: #86868b;
        }}
        
        .coord-link {{
            text-decoration: none;
            color: #667eea;
            transition: all 0.2s ease;
            display: inline-block;
        }}
        
        .coord-link:hover {{
            color: #5568d3;
            transform: scale(1.05);
        }}
        
        .coord-link:hover div {{
            text-decoration: underline;
        }}
        
        .filter-section {{
            margin-bottom: 1.5rem;
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
            align-items: center;
        }}
        
        .filter-section input {{
            padding: 0.75rem 1rem;
            border: 2px solid #e5e5ea;
            border-radius: 8px;
            font-size: 0.875rem;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            flex: 1;
            min-width: 200px;
        }}
        
        .filter-section input:focus {{
            outline: none;
            border-color: #667eea;
        }}
        
        .filter-section label {{
            font-size: 0.875rem;
            font-weight: 600;
            color: #1d1d1f;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
        }}
        
        .date-filter {{
            display: flex;
            gap: 0.5rem;
            align-items: center;
        }}
        
        .date-filter input[type="date"] {{
            padding: 0.5rem 0.75rem;
            border: 2px solid #e5e5ea;
            border-radius: 8px;
            font-size: 0.875rem;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
        }}
        
        .date-filter input[type="date"]:focus {{
            outline: none;
            border-color: #667eea;
        }}
        
        .tiles-table th input[type="date"] {{
            padding: 0.4rem 0.5rem;
            border: 1px solid #d2d2d7;
            border-radius: 6px;
            font-size: 0.75rem;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: white;
        }}
        
        .tiles-table th input[type="date"]:focus {{
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 2px rgba(102, 126, 234, 0.1);
        }}
        
        .note {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 1rem;
            margin-bottom: 1rem;
            border-radius: 4px;
        }}
        
        .note strong {{ color: #856404; }}
        
        #map {{
            height: 500px;
            width: 100%;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        
        .leaflet-popup-content {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }}
        
        .popup-title {{
            font-weight: 600;
            color: #667eea;
            margin-bottom: 0.5rem;
        }}
        
        .popup-places {{
            font-size: 0.875rem;
            color: #1d1d1f;
            margin-top: 0.5rem;
        }}
        
        /* Modal styles for JPEG viewer */
        .jpeg-modal {{
            display: none;
            position: fixed;
            z-index: 10000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.9);
            animation: fadeIn 0.3s;
        }}
        
        @keyframes fadeIn {{
            from {{ opacity: 0; }}
            to {{ opacity: 1; }}
        }}
        
        .jpeg-modal-content {{
            position: relative;
            margin: 2% auto;
            padding: 0;
            width: 90%;
            max-width: 1200px;
            max-height: 90vh;
            display: flex;
            flex-direction: column;
            align-items: center;
        }}
        
        .jpeg-modal-image {{
            max-width: 100%;
            max-height: 85vh;
            object-fit: contain;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
        }}
        
        .jpeg-modal-close {{
            position: absolute;
            top: -40px;
            right: 0;
            color: #f1f1f1;
            font-size: 40px;
            font-weight: bold;
            cursor: pointer;
            transition: color 0.3s;
            background: none;
            border: none;
            padding: 0;
            width: 40px;
            height: 40px;
            line-height: 40px;
            text-align: center;
        }}
        
        .jpeg-modal-close:hover,
        .jpeg-modal-close:focus {{
            color: #667eea;
        }}
        
        .jpeg-modal-info {{
            color: #f1f1f1;
            text-align: center;
            margin-top: 1rem;
            font-size: 0.875rem;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }}
        
        .jpeg-thumbnail {{
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        
        .jpeg-thumbnail:hover {{
            transform: scale(1.05);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4) !important;
        }}
    </style>
    
    <!-- Leaflet CSS -->
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
          integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY="
          crossorigin=""/>
    
    <!-- Leaflet JS -->
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"
            integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo="
            crossorigin=""></script>
</head>
<body>
    <!-- JPEG Image Modal -->
    <div id="jpegModal" class="jpeg-modal" onclick="closeJpegModal(event)">
        <div class="jpeg-modal-content">
            <button class="jpeg-modal-close" onclick="closeJpegModal(event)">&times;</button>
            <img id="jpegModalImage" class="jpeg-modal-image" src="" alt="JPEG Tile">
            <div class="jpeg-modal-info">
                <div id="jpegModalTitle" style="font-weight: 600; font-size: 1rem; margin-bottom: 0.5rem;"></div>
                <div id="jpegModalSize" style="color: #b0b0b0;"></div>
                <div style="margin-top: 1rem; color: #86868b;">Click anywhere outside the image to close</div>
            </div>
        </div>
    </div>

    <div class="header">
        <h1>iOS Map Tiles Analysis</h1>
        <p>VMP4 Format Database Extraction Report with Timestamps</p>
    </div>
    
    <div class="container">
        <div class="section">
            <h2>Tile Locations</h2>
            
            <div class="note" style="background: #d1ecf1; border-left-color: #0c5460; margin-top: 1rem;">
                <strong>Note:</strong> Plotted points are an effort to show, what can be, large approximations of tile data. The points are for illustrative purposes only and may not represent accurate locations. Tiles with broad coverage areas (Country or Continent level) or missing coordinate data are not plotted.
            </div>
            
            <div style="margin-top: 1.5rem;">
                <h3 style="margin-bottom: 1rem; font-size: 1.25rem;">Interactive Map</h3>
                <div id="map"></div>
            </div>
        </div>
        
        <div class="section">
            <h2>Tile Details</h2>
            
            <!-- Compact Summary Bar -->
            <div style="background:#f5f5f7;border-radius:8px;padding:12px 16px;margin-bottom:1.5rem;font-size:0.875rem;line-height:1.5;">
                <div style="display:flex;gap:32px;flex-wrap:wrap;">
                    <div>
                        <span style="color:#86868b;">Total Tiles:</span>
                        <strong style="margin-left:6px;">{len(tiles_data)}</strong>
                        <span style="font-size:0.75rem;color:#86868b;margin-left:4px;">({sum(1 for t in tiles_data if t.get('format') == 'VMP4')} VMP4, {sum(1 for t in tiles_data if t.get('format') == 'JPEG')} JPEG)</span>
                    </div>
                    <div>
                        <span style="color:#86868b;">Decoded Locations:</span>
                        <strong style="margin-left:6px;">{sum(1 for t in tiles_data if t['coords'])}</strong>
                        <span style="font-size:0.75rem;color:#86868b;margin-left:4px;">({sum(1 for t in tiles_data if t['coords'])*100//len(tiles_data) if tiles_data else 0}%)</span>
                    </div>
                    <div>
                        <span style="color:#86868b;">With Place Names:</span>
                        <strong style="margin-left:6px;">{sum(1 for t in tiles_data if t['place_names'])}</strong>
                    </div>
                    <div>
                        <span style="color:#86868b;">Vector Geometry Data:</span>
                        <strong style="margin-left:6px;">{sum(1 for t in tiles_data if t.get('geometry'))}</strong>
                    </div>
                    <div>
                        <span style="color:#86868b;">VMP4 Sections:</span>
                        <strong style="margin-left:6px;">{sum(len(t['sections']) for t in tiles_data)}</strong>
                        <span style="font-size:0.75rem;color:#86868b;margin-left:4px;">(compressed: {compression_stats['compressed']})</span>
                    </div>
                </div>
            </div>
            
            <div class="filter-section">
                <input type="text" id="searchInput" placeholder="Search by Row ID, place names...">
            </div>
            <div style="overflow-x: auto;">
                <table class="tiles-table" id="tilesTable">
                    <thead>
                        <tr>
                            <th style="width: 80px;">Row ID</th>
                            <th style="width: 60px;">Zoom</th>
                            <th style="width: 100px;">Size</th>
                            <th style="width: 150px;">Tile Info</th>
                            <th style="width: 180px;">
                                Insert Time
                                <div class="date-filter" style="margin-top: 0.5rem;">
                                    <input type="date" id="insertFrom" style="width: 100%; margin-bottom: 0.25rem;" placeholder="From">
                                    <input type="date" id="insertTo" style="width: 100%;" placeholder="To">
                                </div>
                            </th>
                            <th style="width: 180px;">
                                Access Time
                                <div class="date-filter" style="margin-top: 0.5rem;">
                                    <input type="date" id="accessFrom" style="width: 100%; margin-bottom: 0.25rem;" placeholder="From">
                                    <input type="date" id="accessTo" style="width: 100%;" placeholder="To">
                                </div>
                            </th>
                            <th>Place Names</th>
                        </tr>
                    </thead>
                    <tbody>
"""
    
    # Add table rows
    for tile in tiles_data:
        places_display = ""
        
        # Special handling for JPEG tiles - show the image
        if tile.get('format') == 'JPEG':
            # Use the stored base64 data
            jpeg_base64 = tile.get('jpeg_data', '')
            places_display = f"""
                <div style='text-align:center;'>
                    <img src='data:image/jpeg;base64,{jpeg_base64}' 
                         class='jpeg-thumbnail'
                         style='max-width:200px;max-height:150px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.1);'
                         alt='Tile {tile['rowid']} JPEG'
                         title='Click to view full size'
                         onclick='openJpegModal("data:image/jpeg;base64,{jpeg_base64}", "Tile {tile['rowid']} - JPEG Image", "{tile['total_size']:,} bytes")'>
                    <div style='font-size:0.65rem;color:#86868b;margin-top:0.5rem;'>Click to enlarge</div>
                </div>
            """
        elif tile['place_names']:
            # Show more place names - wrap them nicely
            places_html = ''.join([f"<span class='place-tag'>{html.escape(name)}</span>" for name in tile['place_names']])
            places_display = f"<div class='place-names'>{places_html}</div>"
            
            # Add POI data if available
            if tile.get('poi'):
                poi = tile['poi']
                poi_parts = []
                if poi.get('addresses'):
                    poi_parts.append(f"<div style='font-size:0.7rem;color:#667eea;margin-top:0.35rem;border-top:1px solid #e5e5e7;padding-top:0.25rem;'><strong>POI Addresses:</strong> {len(poi['addresses'])}</div>")
                if poi.get('phone_numbers'):
                    poi_parts.append(f"<div style='font-size:0.7rem;color:#667eea;margin-top:0.15rem;'><strong>Phone Numbers:</strong> {len(poi['phone_numbers'])}</div>")
                if poi.get('names') and len(poi['names']) > len(tile['place_names']):
                    extra_names = len(poi['names']) - len(tile['place_names'])
                    poi_parts.append(f"<div style='font-size:0.7rem;color:#667eea;margin-top:0.15rem;'><strong>Additional Names:</strong> {extra_names}</div>")
                if poi_parts:
                    places_display += ''.join(poi_parts)
        else:
            places_display = "<span style='color:#86868b;font-style:italic;'>No place names</span>"
        
        insert_time_display = tile['insert_time'] if tile['insert_time'] else "<span style='color:#86868b;'>-</span>"
        access_time_display = tile['access_time'] if tile['access_time'] else "<span style='color:#86868b;'>-</span>"
        
        # Add tile metadata if available
        if tile.get('metadata_adv'):
            metadata_adv = tile['metadata_adv']
            if metadata_adv.get('timestamp'):
                insert_time_display += f"<div style='font-size:0.65rem;color:#667eea;margin-top:0.35rem;border-top:1px solid #e5e5e7;padding-top:0.25rem;' title='From VMP4 metadata section'><strong>Tile Created:</strong><br>{metadata_adv['timestamp']}</div>"
            if metadata_adv.get('version'):
                insert_time_display += f"<div style='font-size:0.65rem;color:#86868b;margin-top:0.25rem;'><strong>Version:</strong> {metadata_adv['version']}</div>"
        
        # Format tile coordinate info
        tile_info_display = ""
        
        # JPEG tiles get special formatting
        if tile.get('format') == 'JPEG':
            if tile['coords'] and tile['coords'].get('lat') and tile['coords'].get('lon'):
                coords = tile['coords']
                lat_dir = 'N' if coords['lat'] >= 0 else 'S'
                lon_dir = 'E' if coords['lon'] >= 0 else 'W'
                lat_abs = abs(coords['lat'])
                lon_abs = abs(coords['lon'])
                google_maps_url = f"https://www.google.com/maps?q={coords['lat']},{coords['lon']}"
                
                tile_info_display = f"""
                    <div style='font-family:monospace;font-size:0.75rem;line-height:1.4;'>
                        <a href='{google_maps_url}' target='_blank' class='coord-link' title='Click to open in Google Maps' style='text-decoration:none;color:inherit;'>
                            <div style='font-weight:600;color:#1d1d1f;'>{lat_abs:.4f}°{lat_dir}</div>
                            <div style='font-weight:600;color:#1d1d1f;'>{lon_abs:.4f}°{lon_dir}</div>
                        </a>
                        <div style='color:#667eea;font-size:0.65rem;margin-top:0.35rem;border-top:1px solid #e5e5e7;padding-top:0.35rem;'>
                            <div><strong>Format:</strong> JPEG Image</div>
                            <div style='margin-top:0.15rem;'><strong>Size:</strong> {tile['total_size']:,} bytes</div>
                            <div style='margin-top:0.15rem;font-size:0.6rem;color:#86868b;'>Raster imagery tile</div>
                        </div>
                    </div>
                """
            else:
                tile_info_display = f"""
                    <div style='font-family:monospace;font-size:0.75rem;line-height:1.4;'>
                        <div style='color:#ff9500;font-weight:600;'>Location Unknown</div>
                        <div style='color:#667eea;font-size:0.65rem;margin-top:0.35rem;border-top:1px solid #e5e5e7;padding-top:0.35rem;'>
                            <div><strong>Format:</strong> JPEG Image</div>
                            <div style='margin-top:0.15rem;'><strong>Size:</strong> {tile['total_size']:,} bytes</div>
                            <div style='margin-top:0.15rem;font-size:0.6rem;color:#86868b;'>Raster imagery tile</div>
                        </div>
                    </div>
                """
        elif tile['coords']:
            coords = tile['coords']
            if 'lat' in coords and 'lon' in coords and coords['lat'] is not None and coords['lon'] is not None:
                # Show decoded coordinates with proper N/S and E/W indicators
                lat_dir = 'N' if coords['lat'] >= 0 else 'S'
                lon_dir = 'E' if coords['lon'] >= 0 else 'W'
                lat_abs = abs(coords['lat'])
                lon_abs = abs(coords['lon'])
                
                # Create Google Maps link
                google_maps_url = f"https://www.google.com/maps?q={coords['lat']},{coords['lon']}&z={coords['zoom']}"
                
                # Build additional info sections
                additional_sections = []
                
                # Add zoom level info
                zoom_info = f"<div style='color:#86868b;font-size:0.65rem;margin-top:0.35rem;border-top:1px solid #e5e5e7;padding-top:0.35rem;'>"
                zoom_info += f"<div><strong>Zoom Level:</strong> {coords['zoom']}</div>"
                zoom_info += f"<div style='margin-top:0.15rem;'><strong>Accuracy:</strong> {coords.get('accuracy', 'Estimated')}</div>"
                if coords['zoom'] <= 4:
                    zoom_info += f"<div style='color:#ff9500;margin-top:0.15rem;'><strong>Note:</strong> Not plotted (zoom ≤ 4)</div>"
                zoom_info += "</div>"
                additional_sections.append(zoom_info)
                
                # Add bounds info if available
                if tile.get('bounds'):
                    bounds = tile['bounds']
                    section_type = bounds.get('section_type', 'unknown')
                    bounds_info = f"<div style='color:#667eea;font-size:0.65rem;margin-top:0.35rem;border-top:1px solid #e5e5e7;padding-top:0.35rem;'>"
                    bounds_info += f"<div><strong>Precise Bounds:</strong></div>"
                    bounds_info += f"<div style='margin-top:0.15rem;'>Center: {bounds.get('center_lat', 0):.4f}°, {bounds.get('center_lon', 0):.4f}°</div>"
                    bounds_info += f"<div style='margin-top:0.15rem;font-size:0.6rem;color:#86868b;'>Source: VMP4 section {section_type}</div>"
                    bounds_info += "</div>"
                    additional_sections.append(bounds_info)
                
                # Add geometry complexity if available
                if tile.get('geometry'):
                    geom = tile['geometry']
                    geom_size = geom.get('decompressed_size', 0) / 1024  # KB
                    if geom_size > 0:
                        if geom_size < 1:
                            complexity = "Minimal"
                            complexity_color = "#86868b"
                        elif geom_size < 10:
                            complexity = "Moderate"
                            complexity_color = "#667eea"
                        elif geom_size < 50:
                            complexity = "High"
                            complexity_color = "#667eea"
                        else:
                            complexity = "Very High"
                            complexity_color = "#667eea"
                        
                        geom_info = f"<div style='color:{complexity_color};font-size:0.65rem;margin-top:0.35rem;border-top:1px solid #e5e5e7;padding-top:0.35rem;'>"
                        geom_info += f"<div><strong>Geometry Data:</strong></div>"
                        geom_info += f"<div style='margin-top:0.15rem;'>Complexity: {complexity}</div>"
                        geom_info += f"<div style='margin-top:0.15rem;'>Size: {geom_size:.1f} KB</div>"
                        geom_info += f"<div style='margin-top:0.15rem;font-size:0.6rem;color:#86868b;'>Encoded vector data (not parsed)</div>"
                        geom_info += "</div>"
                        additional_sections.append(geom_info)
                
                # Combine all sections
                additional_info = ''.join(additional_sections)
                
                tile_info_display = f"""
                    <div style='font-family:monospace;font-size:0.75rem;line-height:1.4;'>
                        <a href='{google_maps_url}' target='_blank' class='coord-link' title='Click to open in Google Maps' style='text-decoration:none;color:inherit;'>
                            <div style='font-weight:600;color:#1d1d1f;'>{lat_abs:.4f}°{lat_dir}</div>
                            <div style='font-weight:600;color:#1d1d1f;'>{lon_abs:.4f}°{lon_dir}</div>
                        </a>
                        {additional_info}
                    </div>
                """
            elif 'latitude' in coords and coords['latitude'] is None and coords['longitude'] is None:
                # Tiles with unknown coordinates - show note and encourage checking place names
                note = coords.get('notes', 'Coordinates cannot be decoded from keys')
                encoding_type = coords.get('encoding_type', 'Unknown')
                
                tile_info_display = f"""
                    <div style='font-family:monospace;font-size:0.75rem;line-height:1.4;'>
                        <div style='color:#ff9500;font-weight:600;'>Location Unknown</div>
                        <div style='color:#86868b;font-size:0.65rem;margin-top:0.35rem;border-top:1px solid #e5e5e7;padding-top:0.35rem;'>
                            <div><strong>Encoding:</strong> {encoding_type}</div>
                            <div style='margin-top:0.25rem;line-height:1.3;'>{html.escape(note)}</div>
                        </div>
                        <div style='color:#667eea;font-size:0.65rem;margin-top:0.35rem;border-top:1px solid #e5e5e7;padding-top:0.35rem;'>
                            <strong>Recommendation:</strong><br>
                            Check place names column for location details
                        </div>
                    </div>
                """
            else:
                # Fallback to old format
                tile_info_display = f"""
                    <div style='font-family:monospace;font-size:0.75rem;line-height:1.4;'>
                        <div style='color:#86868b;'>
                            <div><strong>Zoom:</strong> {coords.get('zoom', '-')}</div>
                            <div style='margin-top:0.15rem;'><strong>Tileset:</strong> {coords.get('tileset', '-')}</div>
                        </div>
                    </div>
                """
        else:
            tile_info_display = "<span style='color:#86868b;'>-</span>"
        
        compressed_count = sum(1 for s in tile['sections'] if s['compressed'])
        
        # Format zoom level display with descriptive labels
        zoom_display = ""
        if tile['zoom'] is not None:
            zoom_val = tile['zoom']
            if zoom_val == 120:
                zoom_display = f"<div><span style='font-weight:600;'>{zoom_val}</span></div><div style='font-size:0.7rem;color:#667eea;'>Indoor/Airport</div>"
            elif zoom_val == 0:
                zoom_display = f"<div><span style='font-weight:600;'>{zoom_val}</span></div><div style='font-size:0.7rem;color:#86868b;'>World View</div>"
            elif 1 <= zoom_val <= 3:
                zoom_display = f"<div><span style='font-weight:600;'>{zoom_val}</span></div><div style='font-size:0.7rem;color:#86868b;'>Continent</div>"
            elif 4 <= zoom_val <= 6:
                zoom_display = f"<div><span style='font-weight:600;'>{zoom_val}</span></div><div style='font-size:0.7rem;color:#86868b;'>Country</div>"
            elif 7 <= zoom_val <= 9:
                zoom_display = f"<div><span style='font-weight:600;'>{zoom_val}</span></div><div style='font-size:0.7rem;color:#86868b;'>Region</div>"
            elif 10 <= zoom_val <= 12:
                zoom_display = f"<div><span style='font-weight:600;'>{zoom_val}</span></div><div style='font-size:0.7rem;color:#86868b;'>City</div>"
            elif 13 <= zoom_val <= 15:
                zoom_display = f"<div><span style='font-weight:600;'>{zoom_val}</span></div><div style='font-size:0.7rem;color:#86868b;'>Town</div>"
            elif 16 <= zoom_val <= 18:
                zoom_display = f"<div><span style='font-weight:600;'>{zoom_val}</span></div><div style='font-size:0.7rem;color:#86868b;'>Street</div>"
            elif 19 <= zoom_val <= 20:
                zoom_display = f"<div><span style='font-weight:600;'>{zoom_val}</span></div><div style='font-size:0.7rem;color:#86868b;'>Building</div>"
            else:
                zoom_display = f"<div><span style='font-weight:600;'>{zoom_val}</span></div><div style='font-size:0.7rem;color:#86868b;'>Unknown</div>"
        else:
            zoom_display = "<span style='color:#86868b;'>-</span>"
        
        search_text = f"{tile['rowid']} {' '.join(tile['place_names'])} {' '.join(tile['languages'])} {tile['locale_info']} {tile['insert_time'] or ''} {tile['access_time'] or ''}"
        
        # Format size display based on tile type
        if tile.get('format') == 'JPEG':
            size_display = f"""
                {tile['total_size']:,}
                <br>
                <small style='color:#667eea;font-weight:600;'>JPEG Image</small>
            """
        else:
            size_display = f"""
                {tile['total_size']:,}
                <br>
                <small style='color:#86868b;'>{tile['section_count']} sections</small>
            """
        
        html_content += f"""
                        <tr data-rowid="{tile['rowid']}" data-search="{html.escape(search_text.lower())}" data-insert-time="{tile['insert_time'] or ''}" data-access-time="{tile['access_time'] or ''}">
                            <td><strong>#{tile['rowid']}</strong></td>
                            <td style='text-align:center;'>{zoom_display}</td>
                            <td>
                                {size_display}
                            </td>
                            <td>{tile_info_display}</td>
                            <td style='font-size:0.75rem;'>{insert_time_display}</td>
                            <td style='font-size:0.75rem;'>{access_time_display}</td>
                            <td>{places_display}</td>
                        </tr>
"""
    
    html_content += """
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <script>
        const tiles = """ + json.dumps(tiles_data) + """;
        
        // JPEG Modal functions
        function openJpegModal(imageSrc, title, size) {
            const modal = document.getElementById('jpegModal');
            const modalImg = document.getElementById('jpegModalImage');
            const modalTitle = document.getElementById('jpegModalTitle');
            const modalSize = document.getElementById('jpegModalSize');
            
            modal.style.display = 'block';
            modalImg.src = imageSrc;
            modalTitle.textContent = title;
            modalSize.textContent = 'Size: ' + size;
            
            // Prevent body scrolling when modal is open
            document.body.style.overflow = 'hidden';
        }
        
        function closeJpegModal(event) {
            // Only close if clicking the background or close button
            if (event.target.id === 'jpegModal' || event.target.className === 'jpeg-modal-close') {
                const modal = document.getElementById('jpegModal');
                modal.style.display = 'none';
                document.body.style.overflow = 'auto';
            }
        }
        
        // Close modal with Escape key
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                const modal = document.getElementById('jpegModal');
                if (modal.style.display === 'block') {
                    modal.style.display = 'none';
                    document.body.style.overflow = 'auto';
                }
            }
        });
        
        // Initialize the map
        // Filter: only include tiles with valid coordinates AND zoom > 4
        // (zoom <= 4 represents world/continent level - too broad to plot accurately)
        const tilesWithCoords = tiles.filter(t => 
            t.coords && 
            t.coords.lat && 
            t.coords.lon && 
            t.coords.zoom && 
            t.coords.zoom > 4
        );
        
        if (tilesWithCoords.length > 0) {
            // Calculate center point (average of all coordinates)
            const avgLat = tilesWithCoords.reduce((sum, t) => sum + t.coords.lat, 0) / tilesWithCoords.length;
            const avgLon = tilesWithCoords.reduce((sum, t) => sum + t.coords.lon, 0) / tilesWithCoords.length;
            
            // Initialize map centered on average location
            const map = L.map('map').setView([avgLat, avgLon], 4);
            
            // Add satellite imagery tiles (ESRI World Imagery)
            L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
                attribution: 'Tiles &copy; Esri &mdash; Source: Esri, i-cubed, USDA, USGS, AEX, GeoEye, Getmapping, Aerogrid, IGN, IGP, UPR-EGP, and the GIS User Community',
                maxZoom: 18
            }).addTo(map);
            
            // Add labels overlay for place names
            L.tileLayer('https://{s}.basemaps.cartocdn.com/light_only_labels/{z}/{x}/{y}{r}.png', {
                attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
                maxZoom: 19,
                subdomains: 'abcd'
            }).addTo(map);
            
            // Add rectangles (bounding boxes) and markers for each tile
            tilesWithCoords.forEach(tile => {
                const lat = tile.coords.lat;
                const lon = tile.coords.lon;
                const zoom = tile.coords.zoom;
                const accuracy = tile.coords.accuracy || 'Unknown';
                const bounds = tile.coords.bounds;
                
                // Create popup content
                let popupContent = `
                    <div class="popup-title">Tile #${tile.rowid}</div>
                    <div><strong>Center:</strong> ${Math.abs(lat).toFixed(4)}°${lat >= 0 ? 'N' : 'S'}, ${Math.abs(lon).toFixed(4)}°${lon >= 0 ? 'E' : 'W'}</div>
                    <div><strong>Zoom:</strong> ${zoom}</div>
                    <div><strong>Accuracy:</strong> ${accuracy}</div>
                `;
                
                // Add bounding box info if available
                if (bounds) {
                    const coverage_km = ((bounds.north - bounds.south) * 111).toFixed(1); // Rough km conversion
                    popupContent += `<div><strong>Coverage:</strong> ~${coverage_km}km × ${coverage_km}km</div>`;
                    popupContent += `<div style="font-size:0.75rem;color:#86868b;margin-top:0.25rem;">Bounds: ${bounds.north.toFixed(4)}°N to ${bounds.south.toFixed(4)}°S<br>${bounds.east.toFixed(4)}°E to ${bounds.west.toFixed(4)}°W</div>`;
                }
                
                // Add place names if available
                if (tile.place_names && tile.place_names.length > 0) {
                    const placeList = tile.place_names.slice(0, 5).join(', ');
                    const more = tile.place_names.length > 5 ? ` (+${tile.place_names.length - 5} more)` : '';
                    popupContent += `<div class="popup-places"><strong>Places:</strong> ${placeList}${more}</div>`;
                }
                
                // Add timestamps if available
                if (tile.insert_time) {
                    popupContent += `<div style="font-size:0.75rem;color:#86868b;margin-top:0.5rem;">Accessed: ${tile.insert_time}</div>`;
                }
                
                // Add Google Maps link
                const googleMapsUrl = `https://www.google.com/maps?q=${lat},${lon}&z=${zoom}`;
                popupContent += `<div style="margin-top:0.5rem;"><a href="${googleMapsUrl}" target="_blank" style="color:#667eea;text-decoration:none;">Open in Google Maps</a></div>`;
                
                // Add a point marker
                const marker = L.circleMarker([lat, lon], {
                    radius: 6,
                    fillColor: '#FF4444',    // Bright red
                    color: '#FFFFFF',        // White border for contrast on satellite
                    weight: 2,
                    fillOpacity: 0.9
                }).addTo(map);
                
                marker.bindPopup(popupContent);
                
                // NOTE: Geometry visualization disabled - see GEOMETRY_ANALYSIS_FINDINGS.md
                // Section 0x14 contains encoded vector data (not simple coordinates)
                // Requires proper binary format parsing to extract actual features
                // Current approach produced false coordinate patterns from random bytes
            });
            
            // Fit map bounds to show all markers
            if (tilesWithCoords.length > 1) {
                const bounds = L.latLngBounds(tilesWithCoords.map(t => [t.coords.lat, t.coords.lon]));
                map.fitBounds(bounds, { padding: [50, 50] });
            }
            
            // Add a legend for map markers
            const legend = L.control({ position: 'bottomright' });
            legend.onAdd = function(map) {
                const div = L.DomUtil.create('div', 'info legend');
                div.style.background = 'rgba(255, 255, 255, 0.95)';
                div.style.padding = '10px';
                div.style.borderRadius = '8px';
                div.style.boxShadow = '0 2px 8px rgba(0,0,0,0.15)';
                div.style.fontSize = '0.85rem';
                div.style.lineHeight = '1.5';
                
                div.innerHTML = `
                    <strong>Map Legend</strong><br>
                    <div style="margin-top:5px;">
                        <span style="display:inline-block;width:12px;height:12px;background:#FF4444;border:2px solid #FFF;border-radius:50%;margin-right:5px;"></span>
                        Tile Location<br>
                        <div style="font-size:0.75rem;color:#86868b;margin-top:5px;">
                            Click markers for details
                        </div>
                    </div>
                `;
                return div;
            };
            legend.addTo(map);
        } else {
            // Show message if no coordinates available
            document.getElementById('map').innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#86868b;font-style:italic;">No decoded coordinates available to display on map.</div>';
        }
        
        // Search and filter functionality
        const searchInput = document.getElementById('searchInput');
        const insertFromInput = document.getElementById('insertFrom');
        const insertToInput = document.getElementById('insertTo');
        const accessFromInput = document.getElementById('accessFrom');
        const accessToInput = document.getElementById('accessTo');
        const tableRows = document.querySelectorAll('#tilesTable tbody tr');
        
        function applyFilters() {
            const searchTerm = searchInput.value.toLowerCase();
            const insertFrom = insertFromInput.value ? new Date(insertFromInput.value) : null;
            const insertTo = insertToInput.value ? new Date(insertToInput.value + 'T23:59:59') : null;
            const accessFrom = accessFromInput.value ? new Date(accessFromInput.value) : null;
            const accessTo = accessToInput.value ? new Date(accessToInput.value + 'T23:59:59') : null;
            
            let visibleCount = 0;
            
            tableRows.forEach(row => {
                const searchText = row.dataset.search;
                let matchesSearch = searchText.includes(searchTerm);
                let matchesInsertDate = true;
                let matchesAccessDate = true;
                
                // Check Insert Time filter
                if (insertFrom || insertTo) {
                    const insertTime = row.dataset.insertTime;
                    
                    if (insertTime) {
                        const insertDate = new Date(insertTime);
                        if (insertFrom && insertDate < insertFrom) {
                            matchesInsertDate = false;
                        }
                        if (insertTo && insertDate > insertTo) {
                            matchesInsertDate = false;
                        }
                    } else {
                        // No insert timestamp, hide if insert filter is active
                        matchesInsertDate = false;
                    }
                }
                
                // Check Access Time filter
                if (accessFrom || accessTo) {
                    const accessTime = row.dataset.accessTime;
                    
                    if (accessTime) {
                        const accessDate = new Date(accessTime);
                        if (accessFrom && accessDate < accessFrom) {
                            matchesAccessDate = false;
                        }
                        if (accessTo && accessDate > accessTo) {
                            matchesAccessDate = false;
                        }
                    } else {
                        // No access timestamp, hide if access filter is active
                        matchesAccessDate = false;
                    }
                }
                
                // Show row only if all filters match
                if (matchesSearch && matchesInsertDate && matchesAccessDate) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                }
            });
            
            console.log(`Showing ${visibleCount} of ${tableRows.length} tiles`);
        }
        
        searchInput.addEventListener('input', applyFilters);
        insertFromInput.addEventListener('change', applyFilters);
        insertToInput.addEventListener('change', applyFilters);
        accessFromInput.addEventListener('change', applyFilters);
        accessToInput.addEventListener('change', applyFilters);
        
        // Add hover effect for rows
        tableRows.forEach(row => {
            row.style.cursor = 'default';
        });
        
        console.log(`Loaded ${tiles.length} tiles`);
        console.log(`Tiles with place names: ${tiles.filter(t => t.place_names && t.place_names.length > 0).length}`);
    </script>
</body>
</html>
"""
    
    output_path = Path(output_file)
    output_path.write_text(html_content, encoding='utf-8')

    stats_payload = {
        "total_tiles": len(tiles_data),
        "with_coordinates": sum(1 for t in tiles_data if t['coords']),
        "with_place_names": sum(1 for t in tiles_data if t['place_names']),
        "with_timestamps": sum(1 for t in tiles_data if t['insert_time']),
        "total_sections": sum(len(t['sections']) for t in tiles_data),
        "output_path": str(output_path.absolute()),
    }
    logger.info(
        "HTML report generated at %s (tiles=%d, coords=%d, names=%d, timestamps=%d, sections=%d)",
        stats_payload["output_path"],
        stats_payload["total_tiles"],
        stats_payload["with_coordinates"],
        stats_payload["with_place_names"],
        stats_payload["with_timestamps"],
        stats_payload["total_sections"],
        extra=stats_payload,
    )

def extract_section_readable_data(blob_data, section_type):
    """Extract human-readable data from a specific section type."""
    sections = parse_all_vmp4_sections(blob_data)
    
    if section_type not in sections:
        return None
    
    raw_data = sections[section_type]
    decompressed = decompress_vmp4_section(raw_data)
    
    if not decompressed:
        decompressed = raw_data  # Use raw if not compressed
    
    result = {
        'raw_size': len(raw_data),
        'decompressed_size': len(decompressed) if decompressed else 0,
        'hex_preview': raw_data[:64].hex() if len(raw_data) > 0 else '',
        'ascii_strings': []
    }
    
    # Extract ASCII strings (3+ printable chars)
    if decompressed and len(decompressed) > 0:
        current_string = ""
        for byte in decompressed:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= 3:
                    result['ascii_strings'].append(current_string)
                current_string = ""
        if len(current_string) >= 3:
            result['ascii_strings'].append(current_string)
    
    # Try to extract numeric data
    if decompressed and len(decompressed) >= 4:
        result['numeric_samples'] = []
        # Try reading as various numeric types
        for offset in range(0, min(len(decompressed) - 4, 64), 4):
            try:
                int_val = struct.unpack('<I', decompressed[offset:offset+4])[0]
                float_val = struct.unpack('<f', decompressed[offset:offset+4])[0]
                result['numeric_samples'].append({
                    'offset': offset,
                    'int': int_val,
                    'float': float_val
                })
            except:
                pass
    
    return result


def export_vmp4_to_text(repo: MapTilesRepository, output_dir: str | Path) -> None:
    """Export VMP4 tiles as detailed text files for manual review."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    vmp4_count = 0
    jpeg_count = 0
    skipped_count = 0

    logger.info(
        "Exporting VMP4 tiles to text files in %s",
        output_path.absolute(),
        extra={"output_dir": str(output_path.absolute())},
    )
    
    for row in repo.iterate_tiles():
        rowid, blob_data, size_field, key_a, key_b, key_c, key_d, tileset, insert_ts, access_ts = row
        
        # Check if VMP4
        metadata = parse_vmp4_metadata(blob_data)
        
        if metadata:
            vmp4_count += 1
            
            # Parse all data
            place_names = extract_place_names(blob_data)
            locale_info = extract_locale_info(blob_data)
            languages = extract_languages(blob_data)
            tile_metadata_adv = extract_tile_metadata_advanced(blob_data)
            geometry_data = extract_geometry_data(blob_data)
            coord_bounds = extract_coordinate_bounds(blob_data)
            poi_data = extract_poi_data(blob_data)
            
            # Decode coordinates
            coords = None
            if key_a is not None and key_b is not None and key_c is not None:
                coords = decode_apple_tile_key(key_a, key_b, key_c, key_d)
            
            # Extract zoom
            zoom = None
            if key_d is not None:
                try:
                    key_d_bytes = struct.pack('<I', key_d & 0xFFFFFFFF)
                    zoom = key_d_bytes[1]
                except:
                    pass
            
            # Create text file
            filename = output_path / f"tile_{rowid:04d}_vmp4.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("="*80 + "\n")
                f.write(f"VMP4 TILE #{rowid} - DETAILED ANALYSIS\n")
                f.write("="*80 + "\n\n")
                
                # Basic Info
                f.write("BASIC INFORMATION\n")
                f.write("-"*80 + "\n")
                f.write(f"Row ID:           {rowid}\n")
                f.write(f"File Size:        {len(blob_data):,} bytes\n")
                f.write(f"Section Count:    {metadata['section_count']}\n")
                f.write(f"Tileset:          {tileset or 'Unknown'}\n")
                if zoom is not None:
                    f.write(f"Zoom Level:       {zoom}\n")
                f.write("\n")
                
                # Timestamps
                f.write("TIMESTAMPS\n")
                f.write("-"*80 + "\n")
                if insert_ts:
                    f.write(f"Inserted:         {datetime.fromtimestamp(insert_ts).strftime('%Y-%m-%d %H:%M:%S')}\n")
                if access_ts:
                    f.write(f"Last Accessed:    {datetime.fromtimestamp(access_ts).strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("\n")
                
                # Tile Keys
                f.write("TILE KEYS (RAW)\n")
                f.write("-"*80 + "\n")
                f.write(f"key_a:            {key_a} (0x{key_a:08X})\n" if key_a else "key_a:            None\n")
                f.write(f"key_b:            {key_b} (0x{key_b:08X})\n" if key_b else "key_b:            None\n")
                f.write(f"key_c:            {key_c} (0x{key_c:08X})\n" if key_c else "key_c:            None\n")
                f.write(f"key_d:            {key_d} (0x{key_d:08X})\n" if key_d else "key_d:            None\n")
                f.write("\n")
                
                # Decoded Coordinates
                f.write("DECODED COORDINATES\n")
                f.write("-"*80 + "\n")
                if coords and coords.get('lat') and coords.get('lon'):
                    lat_dir = 'N' if coords['lat'] >= 0 else 'S'
                    lon_dir = 'E' if coords['lon'] >= 0 else 'W'
                    f.write(f"Latitude:         {abs(coords['lat']):.6f}°{lat_dir}\n")
                    f.write(f"Longitude:        {abs(coords['lon']):.6f}°{lon_dir}\n")
                    f.write(f"Decimal:          {coords['lat']:.6f}, {coords['lon']:.6f}\n")
                    f.write(f"Zoom Level:       {coords.get('zoom', 'Unknown')}\n")
                    f.write(f"Accuracy:         {coords.get('accuracy', 'Unknown')}\n")
                    f.write(f"Encoding Type:    {coords.get('encoding_type', 'Unknown')}\n")
                    if coords.get('notes'):
                        f.write(f"Notes:            {coords['notes']}\n")
                    f.write(f"\nGoogle Maps:      https://www.google.com/maps?q={coords['lat']},{coords['lon']}\n")
                else:
                    f.write("Unable to decode coordinates from tile keys\n")
                    if coords and coords.get('notes'):
                        f.write(f"Notes:            {coords['notes']}\n")
                f.write("\n")
                
                # Coordinate Bounds (if available)
                if coord_bounds:
                    f.write("PRECISE COORDINATE BOUNDS (from VMP4 section)\n")
                    f.write("-"*80 + "\n")
                    f.write(f"Center:           {coord_bounds.get('center_lat', 0):.6f}°, {coord_bounds.get('center_lon', 0):.6f}°\n")
                    f.write(f"Min Latitude:     {coord_bounds.get('min_lat', 0):.6f}°\n")
                    f.write(f"Max Latitude:     {coord_bounds.get('max_lat', 0):.6f}°\n")
                    f.write(f"Min Longitude:    {coord_bounds.get('min_lon', 0):.6f}°\n")
                    f.write(f"Max Longitude:    {coord_bounds.get('max_lon', 0):.6f}°\n")
                    f.write(f"Source Section:   {coord_bounds.get('section_type', 'Unknown')}\n")
                    f.write("\n")
                
                # Place Names
                f.write("PLACE NAMES\n")
                f.write("-"*80 + "\n")
                if place_names:
                    for i, name in enumerate(place_names, 1):
                        f.write(f"  {i:2d}. {name}\n")
                else:
                    f.write("No place names found\n")
                f.write("\n")
                
                # Languages
                f.write("LANGUAGES\n")
                f.write("-"*80 + "\n")
                if languages:
                    lang_list = list(languages) if isinstance(languages, set) else languages
                    f.write(", ".join(lang_list) + "\n")
                else:
                    f.write("No language information found\n")
                f.write("\n")
                
                # Locale Information
                f.write("LOCALE INFORMATION\n")
                f.write("-"*80 + "\n")
                if locale_info:
                    if isinstance(locale_info, dict):
                        for key, value in locale_info.items():
                            f.write(f"{key:20s}: {value}\n")
                    else:
                        f.write(f"{locale_info}\n")
                else:
                    f.write("No locale information found\n")
                f.write("\n")
                
                # POI Data
                if poi_data:
                    f.write("POINTS OF INTEREST (POI)\n")
                    f.write("-"*80 + "\n")
                    if poi_data.get('names'):
                        f.write(f"Names ({len(poi_data['names'])}):\n")
                        for i, name in enumerate(poi_data['names'][:20], 1):
                            f.write(f"  {i:2d}. {name}\n")
                        if len(poi_data['names']) > 20:
                            f.write(f"  ... and {len(poi_data['names']) - 20} more\n")
                    if poi_data.get('addresses'):
                        f.write(f"\nAddresses ({len(poi_data['addresses'])}):\n")
                        for i, addr in enumerate(poi_data['addresses'][:10], 1):
                            f.write(f"  {i:2d}. {addr}\n")
                        if len(poi_data['addresses']) > 10:
                            f.write(f"  ... and {len(poi_data['addresses']) - 10} more\n")
                    if poi_data.get('phone_numbers'):
                        f.write(f"\nPhone Numbers ({len(poi_data['phone_numbers'])}):\n")
                        for i, phone in enumerate(poi_data['phone_numbers'][:10], 1):
                            f.write(f"  {i:2d}. {phone}\n")
                        if len(poi_data['phone_numbers']) > 10:
                            f.write(f"  ... and {len(poi_data['phone_numbers']) - 10} more\n")
                    f.write("\n")
                
                # Advanced Metadata
                if tile_metadata_adv:
                    f.write("TILE METADATA (from VMP4)\n")
                    f.write("-"*80 + "\n")
                    if tile_metadata_adv.get('timestamp'):
                        f.write(f"Tile Created:     {tile_metadata_adv['timestamp']}\n")
                    if tile_metadata_adv.get('version'):
                        f.write(f"Version:          {tile_metadata_adv['version']}\n")
                    if tile_metadata_adv.get('build'):
                        f.write(f"Build:            {tile_metadata_adv['build']}\n")
                    f.write("\n")
                
                # Geometry Data
                if geometry_data:
                    f.write("GEOMETRY DATA\n")
                    f.write("-"*80 + "\n")
                    if geometry_data.get('compressed_size'):
                        f.write(f"Compressed Size:  {geometry_data['compressed_size']:,} bytes\n")
                    if geometry_data.get('decompressed_size'):
                        f.write(f"Decompressed:     {geometry_data['decompressed_size']:,} bytes\n")
                        geom_size_kb = geometry_data['decompressed_size'] / 1024
                        if geom_size_kb < 1:
                            complexity = "Minimal"
                        elif geom_size_kb < 10:
                            complexity = "Moderate"
                        elif geom_size_kb < 50:
                            complexity = "High"
                        else:
                            complexity = "Very High"
                        f.write(f"Complexity:       {complexity}\n")
                    f.write("Note: Geometry data contains encoded vector paths and shapes\n")
                    f.write("\n")
                
                # VMP4 Sections
                f.write("VMP4 SECTIONS\n")
                f.write("-"*80 + "\n")
                f.write(f"{'Type':<10s} {'Size':<12s} {'Compressed':<12s} {'Description':<40s}\n")
                f.write("-"*80 + "\n")
                
                section_descriptions = {
                    0x01: "Header/Metadata", 0x0A: "Place Names", 0x0B: "Locale Info",
                    0x0D: "Language/Localization", 0x14: "Geometry Data", 0x1E: "Coordinates",
                    0x1F: "Additional Geometry", 0x20: "Map Layer Data", 0x26: "Label Data",
                    0x33: "Text/Glyph Data", 0x34: "Street Names", 0x64: "Tile Image Data",
                    0x65: "Tile Metadata", 0x67: "Large Tile Image", 0x70: "POI Data",
                    0x83: "Attribution", 0x87: "Unknown (0x87)", 0x8D: "Rendering Parameters",
                    0x8E: "Elevation Data", 0x90: "Building Data", 0x91: "Traffic Data",
                    0x93: "3D Model Data", 0x95: "Transit Data", 0x97: "Environmental Data",
                    0x98: "Road Network", 0x9A: "Vector Tile Data", 0x9B: "Raster Tile Data",
                    0xA0: "Search Index", 0xA7: "Route Data", 0x3C: "Unknown (0x3C)"
                }
                
                for section in metadata['sections']:
                    sect_type = section['type']
                    sect_hex = f"0x{sect_type:02X}"
                    sect_size = f"{section['size']:,}"
                    sect_compressed = "Yes" if section['compressed'] else "No"
                    sect_desc = section_descriptions.get(sect_type, f"Unknown (0x{sect_type:02X})")
                    f.write(f"{sect_hex:<10s} {sect_size:<12s} {sect_compressed:<12s} {sect_desc:<40s}\n")
                
                f.write("\n")
                
                # Add detailed section data
                f.write("="*80 + "\n")
                f.write("DETAILED SECTION DATA\n")
                f.write("="*80 + "\n\n")
                
                for section in metadata['sections']:
                    sect_type = section['type']
                    sect_hex = f"0x{sect_type:02X}"
                    sect_desc = section_descriptions.get(sect_type, f"Unknown (0x{sect_type:02X})")
                    
                    f.write(f"[{sect_hex}] {sect_desc}\n")
                    f.write("-"*80 + "\n")
                    
                    # Extract readable data from this section
                    section_data = extract_section_readable_data(blob_data, sect_type)
                    
                    if section_data:
                        f.write(f"Raw Size:         {section_data['raw_size']:,} bytes\n")
                        f.write(f"Decompressed:     {section_data['decompressed_size']:,} bytes\n")
                        
                        # Show hex preview
                        if section_data['hex_preview']:
                            f.write(f"\nHex Preview (first 64 bytes):\n")
                            hex_str = section_data['hex_preview']
                            for i in range(0, len(hex_str), 32):
                                f.write(f"  {hex_str[i:i+32]}\n")
                        
                        # Show extracted strings
                        if section_data['ascii_strings']:
                            f.write(f"\nExtracted Text/Strings ({len(section_data['ascii_strings'])} found):\n")
                            for i, text in enumerate(section_data['ascii_strings'][:50], 1):
                                # Truncate very long strings
                                display_text = text[:100] + "..." if len(text) > 100 else text
                                f.write(f"  {i:2d}. {display_text}\n")
                            if len(section_data['ascii_strings']) > 50:
                                f.write(f"  ... and {len(section_data['ascii_strings']) - 50} more strings\n")
                        
                        # Show numeric samples for small sections
                        if section_data.get('numeric_samples') and len(section_data['numeric_samples']) <= 16:
                            f.write(f"\nNumeric Data Samples:\n")
                            f.write(f"  {'Offset':<8s} {'Int (dec)':<15s} {'Float':<15s}\n")
                            f.write(f"  {'-'*8} {'-'*15} {'-'*15}\n")
                            for sample in section_data['numeric_samples'][:16]:
                                offset = sample['offset']
                                int_val = sample['int']
                                float_val = sample['float']
                                f.write(f"  {offset:<8d} {int_val:<15d} {float_val:<15.6f}\n")
                        
                        f.write("\n")
                    else:
                        f.write("No data available\n\n")
                
                f.write("="*80 + "\n")
                f.write(f"End of Tile #{rowid} Analysis\n")
                f.write("="*80 + "\n")
            
            if vmp4_count % 50 == 0 and vmp4_count > 0:
                logger.info(
                    "Export progress: %d tiles written",
                    vmp4_count,
                    extra={"exported_tiles": vmp4_count},
                )
        
        elif blob_data[:3] == b'\xff\xd8\xff':
            jpeg_count += 1
        else:
            skipped_count += 1
    
    logger.info(
        "Export complete: %d VMP4 tiles, %d JPEG skipped, %d other skipped (output=%s)",
        vmp4_count,
        jpeg_count,
        skipped_count,
        output_path.absolute(),
        extra={
            "vmp4_tiles": vmp4_count,
            "jpeg_skipped": jpeg_count,
            "other_skipped": skipped_count,
            "output_dir": str(output_path.absolute()),
        },
    )
    

def main():
    """Main CLI entry point."""
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(
        description='Generate an interactive HTML map report from Apple Maps tile database',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  generate_map_report.py /path/to/MapTiles.sqlitedb
  generate_map_report.py /path/to/MapTiles.sqlitedb -o custom_report.html
  generate_map_report.py /path/to/MapTiles.sqlitedb --output /output/dir/report.html

The tool will:
  1. Read and decode Apple Maps tiles from the database
  2. Extract place names, coordinates, and metadata
  3. Generate an interactive HTML map with satellite imagery
  4. Display tile statistics and allow filtering by date/location

Current decoding coverage is not 100%: Please review the results and compare with provided Place Names for location accuracy.
Accuracy in test is ±0.1° to ±4° depending on tile type

Copyright (c) 2025 North Loop Consulting, LLC

        """
    )
    
    parser.add_argument(
        'database',
        help='Path to the MapTiles.sqlitedb database file'
    )
    
    parser.add_argument(
        '-o', '--output',
        dest='output_file',
        help='Output HTML file path (default: map_tiles_report.html in current directory)',
        default=None
    )
    
    parser.add_argument(
        '--export-text',
        dest='export_text',
        metavar='DIR',
        help='Export VMP4 tiles as detailed text files to specified directory',
        default=None
    )
    
    parser.add_argument(
        '-v', '--version',
        action='version',
        version='%(prog)s 2.0 - Apple Maps Tile Decoder'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show detailed decoding information'
    )
    
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s:%(name)s:%(message)s",
    )

    db_path = Path(args.database)
    repo = MapTilesRepository(db_path)

    try:
        repo.validate()
    except ValueError as exc:
        logger.error("%s", exc)
        return 1

    if args.export_text:
        logger.info("Text export mode: database=%s, output=%s", db_path, args.export_text)
        try:
            export_vmp4_to_text(repo, args.export_text)
            logger.info("Text export completed successfully")
            return 0
        except Exception as exc:  # pragma: no cover - defensive logging for CLI
            if args.verbose:
                logger.exception("Error exporting VMP4 tiles to text files")
            else:
                logger.error("Error exporting VMP4 tiles to text files: %s", exc)
            return 1

    if args.output_file:
        output_file = Path(args.output_file)
    else:
        output_file = Path.cwd() / 'map_tiles_report.html'

    output_file.parent.mkdir(parents=True, exist_ok=True)

    logger.info("Generating interactive map report from %s to %s", db_path, output_file)

    try:
        generate_html_report(repo, str(output_file))
        logger.info("Report saved to %s", output_file.absolute())
        return 0
    except Exception as exc:  # pragma: no cover - defensive logging for CLI
        if args.verbose:
            logger.exception("Error generating HTML report")
        else:
            logger.error("Error generating HTML report: %s", exc)
        return 1

if __name__ == '__main__':
    sys.exit(main())
