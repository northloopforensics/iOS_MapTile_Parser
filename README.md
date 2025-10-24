***Map_Tile_Parser***

Usage

Generate Interactive Map Report-

**python3 MapTileParser.py /path/to/MapTiles.sqlitedb**

This creates map_tiles_report.html in your current directory with:

-Interactive satellite map showing decoded tile locations
-Searchable table of all tiles with timestamps
-Place names, coordinates, and metadata
-Date filtering to track when locations were accessed
-JPEGs or recovered tile images

Specify Output Location-

**python3 MapTileParser.py /path/to/MapTiles.sqlitedb -o /output/report.html**

Export Detailed Text Files

For manual review of raw tile data:

**python3 MapTileParser.py /path/to/MapTiles.sqlitedb --export-text ./text_output/**

This creates individual text files for each tile with:
-Decoded coordinates and accuracy estimates
-Complete place names and POI data
-All embedded timestamps
-Raw section data in readable format
-Traffic and environmental data (when present, but its pretty useless TBH)
