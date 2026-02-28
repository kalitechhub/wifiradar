#!/usr/bin/env bash
# build_radar.sh — Build the React Radar dashboard into wifiradar/static/
#
# Prerequisites: Node.js 18+ and npm installed.
# Run from project root:
#   bash wifiradar/build_radar.sh
#
# After building, wifi_radar.py serves the dashboard at http://localhost:8080

set -euo pipefail
cd "$(dirname "$0")/.."

echo "📡 Installing dependencies..."
npm install

echo "📡 Building Radar dashboard..."
npx vite build --config vite.config.radar.ts

echo ""
echo "✅ Built to wifiradar/static/"
echo "   Start wifi_radar.py and open http://localhost:8080"
