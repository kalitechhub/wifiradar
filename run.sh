#!/bin/bash
PROJECT_DIR="${HOME}/Desktop/wifiradar"
if [ "$1" == "stop" ]; then
    sudo python3 "${PROJECT_DIR}/wifi_radar.py" stop
else
    sudo python3 "${PROJECT_DIR}/wifi_radar.py" start
fi
