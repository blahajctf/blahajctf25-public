#!/bin/bash
python3 app.py &
sleep 0.5
haproxy -f haproxy.cfg