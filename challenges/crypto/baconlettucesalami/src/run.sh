#!/bin/bash

echo "Hi! This instance may take a while to load. (10-40seconds approx) Give it some time."
timeout -s KILL 10m /usr/bin/sage /app/server.py