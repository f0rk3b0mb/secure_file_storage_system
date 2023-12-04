#!/bin/sh

# Start Nginx in the background
nginx -g "daemon off;" &

# Start your Flask app
python /app/main.py
