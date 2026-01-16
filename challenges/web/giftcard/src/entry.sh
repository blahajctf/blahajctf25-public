#!/bin/sh
exec &>/dev/null
hypercorn app:asgi_app --bind "127.0.0.1:8080" --keyfile /app/key.pem --certfile /app/cert.pem &
sslh --listen 0.0.0.0:1337 --http 127.0.0.1:8081 --ssl 127.0.0.1:8443 &
haproxy -f haproxy.cfg
#hypercorn app:asgi_app --bind "0.0.0.0:8000" --keyfile /app/key.pem --certfile /app/cert.pem