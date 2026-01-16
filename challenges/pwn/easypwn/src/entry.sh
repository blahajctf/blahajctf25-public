#!/bin/bash
socat TCP-LISTEN:1337,nodelay,reuseaddr,fork EXEC:"timeout -s KILL 10m /srv/app/run"