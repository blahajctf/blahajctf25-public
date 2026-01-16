FROM python:3.10-slim-bullseye

RUN apt-get update && apt-get install -y --no-install-recommends \
    socat python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -m 777 /app
WORKDIR /app

COPY /roblox.py /app/roblox.py
COPY --chmod=555 ./run.sh /app/run.sh

EXPOSE 20001
CMD ["socat", "TCP-LISTEN:20001,nodelay,reuseaddr,fork", "EXEC:\"/app/run.sh\""]
# docker build . -t roblox
# docker run -p 20001:20001 -d -t roblox:latest