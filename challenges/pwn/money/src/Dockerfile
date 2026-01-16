from ubuntu:22.04@sha256:4cb780d50443fc4463f1f9360c03ca46512e4fdd8fd97c5ce7e69c8758924575

arg DEBIAN_FRONTEND=noninteractive

run apt-get update -y && apt-get install -y software-properties-common && \
  add-apt-repository -y ppa:deadsnakes/ppa && \
  apt-get update -y

run apt install -y python3.11 python3-pip python3.11-dev socat gdb && \
  python3.11 -m pip install RestrictedPython

workdir /tmp

add ./money .
run python3.11 -m pip install .

workdir /app
add ./app/run.py .
add ./app/server.py .
add ./app/flag.txt .

run chmod 744 ./flag.txt
run chmod +x ./server.py ./run.py

run useradd -ms /bin/bash jail
user jail
env PYTHONUNBUFFERED=y

expose 5000

cmd socat tcp4-listen:5000,fork,reuseaddr exec:/app/server.py
