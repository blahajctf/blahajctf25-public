FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y python3 python3-pip socat && rm -rf /var/lib/apt/lists/*
RUN pip install --break-system-packages --no-cache-dir --upgrade pip \
  && pip install --break-system-packages --no-cache-dir flask  \
  && pip install --break-system-packages --no-cache-dir pycryptodome \
  && pip install --break-system-packages --no-cache-dir flask_wtf

RUN addgroup --gid 1001 nonroot && \
  adduser --uid 1001 --gid 1001 --disabled-password --gecos "" nonroot && \
  echo 'nonroot ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

COPY . /app 

USER 1001
EXPOSE 1337
CMD ["python3",  "/app/app.py"]
