FROM python:3.11-slim

WORKDIR /

# Install dependencies
RUN apt-get update && apt-get install -y \
  exiftool \
  && apt-get clean

RUN groupadd --gid 1001 ctfuser && \
  useradd --uid 1001 --gid 1001 --system --comment "" -s /usr/bin/nologin ctfuser && \
  echo 'ctfuser ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

RUN mkdir -m 555 /app

COPY --chown=root:ctfuser --chmod=444 . /app/
WORKDIR /app

COPY *.txt /
RUN chmod 444 /*.txt

RUN pip3 install -r requirements.txt
RUN chmod 555 templates/ static/

USER ctfuser
ENV PYTHONUNBUFFERED=1

EXPOSE 1337
CMD ["python3", "app.py"]