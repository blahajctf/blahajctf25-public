FROM selenium/standalone-chrome:latest

USER root
RUN apt-get update && apt-get install -y python3 python3-pip
RUN pip install flask selenium

WORKDIR /app
COPY server.py .
COPY bot.py .
COPY flag.txt .

USER seluser
EXPOSE 5000

CMD ["python3", "server.py"]
