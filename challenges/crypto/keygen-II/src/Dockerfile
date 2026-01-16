FROM python:3.11-slim

WORKDIR /app

# copy project
COPY . .

# install runtime deps
RUN pip install --no-cache-dir flask pycryptodome

EXPOSE 5000

ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

CMD ["flask", "run"]
