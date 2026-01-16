FROM python:latest

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

# Generate 10 secret key files
RUN mkdir secrets
RUN for i in $(seq 0 9); do openssl rand -base64 1000 > "./secrets/secret_key$i"; done

EXPOSE 5000
CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0"]
