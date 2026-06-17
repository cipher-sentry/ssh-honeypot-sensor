FROM python:3.11-slim

WORKDIR /app

RUN adduser --disabled-password --gecos "" honeypot

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY config.py api_client.py logger.py sftp_server.py ssh_server.py honeypot.py ./
COPY entrypoint.sh ./
COPY config.yaml ./

RUN mkdir -p logs && chown honeypot:honeypot logs && chmod +x entrypoint.sh

EXPOSE 2222

CMD ["/bin/sh", "entrypoint.sh"]
