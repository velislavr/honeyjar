FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY honeyjar ./honeyjar
COPY rules ./rules
COPY db ./db
RUN useradd -u 1000 app && mkdir -p /app/data/geoip && chown -R app /app/data
USER app
