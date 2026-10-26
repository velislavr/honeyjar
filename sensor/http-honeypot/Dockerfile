FROM python:3.12-slim
RUN useradd -u 1000 -m honeypot && mkdir -p /logs /data && chown honeypot /logs /data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py .
USER honeypot
CMD ["python", "-u", "honeypot.py"]
