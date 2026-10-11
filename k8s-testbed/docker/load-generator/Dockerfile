FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY locustfile.py .
EXPOSE 8089
# Run headless by default; override CMD to use web UI
CMD ["locust", "-f", "locustfile.py", \
     "--host", "http://payment-gateway:8080", \
     "--users", "50", "--spawn-rate", "5", \
     "--headless", "--run-time", "0"]
