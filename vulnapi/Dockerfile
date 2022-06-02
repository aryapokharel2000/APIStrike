FROM python:3.10-slim

LABEL maintainer="APIStrike Research"
LABEL description="VulnAPI Testbed - deliberately misconfigured API for security research"

WORKDIR /app
ENV VULNAPI_HOST=0.0.0.0

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 5000

CMD ["python", "app.py"]
