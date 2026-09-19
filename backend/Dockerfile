FROM python:3.12-slim

WORKDIR /code

# lxml derlemesi için sistem bağımlılıkları
RUN apt-get update && apt-get install -y --no-install-recommends gcc libxml2-dev libxslt-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Root olarak çalıştırma (Azure/kapsayıcı güvenliği)
RUN useradd -m elfsec && chown -R elfsec:elfsec /code
USER elfsec

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
