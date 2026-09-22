FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies required for ML and Scapy packet sniffing
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    tcpdump \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Install CPU-only PyTorch first for fast builds
RUN pip install --no-cache-dir torch --extra-index-url https://download.pytorch.org/whl/cpu

RUN pip install --no-cache-dir -r requirements.txt

# Copy directories and ALL python scripts
COPY data/ /app/data/
COPY models/ /app/models/
COPY *.py /app/

# Launch the interactive menu on startup
CMD ["python", "menu.py"]