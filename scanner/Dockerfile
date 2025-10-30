FROM python:3.11-slim

# Metadatos
LABEL maintainer="NetAudit HomeStack"
LABEL description="Network Scanner for NetBox with nmap and SNMP support"

# Variables de entorno
ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    snmp \
    iputils-ping \
    dnsutils \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Crear directorio de trabajo
WORKDIR /app

# Copiar requirements
COPY requirements.txt .

# Instalar dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código de la aplicación
COPY . .

# Crear directorio para logs
RUN mkdir -p /app/logs

# Comando por defecto (se sobreescribe con ofelia)
CMD ["python", "scan.py"]
