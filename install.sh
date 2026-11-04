#!/bin/bash
echo "========================================"
echo " Jagi-Sentinel - Instalacion automatica"
echo "========================================"
echo "[1/7] Actualizando sistema..."
sudo apt update && sudo apt upgrade -y
echo "[2/7] Instalando Nmap e iproute2..."
sudo apt install nmap iproute2 -y
echo "[3/7] Instalando librerias del sistema para los informes PDF (WeasyPrint)..."
sudo apt install libpango-1.0-0 libpangoft2-1.0-0 -y
echo "[4/7] Instalando Python y pip..."
sudo apt install python3 python3-pip python3-venv -y
echo "[5/7] Creando entorno virtual..."
python3 -m venv venv
source venv/bin/activate
echo "[6/7] Instalando dependencias de Python..."
pip install -r requirements.txt
[ -f .env ] || cp .env.example .env
echo "[7/7] Verificando instalacion..."
nmap --version
python3 --version
echo "Instalacion completada. Edita .env (opcional: NVD_API_KEY) y ejecuta:"
echo "  sudo venv/bin/python3 app.py"
