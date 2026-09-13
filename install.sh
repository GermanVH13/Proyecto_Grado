#!/bin/bash
echo "========================================"
echo " Jagi-Sentinel - Instalacion automatica"
echo "========================================"
echo "[1/6] Actualizando sistema..."
sudo apt update && sudo apt upgrade -y
echo "[2/6] Instalando Nmap..."
sudo apt install nmap -y
echo "[3/6] Instalando Python y pip..."
sudo apt install python3 python3-pip python3-venv -y
echo "[4/6] Creando entorno virtual..."
python3 -m venv venv
source venv/bin/activate
echo "[5/6] Instalando dependencias de Python..."
pip install -r requirements.txt
echo "[6/6] Verificando instalacion..."
nmap --version
python3 --version
echo "Instalacion completada. Ejecuta: python app.py"