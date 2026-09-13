# Jagi-Sentinel

Sistema automatizado para el análisis de vulnerabilidades en redes IoT de pequeña escala, basado en herramientas de código abierto sobre Linux.

Jagi-Sentinel integra **Nmap** (descubrimiento de dispositivos y servicios) y la **API de NVD** (consulta de vulnerabilidades conocidas / CVE) en una única aplicación web local, orquestada con Python y Flask. Incluye un motor de riesgo contextual propio que prioriza los hallazgos, historial de análisis y generación de informes en PDF.

> Proyecto de grado — Programa de Ingeniería de Datos y Software, Universidad de San Buenaventura (Medellín).

## Autores

- Jhoan Vélez
- Alejandro Zuleta
- Germán Valencia
- Isaac Ocampo

## Problema que resuelve

Auditar una red IoT hoy implica usar varias herramientas por separado (Nmap, Wireshark, Nessus, consultas manuales a NVD) e interpretar sus resultados a mano — un proceso lento, propenso a errores y que exige conocimientos técnicos que muchas PYMES no tienen. Jagi-Sentinel automatiza todo ese flujo en un solo clic desde una interfaz web.

## Características principales

- Descubrimiento automático de dispositivos, puertos y servicios con Nmap.
- Normalizador propio que traduce productos/versiones detectados a identificadores CPE.
- Consulta automática de CVEs asociados en la API pública de NVD.
- Motor de riesgo contextual (CVSS + exposición del servicio + protocolo inseguro + tipo de dispositivo) con niveles Bajo / Medio / Alto / Crítico.
- Dashboard web con resumen gráfico de resultados.
- Historial de análisis almacenado localmente.
- Generación de informes en PDF con un clic.
- Todo el escaneo ocurre en el equipo local; solo el CPE (nunca IPs ni datos de red) sale a Internet, hacia la API de NVD.

## Stack técnico

| Componente | Tecnología |
|---|---|
| Backend | Python 3.10+, Flask, Flask-SQLAlchemy |
| Escaneo de red | Nmap (vía `python-nmap`) |
| Fuente de vulnerabilidades | API pública de NVD (`requests`) |
| Base de datos | SQLite |
| Frontend | HTML5, Bootstrap 5, Chart.js |
| Informes PDF | WeasyPrint |
| Config | `python-dotenv` |

## Estructura del proyecto

```
Jagi-Sentinel/
├── app.py                     # Punto de entrada de la aplicación Flask
├── requirements.txt           # Dependencias de Python
├── install.sh                 # Script de instalación automática
├── README.md
├── modules/
│   ├── network_manager.py     # Descubre interfaz, IP, gateway, red
│   ├── device_discovery.py    # Ejecuta Nmap y parsea el XML
│   ├── normalizer.py          # Convierte producto + versión a CPE
│   ├── vulnerability_lookup.py# Consulta la API de NVD
│   ├── risk_engine.py         # Motor de riesgo contextual
│   └── report_generator.py    # Genera el informe PDF
├── static/                    # CSS, JS, imágenes
├── templates/                 # Plantillas Flask + Jinja2
├── database/                  # jagi-sentinel.db (SQLite, se crea sola)
├── reports/                   # Informes PDF generados
├── logs/                      # Logs de ejecución
└── tests/                     # Pruebas unitarias
```

## Requisitos previos

- Un entorno Linux con acceso real a la red local (Nmap necesita ver la LAN de verdad):
  - Ubuntu nativo, **o**
  - WSL2 con *mirrored networking*, **o**
  - Una VM en modo *bridged*.
- Al menos 8 GB de RAM y 50 GB de espacio libre.

## Instalación

### Opción rápida — script automático

```bash
chmod +x install.sh
./install.sh
```

Esto actualiza el sistema, instala Nmap, Python y crea el entorno virtual con las dependencias ya instaladas.

### Opción manual

1. **Actualizar el sistema e instalar Nmap y Python**
   ```bash
   sudo apt update && sudo apt upgrade -y
   sudo apt install nmap python3 python3-pip python3-venv -y
   ```
   > En redes domésticas colombianas, si `apt` se cuelga, prueba el fix de `ForceIPv4` y cambia a un mirror global en vez de `co.archive.ubuntu.com`.

2. **Crear y activar el entorno virtual**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Instalar las dependencias de Python**
   ```bash
   pip install -r requirements.txt
   ```

## Uso

Ejecuta la aplicación **con el Python del entorno virtual**, no el del sistema — Nmap necesita permisos de root, pero si usas `sudo python3` en lugar del venv, no va a encontrar `python-nmap` instalado:

```bash
sudo venv/bin/python3 app.py
```

Luego abre el navegador en:

```
http://localhost:5000
```

Desde ahí puedes seleccionar la interfaz de red, iniciar un análisis, ver el progreso en tiempo real, consultar el dashboard de resultados y generar el informe en PDF.

## Notas de desarrollo

- Los escaneos deben correr con `sudo venv/bin/python3`, nunca con `sudo python3` a secas.
- Si usas WSL2, asegúrate de tener *mirrored networking* habilitado; si usas una VM, que esté en modo *bridged* — de lo contrario Nmap no vera la red real.

## Licencia

Por definir.
