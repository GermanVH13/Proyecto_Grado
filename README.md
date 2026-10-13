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

- Descubrimiento automático de dispositivos, puertos y servicios con Nmap (`-sS -sV -O`).
- Identificación de cada servicio con un CPE 2.3: se usa el CPE de aplicación que entrega Nmap y, si no hay, una tabla de productos conocidos. **No se inventan nombres**: si no se puede determinar con certeza, el servicio queda «no verificado».
- Consulta automática de CVE en la API pública de NVD, con reintentos, caché por CPE y conexión por IPv4 primero.
- Cada servicio muestra **cómo quedó su verificación**, para no confundir «sin CVE» con «no se pudo revisar»:

  | Estado | Significado |
  |---|---|
  | N CVE encontrados | El NVD respondió y hay CVE para esa versión |
  | Sin CVE en NVD | El NVD respondió y no hay CVE |
  | No verificado: versión no detectada | Nmap no detectó la versión; no se consulta |
  | No verificado: producto sin CPE conocido | Hay versión, pero no se pudo determinar el CPE |
  | No verificado: NVD no respondió | Falló la consulta; el análisis continúa |

- Motor de riesgo contextual (CVSS + exposición del puerto + protocolo inseguro) con niveles Bajo / Medio / Alto / Crítico.
- Dashboard web con resumen del análisis, nivel de riesgo por dispositivo y lista desplegable de CVE (ID, CVSS y descripción) por servicio.
- Análisis fallidos con el motivo explicado y guardado (Nmap sin instalar, falta de `sudo`, sin red activa, etc.).
- Historial de análisis almacenado localmente.
- Informe en PDF y exportación a JSON.
- El escaneo ocurre en el equipo local; a Internet solo sale el CPE del servicio hacia la API de NVD (nunca IPs ni datos de la red). Ver «Limitaciones conocidas» para un matiz sobre las tipografías.

## Stack técnico

| Componente | Tecnología |
|---|---|
| Backend | Python 3.10+ (probado con 3.13 y 3.14), Flask, Flask-SQLAlchemy |
| Escaneo de red | Nmap (vía `python-nmap`) |
| Fuente de vulnerabilidades | API pública de NVD (`requests`) |
| Base de datos | SQLite |
| Frontend | Plantillas Jinja2, HTML5 y CSS propio |
| Informes PDF | WeasyPrint |
| Configuración | `python-dotenv` (archivo `.env`) |
| Pruebas | pytest |

## Estructura del proyecto

```
Jagi-Sentinel/
├── app.py                      # Aplicación Flask y flujo del análisis
├── banner.py                   # Banner de texto de la pantalla de progreso
├── requirements.txt            # Dependencias de Python
├── install.sh                  # Instalación automática
├── crear_estructura.sh         # Esqueleto inicial del proyecto (solo referencia)
├── .env.example                # Plantilla de configuración (copiar a .env)
├── README.md
├── modules/
│   ├── models.py               # Tablas: Analisis, Dispositivo, Servicio, Vulnerabilidad
│   ├── migracion.py            # Agrega columnas nuevas a bases locales antiguas
│   ├── network_manager.py      # Detecta interfaz, IP, gateway y red (CIDR)
│   ├── device_discovery.py     # Ejecuta Nmap, estructura resultados y lee sus CPE
│   ├── normalizer.py           # CPE 2.2 de Nmap -> CPE 2.3, tabla de productos
│   ├── vulnerability_lookup.py # Cliente de la API de NVD (reintentos, caché, IPv4)
│   ├── estados_nvd.py          # Estado de verificación de cada servicio
│   ├── risk_engine.py          # Motor de riesgo contextual
│   ├── errores.py              # Mensajes claros para los errores de un análisis
│   └── report_generator.py     # Informe PDF
├── static/                     # CSS, imágenes (dashboard.js está vacío por ahora)
├── templates/                  # Plantillas Flask + Jinja2
├── database/                   # jagi-sentinel.db (SQLite, se crea sola)
├── reports/                    # Informes PDF generados (no se versionan)
└── tests/                      # Pruebas automáticas (sin red ni Nmap reales)
```

## Requisitos previos

- Un entorno Linux con acceso real a la red local (Nmap necesita ver la LAN de verdad):
  - Ubuntu nativo, **o**
  - WSL2 con *mirrored networking*, **o**
  - Una VM en modo *bridged*.
- Nmap, Python 3 con `venv` y el comando `ip` (paquete `iproute2`). El script de instalación los instala.
- Al menos 8 GB de RAM y 50 GB de espacio libre.

## Instalación

### Opción rápida — script automático

```bash
chmod +x install.sh
./install.sh
```

Esto actualiza el sistema, instala Nmap, Python y `iproute2`, crea el entorno virtual con las dependencias y deja un `.env` de partida.

### Opción manual

1. **Actualizar el sistema e instalar Nmap y Python**
   ```bash
   sudo apt update && sudo apt upgrade -y
   sudo apt install nmap iproute2 python3 python3-pip python3-venv -y
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

4. **Crear el archivo de configuración**
   ```bash
   cp .env.example .env
   ```

## Configuración (`.env`)

El archivo `.env` **nunca se sube a Git** (está en `.gitignore`). Guarda ahí tus valores:

| Variable | Descripción | Por defecto |
|---|---|---|
| `NVD_API_KEY` | Clave gratuita del NVD (https://nvd.nist.gov/developers/request-an-api-key). Sin ella la app funciona, pero con un límite de consultas mucho menor | vacío |
| `NVD_TIMEOUT` | Segundos de espera por intento al consultar el NVD | `60` |
| `NVD_REINTENTOS` | Reintentos tras un fallo temporal | `2` |
| `NVD_IPV4` | `1`: conectar primero por IPv4 y, si falla, con el orden normal del sistema. `0`: usar siempre el orden del sistema | `1` |

> **¿Por qué IPv4 primero?** En algunas redes, IPv6 hacia el NVD no responde y Python espera minutos antes de pasar a IPv4. Con IPv4 primero, una consulta pasó de ~540 s a ~1 s.

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

## Pruebas

```bash
python -m pytest -q
```

Las pruebas usan Nmap y NVD simulados, una base de datos temporal y no necesitan red ni `sudo`. Cubren el normalizador, el cliente del NVD, el motor de riesgo, el informe PDF, las rutas de Flask y el flujo completo de un análisis.

## Notas de desarrollo

- Los escaneos deben correr con `sudo venv/bin/python3`, nunca con `sudo python3` a secas.
- Si usas WSL2, asegúrate de tener *mirrored networking* habilitado; si usas una VM, que esté en modo *bridged* — de lo contrario Nmap no verá la red real.
- Si tu base de datos local es de una versión anterior, la app agrega sola las columnas que falten al arrancar; no hace falta borrarla.
- Los informes generados en `reports/` no se versionan (pueden contener datos de tu red); solo se conserva `informe_prueba.pdf` como ejemplo.

## Limitaciones conocidas

- **Servicios sin versión:** si Nmap no detecta la versión de un servicio, no se puede verificar contra el NVD y se marca «no verificado». Su riesgo se calcula solo con el contexto (puerto y protocolo).
- **Tipo de dispositivo:** el motor de riesgo todavía no incluye el tipo de dispositivo como factor.
- **Nombres de producto en el NVD:** el CPE depende de lo que entregue Nmap o de la tabla de productos conocidos (`modules/normalizer.py`); un producto que ninguna de las dos reconozca queda «no verificado».
- **Disponibilidad del NVD:** si el NVD no responde, el servicio queda «no verificado» y el análisis continúa; los resultados pueden ser incompletos.
- **Tipografías:** la interfaz carga fuentes desde Google Fonts; sin Internet usa las del sistema. El navegador, no el escáner, hace esa petición.
- **Versiones del software:** los CPE con versiones tipo `7.4p1` (OpenSSH) pueden requerir ajustes para coincidir con el formato del NVD.

## Licencia

Por definir.
