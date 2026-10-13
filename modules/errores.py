"""
errores.py — Traduce las excepciones de un análisis a un mensaje claro para el usuario.
"""
import subprocess

DETALLE_MAXIMO = 300


def _detalle(exc):
    texto = f"{type(exc).__name__}: {exc}".strip()
    return texto if len(texto) <= DETALLE_MAXIMO else texto[:DETALLE_MAXIMO] + "…"


def mensaje_claro(exc):
    """Devuelve 'qué pasó y qué hacer' seguido del detalle técnico entre paréntesis."""
    texto = str(exc).lower()
    claro = None

    if "nmap program was not found" in texto:
        claro = "Nmap no está instalado o no se encuentra. Instálalo (sudo apt install nmap) e inténtalo de nuevo."
    elif "root privileges" in texto or "requires root" in texto:
        claro = "Nmap necesita permisos de administrador. Cierra la aplicación y ejecútala con sudo (sudo venv/bin/python app.py)."
    elif isinstance(exc, FileNotFoundError) and getattr(exc, "filename", None) == "ip":
        claro = "Falta el comando `ip` del sistema (paquete iproute2), necesario para detectar la red."
    elif isinstance(exc, subprocess.CalledProcessError):
        claro = "Un comando del sistema necesario para detectar la red falló."
    elif isinstance(exc, KeyError) and exc.args and exc.args[0] == "gateway":
        claro = "La ruta de red por defecto no tiene gateway (¿VPN o red sin router?). Conéctate a una red local e inténtalo de nuevo."
    elif isinstance(exc, RuntimeError) and "ruta por defecto" in texto:
        claro = "No hay una conexión de red activa (no existe ruta por defecto). Conéctate a una red e inténtalo de nuevo."
    elif isinstance(exc, RuntimeError) and "no tiene ipv4" in texto:
        claro = "La interfaz de red elegida no tiene dirección IPv4. Elige otra interfaz o revisa tu conexión."
    elif isinstance(exc, RuntimeError) and "no se encontró la interfaz" in texto:
        claro = "La interfaz de red elegida ya no existe. Vuelve a elegirla e inténtalo de nuevo."
    elif isinstance(exc, PermissionError):
        claro = "Permisos insuficientes para completar el análisis. Ejecuta la aplicación con sudo."
    elif type(exc).__name__ in ("OperationalError", "IntegrityError", "ProgrammingError"):
        claro = "Error al guardar los resultados en la base de datos local."

    if claro is None:
        claro = "El análisis se detuvo por un error inesperado."
    return f"{claro} (Detalle técnico: {_detalle(exc)})"
