"""
credenciales.py — Verifica si un servicio web acepta credenciales por defecto.

Las credenciales por defecto (admin/admin, etc.) NO son un CVE: NVD no las reporta,
porque son una mala configuración y no una falla de una versión de software. Por eso
se verifican con un paso aparte: se intenta entrar con una lista corta de parejas de
fábrica usando autenticación HTTP básica. Si alguna funciona, el servicio es vulnerable.

Alcance actual: solo HTTP con autenticación básica. Telnet y FTP quedan como mejora futura.
"""
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Muchos dispositivos IoT usan HTTPS con certificado propio; se omite su verificación.
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

PUERTOS_WEB = {80, 443, 8080, 8443, 8000}
NOMBRES_WEB = ("http", "https")

CREDENCIALES_POR_DEFECTO = [
    ("admin", "admin"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "password"),
    ("admin", ""),
    ("root", "root"),
    ("root", "admin"),
    ("user", "user"),
]

TIEMPO_ESPERA = 5  # segundos por intento


def es_servicio_web(puerto, nombre_servicio=None):
    """True si el servicio parece un panel web (por puerto o por nombre de Nmap)."""
    if puerto in PUERTOS_WEB:
        return True
    nombre = (nombre_servicio or "").lower()
    return any(n in nombre for n in NOMBRES_WEB)


def verificar_credenciales_por_defecto(ip, puerto, nombre_servicio=None, credenciales=None):
    """
    Intenta iniciar sesión en un panel web con credenciales de fábrica.

    Devuelve un dict:
      - verificado: True si se pudo probar el servicio; False si no respondió.
      - vulnerable: True si alguna pareja fue aceptada.
      - credencial: "usuario/clave" encontrada, o None.

    Nunca lanza excepciones: ante cualquier error de red devuelve verificado=False,
    para no interrumpir el análisis.
    """
    if not es_servicio_web(puerto, nombre_servicio):
        return {"verificado": False, "vulnerable": False, "credencial": None}

    parejas = credenciales if credenciales is not None else CREDENCIALES_POR_DEFECTO
    esquema = "https" if puerto in (443, 8443) else "http"
    url = f"{esquema}://{ip}:{puerto}/"

    # Primero se confirma que el servicio responde y que exige autenticación.
    try:
        sin_auth = requests.get(url, timeout=TIEMPO_ESPERA, verify=False)
    except requests.RequestException:
        return {"verificado": False, "vulnerable": False, "credencial": None}

    # Si la página abre sin pedir credenciales, no hay panel que probar por esta vía.
    if sin_auth.status_code != 401:
        return {"verificado": True, "vulnerable": False, "credencial": None}

    for usuario, clave in parejas:
        try:
            r = requests.get(url, auth=(usuario, clave), timeout=TIEMPO_ESPERA, verify=False)
        except requests.RequestException:
            return {"verificado": False, "vulnerable": False, "credencial": None}
        if r.status_code == 200:
            return {"verificado": True, "vulnerable": True, "credencial": f"{usuario}/{clave}"}

    return {"verificado": True, "vulnerable": False, "credencial": None}
