"""
normalizer.py — Obtiene el CPE 2.3 de un servicio para consultar el NVD.

Orden de preferencia:
  1. CPE de aplicación que Nmap ya entrega (formato 2.2, "cpe:/a:...") convertido a 2.3.
  2. Tabla curada MAPEO_PRODUCTOS (producto de Nmap -> fabricante/producto del NVD).
  3. Si no hay ninguno, devuelve None. No se inventan nombres: un CPE que el NVD
     no reconoce responde "0 resultados" y sería indistinguible de "sin vulnerabilidades".
"""
import re
from urllib.parse import unquote

MAPEO_PRODUCTOS = {
    "nginx": ("nginx", "nginx"),
    "apache httpd": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "mysql": ("mysql", "mysql"),
    "openssh": ("openbsd", "openssh"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "dnsmasq": ("thekelleys", "dnsmasq"),
}

_DOS_PUNTOS_SIN_ESCAPAR = re.compile(r"(?<!\\):")
_CARACTER_A_ESCAPAR = re.compile(r"([^a-z0-9_.\-])")
_VACIOS = ("", "*", "-")


def _componente_a_cpe23(texto):
    """Pasa un componente de CPE 2.2 a su forma en CPE 2.3 (decodifica % y escapa)."""
    texto = unquote(texto.replace("\\:", ":")).strip().lower()
    if texto in _VACIOS:
        return "*"
    return _CARACTER_A_ESCAPAR.sub(r"\\\1", texto)


def convertir_cpe22_a_cpe23(cpe22, version_servicio=None):
    """
    Convierte un CPE 2.2 de aplicación (p. ej. 'cpe:/a:miniupnp_project:miniupnpd:1.9')
    a CPE 2.3. Devuelve None si no es de aplicación, está mal formado o no se
    puede determinar la versión (sin versión el NVD devolvería CVE de todas las versiones).
    Si el CPE no trae versión pero Nmap sí detectó una para el servicio, se usa esa.
    """
    if not cpe22 or not isinstance(cpe22, str):
        return None
    cpe22 = cpe22.strip()
    if not cpe22.lower().startswith("cpe:/a:"):
        return None
    partes = _DOS_PUNTOS_SIN_ESCAPAR.split(cpe22[len("cpe:/"):])
    # partes: [tipo, fabricante, producto, version, update, edition, language]
    partes = partes + [""] * (7 - len(partes))
    campos = [_componente_a_cpe23(p) for p in partes[:7]]
    tipo, fabricante, producto, version, actualizacion, edicion, idioma = campos
    if fabricante == "*" or producto == "*":
        return None
    if version == "*" and version_servicio and version_servicio.strip():
        version = _componente_a_cpe23(version_servicio)
    if version == "*":
        return None
    return (f"cpe:2.3:{tipo}:{fabricante}:{producto}:{version}:{actualizacion}:"
            f"{edicion}:{idioma}:*:*:*:*")


def normalizar_a_cpe(producto, version, cpes_nmap=None):
    """
    Devuelve el CPE 2.3 del servicio o None si no se puede determinar con certeza.

    producto, version : valores que reporta Nmap para el servicio.
    cpes_nmap         : lista opcional de CPE (formato 2.2) que Nmap asoció al servicio.
    """
    for cpe22 in cpes_nmap or []:
        cpe23 = convertir_cpe22_a_cpe23(cpe22, version_servicio=version)
        if cpe23:
            return cpe23

    if not producto or not version or not version.strip():
        return None
    clave = producto.strip().lower()
    if clave in MAPEO_PRODUCTOS:
        fabricante, producto_cpe = MAPEO_PRODUCTOS[clave]
        return (f"cpe:2.3:a:{fabricante}:{producto_cpe}:"
                f"{_componente_a_cpe23(version)}:*:*:*:*:*:*:*")
    return None


if __name__ == "__main__":
    ejemplos = [
        ("nginx", "1.18.0", None), ("Apache httpd", "2.4.52", None),
        ("MiniUPnP", "1.9", ["cpe:/a:miniupnp_project:miniupnpd:1.9"]),
        ("lighttpd", "", ["cpe:/a:lighttpd:lighttpd"]),
        ("MiServicioRaro", "3.2", None), ("Linux telnetd", "", None),
    ]
    for producto, version, cpes in ejemplos:
        print(f"{producto!r} {version!r} {cpes} -> {normalizar_a_cpe(producto, version, cpes)}")
