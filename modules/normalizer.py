"""
normalizer.py — Convierte producto+versión de Nmap en una cadena CPE 2.3.
"""
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


def normalizar_a_cpe(producto, version):
    if not producto or not version:
        return None
    producto_normalizado = producto.strip().lower()
    if producto_normalizado in MAPEO_PRODUCTOS:
        fabricante, producto_cpe = MAPEO_PRODUCTOS[producto_normalizado]
    else:
        fabricante = producto_normalizado.replace(" ", "_")
        producto_cpe = producto_normalizado.replace(" ", "_")
    version_normalizada = version.strip()
    return f"cpe:2.3:a:{fabricante}:{producto_cpe}:{version_normalizada}:*:*:*:*:*:*:*"


if __name__ == "__main__":
    ejemplos = [
        ("nginx", "1.18.0"), ("Apache httpd", "2.4.52"),
        ("MySQL", "8.0.34"), ("Linux telnetd", ""),
    ]
    for producto, version in ejemplos:
        print(f"{producto!r} {version!r} -> {normalizar_a_cpe(producto, version)}")