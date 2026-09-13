"""
network_manager.py
Detecta la interfaz de red activa, su IP, máscara y gateway,
y calcula el rango de red en notación CIDR para que Nmap lo escanee.
"""

import subprocess
import json
import ipaddress


def _ejecutar_comando_json(comando):
    """Ejecuta un comando del sistema que devuelve JSON y lo parsea."""
    resultado = subprocess.run(comando, capture_output=True, text=True, check=True)
    return json.loads(resultado.stdout)


def listar_interfaces_disponibles():
    """Devuelve la lista de interfaces de red activas (estado UP)."""
    interfaces = _ejecutar_comando_json(["ip", "-j", "addr"])
    activas = []
    for iface in interfaces:
        nombre = iface["ifname"]
        estado = iface.get("operstate", "").upper()
        if nombre == "lo":
            continue
        if estado == "UP":
            activas.append(nombre)
    return activas


def obtener_info_red(interfaz=None):
    """Detecta IP, máscara, gateway y calcula el rango CIDR."""
    if interfaz is None:
        rutas = _ejecutar_comando_json(["ip", "-j", "route", "show", "default"])
        if not rutas:
            raise RuntimeError("No se encontró una ruta por defecto.")
        interfaz = rutas[0]["dev"]
        gateway = rutas[0]["gateway"]
    else:
        rutas = _ejecutar_comando_json(["ip", "-j", "route", "show", "default", "dev", interfaz])
        gateway = rutas[0]["gateway"] if rutas else None

    direcciones = _ejecutar_comando_json(["ip", "-j", "addr", "show", interfaz])
    if not direcciones:
        raise RuntimeError(f"No se encontró la interfaz '{interfaz}'.")

    ip_info = None
    for addr in direcciones[0].get("addr_info", []):
        if addr["family"] == "inet":
            ip_info = addr
            break
    if ip_info is None:
        raise RuntimeError(f"La interfaz '{interfaz}' no tiene IPv4 asignada.")

    ip = ip_info["local"]
    prefijo = ip_info["prefixlen"]
    red = ipaddress.ip_interface(f"{ip}/{prefijo}")

    return {
        "interfaz": interfaz, "ip": ip, "prefijo": prefijo,
        "gateway": gateway, "red_cidr": str(red.network),
    }


if __name__ == "__main__":
    print("Interfaces activas:", listar_interfaces_disponibles())
    info = obtener_info_red()
    for clave, valor in info.items():
        print(f"  {clave}: {valor}")