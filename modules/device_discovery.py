"""
device_discovery.py — Ejecuta un escaneo con Nmap y estructura los resultados.
"""
import xml.etree.ElementTree as ET

import nmap


def extraer_cpes_nmap(xml_texto):
    """
    Lee el XML crudo de Nmap y devuelve {ip: {puerto: [cpe, ...]}} solo con CPE de
    aplicación ("cpe:/a:..."). Se hace aquí porque python-nmap guarda únicamente el
    ÚLTIMO <cpe> de cada servicio, que suele ser el del sistema operativo.
    """
    resultado = {}
    if not xml_texto:
        return resultado
    try:
        raiz = ET.fromstring(xml_texto)
    except ET.ParseError:
        return resultado
    for host in raiz.findall("host"):
        ip = None
        for direccion in host.findall("address"):
            if direccion.get("addrtype") in ("ipv4", "ipv6"):
                ip = direccion.get("addr")
                break
        if not ip:
            continue
        for puerto in host.findall("ports/port"):
            if puerto.get("protocol") != "tcp":
                continue
            cpes = [c.text.strip() for c in puerto.findall("service/cpe")
                    if c.text and c.text.strip().lower().startswith("cpe:/a:")]
            if cpes:
                resultado.setdefault(ip, {})[int(puerto.get("portid"))] = cpes
    return resultado


def escanear_red(red_cidr):
    escaner = nmap.PortScanner()
    escaner.scan(hosts=red_cidr, arguments="-sS -sV -O -T4 --host-timeout 180s --max-retries 2")
    cpes_por_host = extraer_cpes_nmap(escaner.get_nmap_last_output())
    dispositivos = []
    for ip in escaner.all_hosts():
        host_info = escaner[ip]
        dispositivo = {
            "ip": ip, "estado": host_info.state(),
            "mac": host_info["addresses"].get("mac", "Desconocida"),
            "fabricante": None, "sistema_operativo": None, "servicios": [],
        }
        vendor_info = host_info.get("vendor", {})
        mac = dispositivo["mac"]
        if mac in vendor_info:
            dispositivo["fabricante"] = vendor_info[mac]
        if "osmatch" in host_info and host_info["osmatch"]:
            dispositivo["sistema_operativo"] = host_info["osmatch"][0]["name"]
        if "tcp" in host_info:
            for puerto, datos_puerto in host_info["tcp"].items():
                dispositivo["servicios"].append({
                    "puerto": puerto, "protocolo": "tcp",
                    "estado": datos_puerto.get("state"),
                    "nombre_servicio": datos_puerto.get("name"),
                    "producto": datos_puerto.get("product"),
                    "version": datos_puerto.get("version"),
                    "cpes_nmap": cpes_por_host.get(ip, {}).get(puerto, []),
                })
        dispositivos.append(dispositivo)
    return dispositivos


if __name__ == "__main__":
    from network_manager import obtener_info_red
    info_red = obtener_info_red()
    print(f"Escaneando red: {info_red['red_cidr']} ...\n")
    for d in escanear_red(info_red["red_cidr"]):
        print(f"Dispositivo: {d['ip']} ({d['estado']})")
        for s in d["servicios"]:
            print(f"  Puerto {s['puerto']}/{s['protocolo']} - {s['nombre_servicio']}")