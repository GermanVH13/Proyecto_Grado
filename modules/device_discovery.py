"""
device_discovery.py — Ejecuta un escaneo con Nmap y estructura los resultados.
"""
import nmap


def escanear_red(red_cidr):
    escaner = nmap.PortScanner()
    escaner.scan(hosts=red_cidr, arguments="-sS -sV -O")
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