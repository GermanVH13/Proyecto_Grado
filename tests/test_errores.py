"""
test_errores.py — Mensajes claros para los errores de un análisis.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import subprocess
import nmap

from modules.errores import mensaje_claro, DETALLE_MAXIMO


def test_nmap_no_instalado():
    m = mensaje_claro(nmap.PortScannerError("nmap program was not found in path. PATH is : /usr/bin"))
    assert "Nmap no está instalado" in m and "sudo apt install nmap" in m


def test_nmap_sin_permisos_de_administrador():
    m = mensaje_claro(nmap.PortScannerError("TCP/IP fingerprinting (for OS scan) requires root privileges.\nQUITTING!"))
    assert "permisos de administrador" in m and "sudo" in m


def test_sin_ruta_por_defecto():
    m = mensaje_claro(RuntimeError("No se encontró una ruta por defecto."))
    assert "No hay una conexión de red activa" in m


def test_interfaz_sin_ipv4():
    assert "no tiene dirección IPv4" in mensaje_claro(RuntimeError("La interfaz 'eth0' no tiene IPv4 asignada."))


def test_interfaz_inexistente():
    assert "ya no existe" in mensaje_claro(RuntimeError("No se encontró la interfaz 'wlan9'."))


def test_comando_ip_ausente():
    m = mensaje_claro(FileNotFoundError(2, "No such file or directory", "ip"))
    assert "comando `ip`" in m


def test_comando_del_sistema_falla():
    assert "comando del sistema" in mensaje_claro(subprocess.CalledProcessError(1, ["ip"]))


def test_ruta_sin_gateway():
    assert "no tiene gateway" in mensaje_claro(KeyError("gateway"))


def test_error_inesperado_incluye_tipo_y_detalle():
    m = mensaje_claro(ValueError("algo raro"))
    assert "error inesperado" in m and "ValueError: algo raro" in m


def test_siempre_incluye_el_detalle_tecnico():
    assert "Detalle técnico" in mensaje_claro(RuntimeError("No se encontró una ruta por defecto."))


def test_detalle_muy_largo_se_recorta():
    m = mensaje_claro(ValueError("x" * 5000))
    assert len(m) < DETALLE_MAXIMO + 250 and "…" in m
