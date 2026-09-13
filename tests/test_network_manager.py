"""
test_network_manager.py — Pruebas unitarias del detector de red.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import ipaddress
from modules.network_manager import obtener_info_red, listar_interfaces_disponibles


def test_obtener_info_red_estructura_correcta():
    """Verifica que la función real devuelva las claves esperadas."""
    info = obtener_info_red()
    claves_esperadas = {"interfaz", "ip", "prefijo", "gateway", "red_cidr"}
    assert claves_esperadas.issubset(info.keys())


def test_obtener_info_red_ip_valida():
    """Verifica que la IP devuelta sea una IPv4 válida."""
    info = obtener_info_red()
    ipaddress.ip_address(info["ip"])  # lanza excepción si no es válida


def test_obtener_info_red_cidr_coherente_con_ip():
    """Verifica que la IP detectada pertenezca al rango CIDR calculado."""
    info = obtener_info_red()
    red = ipaddress.ip_network(info["red_cidr"])
    ip = ipaddress.ip_address(info["ip"])
    assert ip in red


def test_listar_interfaces_no_incluye_loopback():
    """La interfaz 'lo' (loopback) nunca debe aparecer en la lista."""
    interfaces = listar_interfaces_disponibles()
    assert "lo" not in interfaces


def test_listar_interfaces_devuelve_lista():
    interfaces = listar_interfaces_disponibles()
    assert isinstance(interfaces, list)