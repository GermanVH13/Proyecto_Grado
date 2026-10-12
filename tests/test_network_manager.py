"""
test_network_manager.py — Pruebas del detector de red con la salida de `ip -j` simulada.
No dependen de la red ni del comando `ip` de la máquina donde corren.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import shutil
import pytest
from unittest.mock import patch

from modules import network_manager
from modules.network_manager import obtener_info_red, listar_interfaces_disponibles

RUTA_DEFECTO = [{"dst": "default", "gateway": "192.168.1.254", "dev": "wlp1s0", "prefsrc": "192.168.1.6"}]
DIRECCIONES = [{
    "ifname": "wlp1s0", "operstate": "UP",
    "addr_info": [
        {"family": "inet6", "local": "fe80::1", "prefixlen": 64},
        {"family": "inet", "local": "192.168.1.6", "prefixlen": 24},
    ],
}]
TODAS_LAS_INTERFACES = [
    {"ifname": "lo", "operstate": "UNKNOWN"},
    {"ifname": "wlp1s0", "operstate": "UP"},
    {"ifname": "enp2s0", "operstate": "DOWN"},
]


def simular(rutas=RUTA_DEFECTO, direcciones=DIRECCIONES, interfaces=TODAS_LAS_INTERFACES):
    def falso(comando):
        if comando[:3] == ["ip", "-j", "route"]:
            return rutas
        if comando[:4] == ["ip", "-j", "addr", "show"]:
            return direcciones
        if comando[:3] == ["ip", "-j", "addr"]:
            return interfaces
        raise AssertionError(f"Comando inesperado: {comando}")
    return patch.object(network_manager, "_ejecutar_comando_json", side_effect=falso)


def test_info_red_con_ruta_por_defecto():
    with simular():
        info = obtener_info_red()
    assert info == {"interfaz": "wlp1s0", "ip": "192.168.1.6", "prefijo": 24,
                    "gateway": "192.168.1.254", "red_cidr": "192.168.1.0/24"}


def test_info_red_con_interfaz_indicada():
    with simular():
        info = obtener_info_red("wlp1s0")
    assert info["interfaz"] == "wlp1s0" and info["red_cidr"] == "192.168.1.0/24"


def test_info_red_calcula_cidr_segun_el_prefijo():
    direcciones = [{"ifname": "eth0", "operstate": "UP",
                    "addr_info": [{"family": "inet", "local": "10.20.30.40", "prefixlen": 16}]}]
    with simular(direcciones=direcciones):
        info = obtener_info_red("eth0")
    assert info["red_cidr"] == "10.20.0.0/16"


def test_sin_ruta_por_defecto_lanza_error():
    with simular(rutas=[]):
        with pytest.raises(RuntimeError):
            obtener_info_red()


def test_interfaz_inexistente_lanza_error():
    with simular(direcciones=[]):
        with pytest.raises(RuntimeError):
            obtener_info_red("noexiste0")


def test_interfaz_sin_ipv4_lanza_error():
    direcciones = [{"ifname": "wlp1s0", "operstate": "UP",
                    "addr_info": [{"family": "inet6", "local": "fe80::1", "prefixlen": 64}]}]
    with simular(direcciones=direcciones):
        with pytest.raises(RuntimeError):
            obtener_info_red("wlp1s0")


def test_listar_interfaces_solo_activas_y_sin_loopback():
    with simular():
        assert listar_interfaces_disponibles() == ["wlp1s0"]


@pytest.mark.skipif(shutil.which("ip") is None, reason="el comando `ip` no está disponible")
def test_listar_interfaces_real_no_incluye_loopback():
    """Prueba con el sistema real (se omite si no existe el comando `ip`)."""
    interfaces = listar_interfaces_disponibles()
    assert isinstance(interfaces, list) and "lo" not in interfaces
