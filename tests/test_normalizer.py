"""
test_normalizer.py — Pruebas unitarias del normalizador de productos a CPE
y de la extracción de CPE desde el XML de Nmap. No requieren red ni Nmap.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unittest.mock import patch

from modules.normalizer import normalizar_a_cpe, convertir_cpe22_a_cpe23
from modules import device_discovery
from modules.device_discovery import extraer_cpes_nmap, escanear_red


# ---------- Tabla curada ----------
def test_producto_conocido_nginx():
    resultado = normalizar_a_cpe("nginx", "1.18.0")
    assert resultado == "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"


def test_producto_conocido_apache():
    resultado = normalizar_a_cpe("Apache httpd", "2.4.52")
    assert resultado == "cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*"


def test_producto_conocido_mysql():
    resultado = normalizar_a_cpe("MySQL", "8.0.34")
    assert resultado == "cpe:2.3:a:mysql:mysql:8.0.34:*:*:*:*:*:*:*"


def test_producto_desconocido_no_se_inventa_cpe():
    assert normalizar_a_cpe("MiServicioRaro", "3.2") is None


def test_sin_version_devuelve_none():
    assert normalizar_a_cpe("Linux telnetd", "") is None
    assert normalizar_a_cpe("nginx", "   ") is None


def test_sin_producto_devuelve_none():
    assert normalizar_a_cpe(None, "1.0") is None


# ---------- Conversión CPE 2.2 -> 2.3 ----------
def test_conversion_miniupnp():
    assert convertir_cpe22_a_cpe23("cpe:/a:miniupnp_project:miniupnpd:1.9") == \
        "cpe:2.3:a:miniupnp_project:miniupnpd:1.9:*:*:*:*:*:*:*"


def test_conversion_conserva_actualizacion():
    assert convertir_cpe22_a_cpe23("cpe:/a:openbsd:openssh:7.4:p1") == \
        "cpe:2.3:a:openbsd:openssh:7.4:p1:*:*:*:*:*:*"


def test_conversion_ignora_cpe_de_sistema_operativo():
    assert convertir_cpe22_a_cpe23("cpe:/o:linux:linux_kernel:2.6") is None


def test_conversion_cpe_mal_formado():
    assert convertir_cpe22_a_cpe23(None) is None
    assert convertir_cpe22_a_cpe23("") is None
    assert convertir_cpe22_a_cpe23("basura") is None
    assert convertir_cpe22_a_cpe23("cpe:/a:soloproveedor") is None


def test_conversion_sin_version_devuelve_none():
    assert convertir_cpe22_a_cpe23("cpe:/a:lighttpd:lighttpd") is None


def test_conversion_sin_version_usa_la_del_servicio():
    assert convertir_cpe22_a_cpe23("cpe:/a:lighttpd:lighttpd", version_servicio="1.4.55") == \
        "cpe:2.3:a:lighttpd:lighttpd:1.4.55:*:*:*:*:*:*:*"


def test_conversion_escapa_caracteres_especiales():
    assert convertir_cpe22_a_cpe23("cpe:/a:vendor:prod%2fx:1.0") == \
        "cpe:2.3:a:vendor:prod\\/x:1.0:*:*:*:*:*:*:*"


# ---------- Prioridad del CPE de Nmap sobre la tabla ----------
def test_cpe_de_nmap_tiene_prioridad_sobre_tabla():
    resultado = normalizar_a_cpe("nginx", "1.18.0", ["cpe:/a:igor_sysoev:nginx:1.18.0"])
    assert resultado == "cpe:2.3:a:igor_sysoev:nginx:1.18.0:*:*:*:*:*:*:*"


def test_si_cpe_de_nmap_no_sirve_se_usa_la_tabla():
    resultado = normalizar_a_cpe("nginx", "1.18.0", ["cpe:/o:linux:linux_kernel"])
    assert resultado == "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"


def test_cpe_de_nmap_sin_producto_ni_version_en_nmap():
    resultado = normalizar_a_cpe(None, None, ["cpe:/a:miniupnp_project:miniupnpd:1.9"])
    assert resultado == "cpe:2.3:a:miniupnp_project:miniupnpd:1.9:*:*:*:*:*:*:*"


# ---------- Extracción desde el XML de Nmap ----------
XML_NMAP = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
    <ports>
      <port protocol="tcp" portid="5000">
        <state state="open"/>
        <service name="upnp" product="MiniUPnP" version="1.9">
          <cpe>cpe:/a:miniupnp_project:miniupnpd:1.9</cpe>
          <cpe>cpe:/o:redhat:enterprise_linux:6.10</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="23">
        <state state="open"/>
        <service name="telnet"><cpe>cpe:/o:linux:linux_kernel</cpe></service>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_extraer_cpes_solo_de_aplicacion():
    assert extraer_cpes_nmap(XML_NMAP) == {
        "192.168.1.1": {5000: ["cpe:/a:miniupnp_project:miniupnpd:1.9"]}
    }


def test_extraer_cpes_con_xml_invalido_o_vacio():
    assert extraer_cpes_nmap("esto no es xml") == {}
    assert extraer_cpes_nmap("") == {}
    assert extraer_cpes_nmap(None) == {}


# ---------- escanear_red con Nmap simulado ----------
class _HostFalso(dict):
    def state(self):
        return "up"


class _EscanerFalso:
    def scan(self, hosts, arguments):
        self.argumentos = arguments

    def get_nmap_last_output(self):
        return XML_NMAP

    def all_hosts(self):
        return ["192.168.1.1"]

    def __getitem__(self, ip):
        return _HostFalso({
            "addresses": {"ipv4": ip, "mac": "AA:BB:CC:DD:EE:FF"},
            "vendor": {},
            "tcp": {
                5000: {"state": "open", "name": "upnp", "product": "MiniUPnP", "version": "1.9"},
                23: {"state": "open", "name": "telnet", "product": "", "version": ""},
            },
        })


def test_escanear_red_adjunta_cpes_de_nmap_a_cada_servicio():
    with patch.object(device_discovery.nmap, "PortScanner", _EscanerFalso):
        dispositivos = escanear_red("192.168.1.0/24")
    servicios = {s["puerto"]: s for s in dispositivos[0]["servicios"]}
    assert servicios[5000]["cpes_nmap"] == ["cpe:/a:miniupnp_project:miniupnpd:1.9"]
    assert servicios[23]["cpes_nmap"] == []
    cpe = normalizar_a_cpe(servicios[5000]["producto"], servicios[5000]["version"],
                           servicios[5000]["cpes_nmap"])
    assert cpe == "cpe:2.3:a:miniupnp_project:miniupnpd:1.9:*:*:*:*:*:*:*"
