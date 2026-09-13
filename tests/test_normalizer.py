"""
test_normalizer.py — Pruebas unitarias del normalizador de productos a CPE.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.normalizer import normalizar_a_cpe


def test_producto_conocido_nginx():
    resultado = normalizar_a_cpe("nginx", "1.18.0")
    assert resultado == "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"


def test_producto_conocido_apache():
    resultado = normalizar_a_cpe("Apache httpd", "2.4.52")
    assert resultado == "cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*"


def test_producto_conocido_mysql():
    resultado = normalizar_a_cpe("MySQL", "8.0.34")
    assert resultado == "cpe:2.3:a:mysql:mysql:8.0.34:*:*:*:*:*:*:*"


def test_producto_desconocido_usa_heuristica():
    resultado = normalizar_a_cpe("MiServicioRaro", "3.2")
    assert resultado == "cpe:2.3:a:miservicioraro:miservicioraro:3.2:*:*:*:*:*:*:*"


def test_sin_version_devuelve_none():
    resultado = normalizar_a_cpe("Linux telnetd", "")
    assert resultado is None


def test_sin_producto_devuelve_none():
    resultado = normalizar_a_cpe(None, "1.0")
    assert resultado is None