"""
test_credenciales.py — Pruebas del verificador de credenciales por defecto.
Levanta un pequeño servidor HTTP local con autenticación básica; no usa red externa.
"""
import sys
import os
import base64
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from modules.credenciales import verificar_credenciales_por_defecto, es_servicio_web


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        auth = self.headers.get("Authorization")
        esperado = "Basic " + base64.b64encode(b"admin:admin").decode()
        if auth == esperado:
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        else:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="t"')
            self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def servidor_web():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    puerto = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "127.0.0.1", puerto
    srv.shutdown()


def test_detecta_admin_admin(servidor_web):
    ip, puerto = servidor_web
    r = verificar_credenciales_por_defecto(ip, puerto, "http")
    assert r["verificado"] is True
    assert r["vulnerable"] is True
    assert r["credencial"] == "admin/admin"


def test_no_vulnerable_con_otras_credenciales(servidor_web):
    ip, puerto = servidor_web
    r = verificar_credenciales_por_defecto(ip, puerto, "http",
                                           credenciales=[("x", "y"), ("a", "b")])
    assert r["verificado"] is True
    assert r["vulnerable"] is False
    assert r["credencial"] is None


def test_servicio_no_web_no_se_verifica():
    r = verificar_credenciales_por_defecto("127.0.0.1", 22, "ssh")
    assert r["verificado"] is False
    assert r["vulnerable"] is False


def test_servicio_que_no_responde():
    r = verificar_credenciales_por_defecto("127.0.0.1", 9, "http")
    assert r["verificado"] is False
    assert r["vulnerable"] is False


def test_es_servicio_web():
    assert es_servicio_web(80) is True
    assert es_servicio_web(8080) is True
    assert es_servicio_web(23, "telnet") is False
    assert es_servicio_web(5000, "http") is True
