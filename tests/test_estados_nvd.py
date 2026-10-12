"""
test_estados_nvd.py — Estado de verificación de cada servicio contra el NVD.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.estados_nvd import (
    determinar_estado, etiqueta, CON_CVE, SIN_CVE,
    NO_VERIFICADO_VERSION, NO_VERIFICADO_CPE, NO_VERIFICADO_NVD,
)
from modules.models import Servicio

CPE = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
UNA_CVE = [{"cve_id": "CVE-1", "cvss_score": 5.0, "descripcion": ""}]


def test_con_cve():
    assert determinar_estado(CPE, "2.4.49", UNA_CVE) == CON_CVE


def test_sin_cve_cuando_se_consulto_y_no_hay():
    assert determinar_estado(CPE, "2.4.49", []) == SIN_CVE


def test_consulta_fallida_tiene_prioridad():
    assert determinar_estado(CPE, "2.4.49", [], consulta_fallida=True) == NO_VERIFICADO_NVD


def test_sin_version_ni_cpe():
    assert determinar_estado(None, None, []) == NO_VERIFICADO_VERSION
    assert determinar_estado(None, "  ", []) == NO_VERIFICADO_VERSION


def test_con_version_pero_sin_cpe():
    assert determinar_estado(None, "1.0", []) == NO_VERIFICADO_CPE


def test_etiquetas_en_texto():
    assert etiqueta(CON_CVE, 3) == "3 CVE encontrados"
    assert etiqueta(SIN_CVE) == "Sin CVE en NVD"
    assert etiqueta(NO_VERIFICADO_VERSION) == "No verificado: versión no detectada"
    assert etiqueta(NO_VERIFICADO_NVD) == "No verificado: NVD no respondió"
    assert etiqueta(None) == "—"


def test_servicio_to_dict_incluye_estado():
    s = Servicio(puerto=80, estado_nvd=CON_CVE, total_cve=2)
    d = s.to_dict()
    assert d["estado_nvd"] == CON_CVE
    assert d["estado_nvd_texto"] == "2 CVE encontrados"
    assert d["total_cve"] == 2
