"""
test_report_generator.py — Contenido del informe: estado NVD y lista de CVE.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.report_generator import construir_html, generar_reporte_pdf
from modules.models import Servicio, Vulnerabilidad


def dispositivo(servicios):
    return {"ip": "192.168.1.9", "sistema_operativo": "Linux", "nivel_riesgo": "Crítico",
            "servicios_evaluados": servicios}


SERVICIO_CON_CVE = {
    "puerto": 80, "nombre_servicio": "http", "cvss_max": 9.8, "nivel_riesgo": "Crítico",
    "estado_nvd_texto": "2 CVE encontrados", "total_cve": 2,
    "vulnerabilidades": [
        {"cve_id": "CVE-2021-41773", "cvss_score": 9.8, "descripcion": "Path traversal completo."},
        {"cve_id": "CVE-2000-0001", "cvss_score": None, "descripcion": ""},
    ],
}


def test_html_incluye_cve_cvss_y_descripcion_completa():
    html = construir_html([dispositivo([SERVICIO_CON_CVE])], "Crítico")
    assert "CVE-2021-41773" in html and "CVSS 9.8" in html
    assert "Path traversal completo." in html
    assert "CVSS N/D" in html and "Sin descripción." in html
    assert "2 CVE encontrados" in html


def test_html_muestra_estados_sin_lista_de_cve():
    servicios = [
        {"puerto": 22, "nombre_servicio": "ssh", "cvss_max": 0, "nivel_riesgo": "Bajo",
         "estado_nvd_texto": "No verificado: NVD no respondió"},
        {"puerto": 53, "nombre_servicio": "dns", "cvss_max": 0, "nivel_riesgo": "Bajo",
         "estado_nvd_texto": "Sin CVE en NVD"},
    ]
    html = construir_html([dispositivo(servicios)], "Bajo")
    assert "No verificado: NVD no respondió" in html
    assert 'class="no-verificado"' in html
    assert "Sin CVE en NVD" in html
    assert 'class="cves"' not in html.split("</style>")[1]


def test_html_avisa_cuando_se_muestran_solo_los_mas_graves():
    s = dict(SERVICIO_CON_CVE, total_cve=25)
    html = construir_html([dispositivo([s])], "Crítico")
    assert "Se muestran los 2 CVE más graves de 25 encontrados." in html


def test_html_escapa_texto_del_nvd():
    s = dict(SERVICIO_CON_CVE)
    s["vulnerabilidades"] = [{"cve_id": "CVE-1", "cvss_score": 5.0,
                              "descripcion": "<script>alert(1)</script> {llaves}"}]
    html = construir_html([dispositivo([s])], "Crítico")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html and "{llaves}" in html


def test_servicio_sin_campos_nuevos_sigue_funcionando():
    s = {"puerto": 23, "nombre_servicio": "telnet", "cvss_max": 0, "nivel_riesgo": "Medio"}
    html = construir_html([dispositivo([s])], "Medio")
    assert "telnet" in html


def test_genera_pdf_valido(tmp_path):
    ruta = generar_reporte_pdf([dispositivo([SERVICIO_CON_CVE])], "Crítico",
                               str(tmp_path / "informe.pdf"))
    with open(ruta, "rb") as f:
        assert f.read(5) == b"%PDF-"


def test_servicio_modelo_ordena_cve_de_mayor_a_menor():
    s = Servicio(puerto=80)
    s.vulnerabilidades = [
        Vulnerabilidad(cve_id="B", cvss_score=5.0),
        Vulnerabilidad(cve_id="C", cvss_score=None),
        Vulnerabilidad(cve_id="A", cvss_score=9.8),
    ]
    assert [v.cve_id for v in s.vulnerabilidades_ordenadas] == ["A", "B", "C"]
