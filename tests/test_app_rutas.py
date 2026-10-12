"""
test_app_rutas.py — Rutas de Flask con una base de datos temporal.
"""
import os
from unittest.mock import patch, MagicMock

from modules.models import db, Analisis, Dispositivo, Servicio, Vulnerabilidad
from modules.estados_nvd import CON_CVE


def sembrar_analisis(jagi):
    """Crea un análisis con un dispositivo, un servicio y un CVE. Devuelve el id."""
    with jagi.app.app_context():
        a = Analisis(red_cidr="192.168.1.0/24", riesgo_general="Crítico")
        db.session.add(a)
        db.session.commit()
        d = Dispositivo(analisis_id=a.id, ip="192.168.1.9", mac="AA:BB", sistema_operativo="Linux",
                        nivel_riesgo="Crítico")
        db.session.add(d)
        db.session.commit()
        s = Servicio(dispositivo_id=d.id, puerto=80, nombre_servicio="http", producto="Apache httpd",
                     version="2.4.49", estado_nvd=CON_CVE, total_cve=1, cvss_max=9.8,
                     nivel_riesgo="Crítico")
        db.session.add(s)
        db.session.commit()
        db.session.add(Vulnerabilidad(servicio_id=s.id, cve_id="CVE-2021-41773",
                                      cvss_score=9.8, descripcion="Path traversal"))
        db.session.commit()
        return a.id


def test_index_lista_las_interfaces(jagi, cliente):
    with patch.object(jagi, "listar_interfaces_disponibles", return_value=["wlp1s0"]):
        r = cliente.get("/")
    assert r.status_code == 200 and "wlp1s0" in r.get_data(as_text=True)


def test_historial_vacio_y_con_analisis(jagi, cliente):
    assert cliente.get("/historial").status_code == 200
    sembrar_analisis(jagi)
    r = cliente.get("/historial")
    assert r.status_code == 200 and "192.168.1.0/24" in r.get_data(as_text=True)


def test_dashboard_muestra_servicio_y_cve(jagi, cliente):
    id_ = sembrar_analisis(jagi)
    html = cliente.get(f"/dashboard/{id_}").get_data(as_text=True)
    assert "192.168.1.9" in html
    assert "CVE-2021-41773" in html
    assert "1 CVE encontrados" in html


def test_dashboard_inexistente_da_404(cliente):
    assert cliente.get("/dashboard/999").status_code == 404


def test_json_incluye_estado_y_cve(jagi, cliente):
    id_ = sembrar_analisis(jagi)
    datos = cliente.get(f"/dashboard/{id_}/json").get_json()
    servicio = datos["dispositivos"][0]["servicios"][0]
    assert servicio["estado_nvd"] == CON_CVE
    assert servicio["vulnerabilidades"][0]["cve_id"] == "CVE-2021-41773"


def test_pdf_se_descarga_y_se_guarda_en_la_carpeta_de_pruebas(jagi, cliente):
    id_ = sembrar_analisis(jagi)
    r = cliente.get(f"/dashboard/{id_}/pdf")
    assert r.status_code == 200 and r.data.startswith(b"%PDF-")
    assert os.path.isfile(os.path.join(jagi.REPORTS_DIR, f"informe_analisis_{id_}.pdf"))
    assert os.path.abspath(jagi.REPORTS_DIR) != os.path.join(jagi.BASE_DIR, "reports")


def test_pdf_inexistente_da_404(cliente):
    assert cliente.get("/dashboard/999/pdf").status_code == 404


def test_api_estado_desconocido(cliente):
    assert cliente.get("/api/estado/12345").get_json()["mensaje"] == "Desconocido"


def test_api_estado_conocido(jagi, cliente):
    jagi.ESTADOS[7] = {"mensaje": "Escaneando", "completado": False, "error": None}
    assert cliente.get("/api/estado/7").get_json()["mensaje"] == "Escaneando"


def test_pagina_de_progreso(cliente):
    assert cliente.get("/analisis/1").status_code == 200


def test_analizar_crea_el_analisis_y_lanza_el_hilo(jagi, cliente):
    with patch.object(jagi.threading, "Thread") as Hilo:
        r = cliente.post("/analizar", data={"interfaz": "wlp1s0"})
    assert r.status_code == 302 and "/analisis/" in r.headers["Location"]
    Hilo.return_value.start.assert_called_once()
    with jagi.app.app_context():
        assert Analisis.query.count() == 1
