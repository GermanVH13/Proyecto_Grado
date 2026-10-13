"""
test_risk_engine.py — Pruebas unitarias del motor de riesgo contextual.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.risk_engine import (
    clasificar_nivel,
    calcular_riesgo_servicio,
    calcular_riesgo_dispositivo,
)


def test_clasificar_nivel_critico():
    assert clasificar_nivel(9.5) == "Crítico"
    assert clasificar_nivel(9.0) == "Crítico"


def test_clasificar_nivel_alto():
    assert clasificar_nivel(8.9) == "Alto"
    assert clasificar_nivel(7.0) == "Alto"


def test_clasificar_nivel_medio():
    assert clasificar_nivel(6.9) == "Medio"
    assert clasificar_nivel(4.0) == "Medio"


def test_clasificar_nivel_bajo():
    assert clasificar_nivel(3.9) == "Bajo"
    assert clasificar_nivel(0) == "Bajo"


def test_telnet_sin_cves_es_medio():
    """Caso real detectado: Telnet sin CVEs debe seguir marcando riesgo."""
    resultado = calcular_riesgo_servicio(
        {"puerto": 23, "nombre_servicio": "telnet"}, []
    )
    assert resultado["nivel_riesgo"] == "Medio"
    assert resultado["protocolo_inseguro"] is True


def test_apache_con_cve_real_es_critico():
    """Caso real probado: CVE-2011-2688 (CVSS 7.5) en puerto 80 (http)."""
    resultado = calcular_riesgo_servicio(
        {"puerto": 80, "nombre_servicio": "http"},
        [{"cve_id": "CVE-2011-2688", "cvss_score": 7.5, "descripcion": "..."}],
    )
    assert resultado["nivel_riesgo"] == "Crítico"


def test_servicio_seguro_sin_cves_es_bajo():
    """Puerto no expuesto, protocolo no inseguro, sin CVEs → Bajo."""
    resultado = calcular_riesgo_servicio(
        {"puerto": 9999, "nombre_servicio": "servicio_desconocido"}, []
    )
    assert resultado["nivel_riesgo"] == "Bajo"


def test_riesgo_dispositivo_toma_el_maximo():
    """El riesgo del dispositivo debe ser el más alto entre sus servicios."""
    bajo = {"nivel_riesgo": "Bajo"}
    critico = {"nivel_riesgo": "Crítico"}
    medio = {"nivel_riesgo": "Medio"}
    assert calcular_riesgo_dispositivo([bajo, critico, medio]) == "Crítico"


def test_cvss_alto_en_puerto_no_expuesto_es_alto():
    """CVSS 7.0 sin puerto expuesto ni protocolo inseguro → Alto."""
    resultado = calcular_riesgo_servicio(
        {"puerto": 9999, "nombre_servicio": "otro"},
        [{"cve_id": "CVE-X", "cvss_score": 7.0, "descripcion": ""}],
    )
    assert resultado["nivel_riesgo"] == "Alto"


def test_cvss_critico_en_puerto_no_expuesto_es_critico():
    resultado = calcular_riesgo_servicio(
        {"puerto": 9999, "nombre_servicio": "otro"},
        [{"cve_id": "CVE-X", "cvss_score": 9.1, "descripcion": ""}],
    )
    assert resultado["nivel_riesgo"] == "Crítico"


def test_cvss_medio_en_puerto_expuesto_sube_a_alto():
    """CVSS 6.5 + 1.0 por puerto expuesto = 7.5 → Alto."""
    resultado = calcular_riesgo_servicio(
        {"puerto": 22, "nombre_servicio": "ssh"},
        [{"cve_id": "CVE-X", "cvss_score": 6.5, "descripcion": ""}],
    )
    assert resultado["nivel_riesgo"] == "Alto"


def test_cve_sin_cvss_se_ignora_en_el_maximo():
    resultado = calcular_riesgo_servicio(
        {"puerto": 9999, "nombre_servicio": "otro"},
        [{"cve_id": "CVE-X", "cvss_score": None, "descripcion": ""},
         {"cve_id": "CVE-Y", "cvss_score": 5.0, "descripcion": ""}],
    )
    assert resultado["cvss_max"] == 5.0 and resultado["nivel_riesgo"] == "Medio"


def test_riesgo_dispositivo_sin_servicios_es_bajo():
    assert calcular_riesgo_dispositivo([]) == "Bajo"


def test_credenciales_por_defecto_sube_a_alto():
    r = calcular_riesgo_servicio(
        {"puerto": 80, "nombre_servicio": "http"}, [], credenciales_por_defecto=True
    )
    assert r["nivel_riesgo"] in ("Alto", "Crítico")
    assert r["credenciales_por_defecto"] is True


def test_sin_credenciales_por_defecto_no_cambia():
    r = calcular_riesgo_servicio({"puerto": 9999, "nombre_servicio": "x"}, [])
    assert r["nivel_riesgo"] == "Bajo"
    assert r["credenciales_por_defecto"] is False
