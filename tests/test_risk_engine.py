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