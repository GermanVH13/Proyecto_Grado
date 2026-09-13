"""
test_models.py — Prueba que las tablas se crean e insertan correctamente.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from flask import Flask
from modules.models import db, Analisis, Dispositivo, Servicio, Vulnerabilidad


def crear_app_prueba():
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    db.init_app(app)
    return app


def test_crear_analisis_completo():
    app = crear_app_prueba()
    with app.app_context():
        db.create_all()

        analisis = Analisis(red_cidr="192.168.1.0/24", riesgo_general="Crítico")
        db.session.add(analisis)
        db.session.commit()

        dispositivo = Dispositivo(
            analisis_id=analisis.id, ip="192.168.1.46",
            sistema_operativo="Linux", nivel_riesgo="Crítico",
        )
        db.session.add(dispositivo)
        db.session.commit()

        servicio = Servicio(
            dispositivo_id=dispositivo.id, puerto=80,
            nombre_servicio="http", cvss_max=7.5, nivel_riesgo="Crítico",
        )
        db.session.add(servicio)
        db.session.commit()

        vulnerabilidad = Vulnerabilidad(
            servicio_id=servicio.id, cve_id="CVE-2011-2688", cvss_score=7.5,
        )
        db.session.add(vulnerabilidad)
        db.session.commit()

        assert Analisis.query.count() == 1
        assert Dispositivo.query.count() == 1
        assert Servicio.query.count() == 1
        assert Vulnerabilidad.query.count() == 1

        resultado = analisis.to_dict()
        assert resultado["riesgo_general"] == "Crítico"
        assert resultado["total_dispositivos"] == 1