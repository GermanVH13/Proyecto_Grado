"""
test_migracion.py — Una base creada con un esquema antiguo se actualiza sin perder datos.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import sqlite3
from flask import Flask
from sqlalchemy import inspect

from modules.models import db
from modules.migracion import agregar_columnas_faltantes


def crear_base_antigua(ruta):
    """Esquema anterior a las etapas 2.2 y 5: sin estado_nvd, total_cve, estado ni error."""
    con = sqlite3.connect(ruta)
    con.executescript("""
        CREATE TABLE analisis (id INTEGER PRIMARY KEY, fecha DATETIME, red_cidr VARCHAR(50),
                               riesgo_general VARCHAR(20));
        CREATE TABLE dispositivos (id INTEGER PRIMARY KEY, analisis_id INTEGER NOT NULL, ip VARCHAR(45) NOT NULL,
                                   mac VARCHAR(20), fabricante VARCHAR(100), sistema_operativo VARCHAR(150),
                                   nivel_riesgo VARCHAR(20));
        CREATE TABLE servicios (id INTEGER PRIMARY KEY, dispositivo_id INTEGER NOT NULL, puerto INTEGER NOT NULL,
                                protocolo VARCHAR(10), nombre_servicio VARCHAR(100), producto VARCHAR(150),
                                version VARCHAR(50), cpe VARCHAR(255), cvss_max FLOAT, nivel_riesgo VARCHAR(20));
        CREATE TABLE vulnerabilidades (id INTEGER PRIMARY KEY, servicio_id INTEGER NOT NULL,
                                       cve_id VARCHAR(30) NOT NULL, cvss_score FLOAT, descripcion TEXT);
        INSERT INTO analisis (id, red_cidr, riesgo_general) VALUES (1, '192.168.1.0/24', 'Alto');
        INSERT INTO dispositivos (id, analisis_id, ip) VALUES (1, 1, '192.168.1.9');
        INSERT INTO servicios (id, dispositivo_id, puerto, cvss_max) VALUES (1, 1, 80, 7.5);
    """)
    con.commit()
    con.close()


def app_sobre(ruta):
    app = Flask("migracion_prueba")
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{ruta}"
    db.init_app(app)
    return app


def test_agrega_las_columnas_nuevas_y_conserva_los_datos(tmp_path):
    ruta = str(tmp_path / "antigua.db")
    crear_base_antigua(ruta)
    app = app_sobre(ruta)
    with app.app_context():
        agregadas = agregar_columnas_faltantes(db)
        assert {"analisis.estado", "analisis.error", "servicios.estado_nvd", "servicios.total_cve"} <= set(agregadas)
        columnas = {c["name"] for c in inspect(db.engine).get_columns("servicios")}
        assert {"estado_nvd", "total_cve"} <= columnas
    con = sqlite3.connect(ruta)
    assert con.execute("SELECT red_cidr, riesgo_general FROM analisis").fetchone() == ("192.168.1.0/24", "Alto")
    assert con.execute("SELECT puerto, cvss_max FROM servicios").fetchone() == (80, 7.5)
    con.close()


def test_es_idempotente(tmp_path):
    ruta = str(tmp_path / "antigua.db")
    crear_base_antigua(ruta)
    app = app_sobre(ruta)
    with app.app_context():
        assert agregar_columnas_faltantes(db)
        assert agregar_columnas_faltantes(db) == []


def test_base_nueva_no_necesita_cambios(tmp_path):
    app = app_sobre(str(tmp_path / "nueva.db"))
    with app.app_context():
        db.create_all()
        assert agregar_columnas_faltantes(db) == []
