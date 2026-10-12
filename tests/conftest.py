"""
conftest.py — Preparación común de las pruebas.

Se define una base de datos y una carpeta de informes temporales ANTES de importar
app.py, para que las pruebas nunca toquen la base de datos ni reports/ reales.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

_TMP = tempfile.mkdtemp(prefix="jagi_tests_")
os.environ["JAGI_DATABASE_URI"] = f"sqlite:///{os.path.join(_TMP, 'prueba.db')}"
os.environ["JAGI_REPORTS_DIR"] = os.path.join(_TMP, "reports")

import pytest


@pytest.fixture
def jagi():
    """Módulo app con la base de datos temporal vacía y sin estados previos."""
    import app as modulo
    from modules.models import db
    with modulo.app.app_context():
        db.drop_all()
        db.create_all()
    modulo.ESTADOS.clear()
    return modulo


@pytest.fixture
def cliente(jagi):
    return jagi.app.test_client()
