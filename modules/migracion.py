"""
migracion.py — Agrega a la base de datos local las columnas que falten.

`db.create_all()` crea las tablas que no existen pero NO añade columnas nuevas a las que
ya existen. Cada vez que los modelos ganan una columna, una base creada antes fallaría con
"no such column". Esta función las agrega al arrancar, sin borrar ningún dato.
"""
from sqlalchemy import inspect, text


def agregar_columnas_faltantes(db):
    """Devuelve la lista de columnas agregadas, como 'tabla.columna'."""
    agregadas = []
    inspector = inspect(db.engine)
    for tabla in db.metadata.sorted_tables:
        if not inspector.has_table(tabla.name):
            continue
        existentes = {c["name"] for c in inspector.get_columns(tabla.name)}
        for columna in tabla.columns:
            if columna.name in existentes:
                continue
            tipo = columna.type.compile(dialect=db.engine.dialect)
            db.session.execute(text(f'ALTER TABLE "{tabla.name}" ADD COLUMN "{columna.name}" {tipo}'))
            agregadas.append(f"{tabla.name}.{columna.name}")
    db.session.commit()
    return agregadas
