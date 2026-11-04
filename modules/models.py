"""
models.py — Modelos de base de datos SQLAlchemy para Jagi-Sentinel.
Define las 4 tablas: Analisis, Dispositivo, Servicio, Vulnerabilidad.
"""
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

from modules.estados_nvd import etiqueta as etiqueta_estado_nvd

db = SQLAlchemy()


class Analisis(db.Model):
    __tablename__ = "analisis"

    id = db.Column(db.Integer, primary_key=True)
    fecha = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    red_cidr = db.Column(db.String(50))
    riesgo_general = db.Column(db.String(20))  # Bajo / Medio / Alto / Crítico
    estado = db.Column(db.String(20))          # en_curso / completado / fallido
    error = db.Column(db.Text)                 # motivo, si el análisis falló

    dispositivos = db.relationship(
        "Dispositivo", backref="analisis", cascade="all, delete-orphan"
    )

    def to_dict(self):
        return {
            "id": self.id,
            "fecha": self.fecha.strftime("%d/%m/%Y %H:%M"),
            "red_cidr": self.red_cidr,
            "riesgo_general": self.riesgo_general,
            "estado": self.estado,
            "error": self.error,
            "total_dispositivos": len(self.dispositivos),
        }


class Dispositivo(db.Model):
    __tablename__ = "dispositivos"

    id = db.Column(db.Integer, primary_key=True)
    analisis_id = db.Column(db.Integer, db.ForeignKey("analisis.id"), nullable=False)
    ip = db.Column(db.String(45), nullable=False)
    mac = db.Column(db.String(20))
    fabricante = db.Column(db.String(100))
    sistema_operativo = db.Column(db.String(150))
    nivel_riesgo = db.Column(db.String(20))

    servicios = db.relationship(
        "Servicio", backref="dispositivo", cascade="all, delete-orphan"
    )

    def to_dict(self):
        return {
            "id": self.id,
            "ip": self.ip,
            "mac": self.mac,
            "fabricante": self.fabricante,
            "sistema_operativo": self.sistema_operativo,
            "nivel_riesgo": self.nivel_riesgo,
            "servicios": [s.to_dict() for s in self.servicios],
        }


class Servicio(db.Model):
    __tablename__ = "servicios"

    id = db.Column(db.Integer, primary_key=True)
    dispositivo_id = db.Column(db.Integer, db.ForeignKey("dispositivos.id"), nullable=False)
    puerto = db.Column(db.Integer, nullable=False)
    protocolo = db.Column(db.String(10), default="tcp")
    nombre_servicio = db.Column(db.String(100))
    producto = db.Column(db.String(150))
    version = db.Column(db.String(50))
    cpe = db.Column(db.String(255))
    estado_nvd = db.Column(db.String(30))   # ver modules/estados_nvd.py
    total_cve = db.Column(db.Integer, default=0)  # CVE hallados (se guardan los 10 más graves)
    cvss_max = db.Column(db.Float, default=0)
    nivel_riesgo = db.Column(db.String(20))
    cred_defecto = db.Column(db.Boolean, default=False)   # acepta credenciales de fábrica
    cred_detalle = db.Column(db.String(100))              # pareja hallada, ej. "admin/admin"

    vulnerabilidades = db.relationship(
        "Vulnerabilidad", backref="servicio", cascade="all, delete-orphan"
    )

    @property
    def estado_nvd_texto(self):
        return etiqueta_estado_nvd(self.estado_nvd, self.total_cve or 0)

    @property
    def vulnerabilidades_ordenadas(self):
        """CVE guardados, del más grave al menos grave (sin CVSS al final)."""
        return sorted(self.vulnerabilidades, key=lambda v: v.cvss_score or 0, reverse=True)

    def to_dict(self):
        return {
            "id": self.id,
            "puerto": self.puerto,
            "protocolo": self.protocolo,
            "nombre_servicio": self.nombre_servicio,
            "producto": self.producto,
            "version": self.version,
            "estado_nvd": self.estado_nvd,
            "estado_nvd_texto": self.estado_nvd_texto,
            "total_cve": self.total_cve or 0,
            "cred_defecto": bool(self.cred_defecto),
            "cred_detalle": self.cred_detalle,
            "cvss_max": self.cvss_max,
            "nivel_riesgo": self.nivel_riesgo,
            "vulnerabilidades": [v.to_dict() for v in self.vulnerabilidades],
        }


class Vulnerabilidad(db.Model):
    __tablename__ = "vulnerabilidades"

    id = db.Column(db.Integer, primary_key=True)
    servicio_id = db.Column(db.Integer, db.ForeignKey("servicios.id"), nullable=False)
    cve_id = db.Column(db.String(30), nullable=False)
    cvss_score = db.Column(db.Float)
    descripcion = db.Column(db.Text)
    referencias = db.Column(db.Text)   # URLs de NVD, una por línea

    @property
    def referencias_lista(self):
        return [u for u in (self.referencias or "").splitlines() if u.strip()]

    def to_dict(self):
        return {
            "id": self.id,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "descripcion": self.descripcion,
            "referencias": self.referencias_lista,
        }