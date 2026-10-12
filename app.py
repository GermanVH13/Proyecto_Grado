"""
app.py — Punto de entrada de la aplicación Flask de Jagi-Sentinel.
"""
import os
import threading
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file
from modules.models import db, Analisis, Dispositivo, Servicio, Vulnerabilidad
from modules.network_manager import listar_interfaces_disponibles, obtener_info_red
from modules.device_discovery import escanear_red
from modules.normalizer import normalizar_a_cpe
from modules.vulnerability_lookup import consultar_vulnerabilidades, NVDError
from modules.estados_nvd import determinar_estado
from modules.risk_engine import calcular_riesgo_servicio, calcular_riesgo_dispositivo
from modules.report_generator import generar_reporte_pdf
from banner import texto_banner_plano

app = Flask(__name__)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))  # NVD_API_KEY, NVD_TIMEOUT, NVD_REINTENTOS
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(BASE_DIR, 'database', 'jagi-sentinel.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

db.init_app(app)

with app.app_context():
    db.create_all()

# Diccionario en memoria para trackear el progreso de cada análisis en curso.
# Clave: id del análisis. Valor: {"mensaje": str, "completado": bool, "error": str|None}
ESTADOS = {}


def risk_slug(nivel):
    """Convierte un nivel de riesgo en español ('Crítico', 'Alto'...) en la
    clase CSS correspondiente (sin tildes) usada por los templates."""
    mapa = {"crítico": "critico", "alto": "alto", "medio": "medio", "bajo": "bajo"}
    return mapa.get((nivel or "bajo").strip().lower(), "bajo")


app.jinja_env.filters["risk_slug"] = risk_slug


@app.route("/")
def index():
    interfaces = listar_interfaces_disponibles()
    return render_template("index.html", interfaces=interfaces)


def ejecutar_analisis_en_segundo_plano(app, analisis_id, interfaz):
    """Corre el escaneo completo en un hilo aparte, actualizando ESTADOS."""
    with app.app_context():
        try:
            ESTADOS[analisis_id] = {"mensaje": "Detectando información de red...", "completado": False, "error": None}
            info_red = obtener_info_red(interfaz)

            ESTADOS[analisis_id]["mensaje"] = f"Escaneando red {info_red['red_cidr']} con Nmap (puede tardar varios minutos)..."
            dispositivos_nmap = escanear_red(info_red["red_cidr"])

            analisis = Analisis.query.get(analisis_id)
            analisis.red_cidr = info_red["red_cidr"]
            db.session.commit()

            riesgos_dispositivos = []
            total = len(dispositivos_nmap)

            for idx, d in enumerate(dispositivos_nmap, start=1):
                ESTADOS[analisis_id]["mensaje"] = f"Procesando dispositivo {idx}/{total}: {d['ip']}..."

                dispositivo = Dispositivo(
                    analisis_id=analisis.id,
                    ip=d["ip"],
                    mac=d["mac"],
                    fabricante=d.get("fabricante"),
                    sistema_operativo=d.get("sistema_operativo"),
                )
                db.session.add(dispositivo)
                db.session.commit()

                servicios_evaluados = []

                for s in d["servicios"]:
                    ESTADOS[analisis_id]["mensaje"] = (
                        f"Dispositivo {idx}/{total} ({d['ip']}): consultando NVD para puerto {s['puerto']}..."
                    )
                    cpe = normalizar_a_cpe(s.get("producto"), s.get("version"), s.get("cpes_nmap"))
                    vulnerabilidades = []
                    consulta_fallida = False
                    if cpe:
                        try:
                            vulnerabilidades = consultar_vulnerabilidades(cpe)
                        except NVDError:
                            consulta_fallida = True
                    estado_nvd = determinar_estado(
                        cpe, s.get("version"), vulnerabilidades, consulta_fallida
                    )

                    riesgo = calcular_riesgo_servicio(
                        {"puerto": s["puerto"], "nombre_servicio": s.get("nombre_servicio")},
                        vulnerabilidades,
                    )

                    servicio = Servicio(
                        dispositivo_id=dispositivo.id,
                        puerto=s["puerto"],
                        protocolo=s.get("protocolo", "tcp"),
                        nombre_servicio=s.get("nombre_servicio"),
                        producto=s.get("producto"),
                        version=s.get("version"),
                        cpe=cpe,
                        estado_nvd=estado_nvd,
                        total_cve=len(vulnerabilidades),
                        cvss_max=riesgo["cvss_max"],
                        nivel_riesgo=riesgo["nivel_riesgo"],
                    )
                    db.session.add(servicio)
                    db.session.commit()

                    # Se guardan los 10 CVE más graves (el CVSS máximo ya usa la lista completa).
                    mas_graves = sorted(vulnerabilidades,
                                        key=lambda v: v["cvss_score"] or 0, reverse=True)
                    for v in mas_graves[:10]:
                        vuln = Vulnerabilidad(
                            servicio_id=servicio.id,
                            cve_id=v["cve_id"],
                            cvss_score=v["cvss_score"],
                            descripcion=v.get("descripcion", ""),
                        )
                        db.session.add(vuln)

                    db.session.commit()
                    servicios_evaluados.append(riesgo)

                riesgo_dispositivo = calcular_riesgo_dispositivo(servicios_evaluados)
                dispositivo.nivel_riesgo = riesgo_dispositivo
                db.session.commit()
                riesgos_dispositivos.append(riesgo_dispositivo)

            riesgo_general = calcular_riesgo_dispositivo(
                [{"nivel_riesgo": r} for r in riesgos_dispositivos]
            )
            analisis.riesgo_general = riesgo_general
            db.session.commit()

            ESTADOS[analisis_id] = {"mensaje": "Análisis completado.", "completado": True, "error": None}

        except Exception as e:
            ESTADOS[analisis_id] = {"mensaje": "Ocurrió un error durante el análisis.", "completado": True, "error": str(e)}


@app.route("/analizar", methods=["POST"])
def analizar():
    interfaz = request.form["interfaz"]

    analisis = Analisis(red_cidr="")
    db.session.add(analisis)
    db.session.commit()

    ESTADOS[analisis.id] = {"mensaje": "Iniciando análisis...", "completado": False, "error": None}

    hilo = threading.Thread(
        target=ejecutar_analisis_en_segundo_plano,
        args=(app, analisis.id, interfaz),
        daemon=True,
    )
    hilo.start()

    return redirect(url_for("analisis_progreso", analisis_id=analisis.id))


@app.route("/analisis/<int:analisis_id>")
def analisis_progreso(analisis_id):
    return render_template(
        "analysis.html", analisis_id=analisis_id, banner=texto_banner_plano()
    )


@app.route("/api/estado/<int:analisis_id>")
def api_estado(analisis_id):
    estado = ESTADOS.get(analisis_id, {"mensaje": "Desconocido", "completado": False, "error": None})
    return jsonify(estado)


@app.route("/dashboard/<int:analisis_id>")
def dashboard(analisis_id):
    analisis = Analisis.query.get_or_404(analisis_id)

    total_cve = 0
    no_verificados = 0
    risk_counts = {"Crítico": 0, "Alto": 0, "Medio": 0, "Bajo": 0}
    for d in analisis.dispositivos:
        risk_counts[d.nivel_riesgo or "Bajo"] = risk_counts.get(d.nivel_riesgo or "Bajo", 0) + 1
        for s in d.servicios:
            total_cve += s.total_cve or len(s.vulnerabilidades)
            if (s.estado_nvd or "").startswith("no_verificado"):
                no_verificados += 1

    return render_template(
        "dashboard.html", analisis=analisis, total_cve=total_cve,
        no_verificados=no_verificados, risk_counts=risk_counts
    )


@app.route("/dashboard/<int:analisis_id>/pdf")
def descargar_pdf(analisis_id):
    analisis = Analisis.query.get_or_404(analisis_id)

    dispositivos = []
    for d in analisis.dispositivos:
        dispositivos.append({
            "ip": d.ip,
            "sistema_operativo": d.sistema_operativo,
            "nivel_riesgo": d.nivel_riesgo or "Bajo",
            "servicios_evaluados": [
                {
                    "puerto": s.puerto,
                    "nombre_servicio": s.nombre_servicio,
                    "cvss_max": s.cvss_max,
                    "nivel_riesgo": s.nivel_riesgo or "Bajo",
                    "estado_nvd_texto": s.estado_nvd_texto,
                    "total_cve": s.total_cve or len(s.vulnerabilidades),
                    "vulnerabilidades": [v.to_dict() for v in s.vulnerabilidades_ordenadas],
                }
                for s in d.servicios
            ],
        })

    ruta_salida = os.path.join(REPORTS_DIR, f"informe_analisis_{analisis_id}.pdf")
    generar_reporte_pdf(dispositivos, analisis.riesgo_general or "Bajo", ruta_salida)

    return send_file(ruta_salida, as_attachment=True, download_name=f"informe_jagi_sentinel_{analisis_id}.pdf")


@app.route("/dashboard/<int:analisis_id>/json")
def descargar_json(analisis_id):
    analisis = Analisis.query.get_or_404(analisis_id)
    datos = analisis.to_dict()
    datos["dispositivos"] = [d.to_dict() for d in analisis.dispositivos]
    return jsonify(datos)


@app.route("/historial")
def historial():
    analisis_lista = Analisis.query.order_by(Analisis.fecha.desc()).all()
    return render_template("history.html", analisis_lista=analisis_lista)


if __name__ == "__main__":
    app.run(debug=True)