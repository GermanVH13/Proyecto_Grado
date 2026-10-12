"""
report_generator.py — Genera un informe en PDF a partir de los resultados
de un análisis (dispositivos, servicios, estado de verificación en el NVD y CVE).
"""
from datetime import datetime
from html import escape

from weasyprint import HTML

PLANTILLA_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
    body {{ font-family: Arial, sans-serif; margin: 40px; color: #222; }}
    h1 {{ color: #1a1a2e; border-bottom: 3px solid #1a1a2e; padding-bottom: 10px; }}
    .fecha {{ color: #666; font-size: 0.9em; margin-bottom: 30px; }}
    .dispositivo {{ margin-bottom: 25px; padding: 15px; border: 1px solid #ddd; border-radius: 6px; }}
    .critico {{ border-left: 6px solid #d32f2f; }}
    .alto {{ border-left: 6px solid #f57c00; }}
    .medio {{ border-left: 6px solid #fbc02d; }}
    .bajo {{ border-left: 6px solid #388e3c; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
    th, td {{ text-align: left; padding: 6px; border-bottom: 1px solid #eee; font-size: 0.9em; vertical-align: top; }}
    tr {{ page-break-inside: avoid; }}
    .resumen {{ background: #f5f5f5; padding: 15px; border-radius: 6px; margin-bottom: 30px; }}
    .no-verificado {{ color: #666; font-style: italic; }}
    .cves td {{ border-bottom: 1px solid #f0f0f0; font-size: 0.82em; }}
    .cves {{ margin: 0 0 8px 18px; width: auto; }}
    .cve-id {{ font-weight: bold; white-space: nowrap; }}
    .cves td:nth-child(2) {{ white-space: nowrap; }}
    .nota {{ color: #666; font-size: 0.8em; margin: 2px 0 0 18px; }}
</style>
</head>
<body>
    <h1>Informe de Seguridad — Jagi-Sentinel</h1>
    <div class="fecha">Generado el {fecha}</div>
    <div class="resumen">
        <strong>Dispositivos analizados:</strong> {total_dispositivos}<br>
        <strong>Nivel de riesgo general de la red:</strong> {riesgo_red}
    </div>
    {bloques_dispositivos}
</body>
</html>
"""

BLOQUE_DISPOSITIVO = """
<div class="dispositivo {clase_riesgo}">
    <h3>{ip} — {sistema_operativo}</h3>
    <p><strong>Riesgo del dispositivo:</strong> {nivel_riesgo}</p>
    <table>
        <tr><th>Puerto</th><th>Servicio</th><th>Estado NVD</th><th>CVSS máx.</th><th>Riesgo</th></tr>
        {filas_servicios}
    </table>
</div>
"""


def _bloque_cve(vulnerabilidades, total_cve):
    """Lista de CVE de un servicio (ID, CVSS y descripción completa)."""
    filas = "".join(
        '<tr><td class="cve-id">{id}</td><td>CVSS {cvss}</td><td>{desc}</td></tr>'.format(
            id=escape(str(v.get("cve_id", ""))),
            cvss=escape(str(v["cvss_score"])) if v.get("cvss_score") is not None else "N/D",
            desc=escape(v.get("descripcion") or "Sin descripción."),
        )
        for v in vulnerabilidades
    )
    nota = ""
    if total_cve and total_cve > len(vulnerabilidades):
        nota = f'<div class="nota">Se muestran los {len(vulnerabilidades)} CVE más graves de {total_cve} encontrados.</div>'
    return f'<tr><td colspan="5"><table class="cves">{filas}</table>{nota}</td></tr>'


def _fila_servicio(s):
    estado = s.get("estado_nvd_texto") or "—"
    clase = ' class="no-verificado"' if estado.startswith("No verificado") else ""
    fila = (
        f'<tr><td>{escape(str(s.get("puerto", "")))}</td>'
        f'<td>{escape(str(s.get("nombre_servicio") or "—"))}</td>'
        f'<td{clase}>{escape(estado)}</td>'
        f'<td>{escape(str(s.get("cvss_max", 0)))}</td>'
        f'<td>{escape(str(s.get("nivel_riesgo", "")))}</td></tr>'
    )
    if s.get("vulnerabilidades"):
        fila += _bloque_cve(s["vulnerabilidades"], s.get("total_cve", 0))
    return fila


def construir_html(dispositivos, riesgo_red):
    bloques = []
    for d in dispositivos:
        filas = "".join(_fila_servicio(s) for s in d.get("servicios_evaluados", []))
        bloques.append(BLOQUE_DISPOSITIVO.format(
            ip=escape(d["ip"]),
            sistema_operativo=escape(d.get("sistema_operativo") or "Desconocido"),
            nivel_riesgo=escape(d["nivel_riesgo"]),
            clase_riesgo=d["nivel_riesgo"].lower().replace("í", "i"),
            filas_servicios=filas,
        ))

    return PLANTILLA_HTML.format(
        fecha=datetime.now().strftime("%d/%m/%Y %H:%M"),
        total_dispositivos=len(dispositivos),
        riesgo_red=escape(riesgo_red),
        bloques_dispositivos="".join(bloques),
    )


def generar_reporte_pdf(dispositivos, riesgo_red, ruta_salida):
    """
    dispositivos: lista de dicts con claves:
        ip, sistema_operativo, nivel_riesgo, servicios_evaluados (lista de dicts
        con puerto, nombre_servicio, cvss_max, nivel_riesgo y, opcionalmente,
        estado_nvd_texto, total_cve y vulnerabilidades [{cve_id, cvss_score, descripcion}])
    riesgo_red: nivel de riesgo general ("Bajo"/"Medio"/"Alto"/"Crítico")
    ruta_salida: ruta del archivo .pdf a generar
    """
    HTML(string=construir_html(dispositivos, riesgo_red)).write_pdf(ruta_salida)
    return ruta_salida


if __name__ == "__main__":
    dispositivos_ejemplo = [
        {
            "ip": "192.168.1.1",
            "sistema_operativo": "Linux (router)",
            "nivel_riesgo": "Medio",
            "servicios_evaluados": [
                {"puerto": 23, "nombre_servicio": "telnet", "cvss_max": 0, "nivel_riesgo": "Medio",
                 "estado_nvd_texto": "No verificado: versión no detectada"},
            ],
        },
        {
            "ip": "192.168.1.46",
            "sistema_operativo": "Linux",
            "nivel_riesgo": "Crítico",
            "servicios_evaluados": [
                {"puerto": 80, "nombre_servicio": "http", "cvss_max": 9.8, "nivel_riesgo": "Crítico",
                 "estado_nvd_texto": "1 CVE encontrados", "total_cve": 1,
                 "vulnerabilidades": [{"cve_id": "CVE-2021-41773", "cvss_score": 9.8,
                                       "descripcion": "Path traversal en Apache HTTP Server 2.4.49."}]},
                {"puerto": 3306, "nombre_servicio": "mysql", "cvss_max": 0, "nivel_riesgo": "Bajo",
                 "estado_nvd_texto": "Sin CVE en NVD"},
            ],
        },
    ]
    ruta = generar_reporte_pdf(dispositivos_ejemplo, "Crítico", "reports/informe_prueba.pdf")
    print(f"Informe generado en: {ruta}")
