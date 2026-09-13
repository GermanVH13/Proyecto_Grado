"""
report_generator.py — Genera un informe en PDF a partir de los resultados
de un análisis (dispositivos, servicios y su nivel de riesgo).
"""
from datetime import datetime
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
    th, td {{ text-align: left; padding: 6px; border-bottom: 1px solid #eee; font-size: 0.9em; }}
    .resumen {{ background: #f5f5f5; padding: 15px; border-radius: 6px; margin-bottom: 30px; }}
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
        <tr><th>Puerto</th><th>Servicio</th><th>CVSS máx.</th><th>Riesgo</th></tr>
        {filas_servicios}
    </table>
</div>
"""

FILA_SERVICIO = """<tr><td>{puerto}</td><td>{nombre_servicio}</td><td>{cvss_max}</td><td>{nivel_riesgo}</td></tr>"""


def generar_reporte_pdf(dispositivos, riesgo_red, ruta_salida):
    """
    dispositivos: lista de dicts con claves:
        ip, sistema_operativo, nivel_riesgo, servicios_evaluados (lista de dicts
        con puerto, nombre_servicio, cvss_max, nivel_riesgo)
    riesgo_red: nivel de riesgo general ("Bajo"/"Medio"/"Alto"/"Crítico")
    ruta_salida: ruta del archivo .pdf a generar
    """
    bloques = []
    for d in dispositivos:
        filas = "".join(
            FILA_SERVICIO.format(**s) for s in d.get("servicios_evaluados", [])
        )
        bloques.append(BLOQUE_DISPOSITIVO.format(
            ip=d["ip"],
            sistema_operativo=d.get("sistema_operativo") or "Desconocido",
            nivel_riesgo=d["nivel_riesgo"],
            clase_riesgo=d["nivel_riesgo"].lower().replace("í", "i"),
            filas_servicios=filas,
        ))

    html_final = PLANTILLA_HTML.format(
        fecha=datetime.now().strftime("%d/%m/%Y %H:%M"),
        total_dispositivos=len(dispositivos),
        riesgo_red=riesgo_red,
        bloques_dispositivos="".join(bloques),
    )

    HTML(string=html_final).write_pdf(ruta_salida)
    return ruta_salida


if __name__ == "__main__":
    dispositivos_ejemplo = [
        {
            "ip": "192.168.1.1",
            "sistema_operativo": "Linux (router)",
            "nivel_riesgo": "Medio",
            "servicios_evaluados": [
                {"puerto": 23, "nombre_servicio": "telnet", "cvss_max": 0, "nivel_riesgo": "Medio"},
            ],
        },
        {
            "ip": "192.168.1.46",
            "sistema_operativo": "Linux",
            "nivel_riesgo": "Crítico",
            "servicios_evaluados": [
                {"puerto": 80, "nombre_servicio": "http", "cvss_max": 7.5, "nivel_riesgo": "Crítico"},
                {"puerto": 3306, "nombre_servicio": "mysql", "cvss_max": 0, "nivel_riesgo": "Bajo"},
            ],
        },
    ]
    ruta = generar_reporte_pdf(dispositivos_ejemplo, "Crítico", "reports/informe_prueba.pdf")
    print(f"Informe generado en: {ruta}")