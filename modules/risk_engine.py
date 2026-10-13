"""
risk_engine.py — Motor de riesgo contextual: combina CVSS con
exposición del puerto y protocolo inseguro.
"""
PUERTOS_EXPUESTOS = {21, 22, 23, 80, 443, 445, 3389}
PROTOCOLOS_INSEGUROS = {"telnet", "ftp", "http"}


def clasificar_nivel(puntaje):
    if puntaje >= 9:
        return "Crítico"
    elif puntaje >= 7:
        return "Alto"
    elif puntaje >= 4:
        return "Medio"
    return "Bajo"


def calcular_riesgo_servicio(servicio, vulnerabilidades, credenciales_por_defecto=False):
    scores = [v["cvss_score"] for v in vulnerabilidades if v["cvss_score"] is not None]
    cvss_max = max(scores, default=0)
    puntaje = cvss_max
    if servicio.get("puerto") in PUERTOS_EXPUESTOS:
        puntaje += 1.0
    nombre = (servicio.get("nombre_servicio") or "").lower()
    inseguro = nombre in PROTOCOLOS_INSEGUROS
    if inseguro:
        puntaje += 1.5
    if cvss_max == 0 and inseguro:
        puntaje = max(puntaje, 4.0)
    # Credenciales de fábrica = acceso directo al dispositivo: riesgo Alto como mínimo.
    if credenciales_por_defecto:
        puntaje = max(puntaje, 7.0)
    return {
        "puerto": servicio.get("puerto"), "nombre_servicio": nombre,
        "cvss_max": cvss_max, "protocolo_inseguro": inseguro,
        "credenciales_por_defecto": credenciales_por_defecto,
        "puntaje_contexto": round(puntaje, 1), "nivel_riesgo": clasificar_nivel(puntaje),
    }


def calcular_riesgo_dispositivo(servicios_evaluados):
    orden = {"Bajo": 0, "Medio": 1, "Alto": 2, "Crítico": 3}
    if not servicios_evaluados:
        return "Bajo"
    return max(servicios_evaluados, key=lambda s: orden[s["nivel_riesgo"]])["nivel_riesgo"]


if __name__ == "__main__":
    telnet = calcular_riesgo_servicio({"puerto": 23, "nombre_servicio": "telnet"}, [])
    print("Telnet (sin CVEs):", telnet)
    apache = calcular_riesgo_servicio(
        {"puerto": 80, "nombre_servicio": "http"},
        [{"cve_id": "CVE-2011-2688", "cvss_score": 7.5, "descripcion": "..."}],
    )
    print("Apache con CVE real:", apache)
    print("Riesgo general:", calcular_riesgo_dispositivo([telnet, apache]))