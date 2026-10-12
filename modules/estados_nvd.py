"""
estados_nvd.py — Estado de la verificación de cada servicio contra el NVD.

Distingue "se revisó y no hay CVE" de "no se pudo revisar", que sin esta
distinción se verían igual (0 CVE) y harían parecer seguro un servicio no verificado.
"""

CON_CVE = "con_cve"
SIN_CVE = "sin_cve"
NO_VERIFICADO_VERSION = "no_verificado_version"
NO_VERIFICADO_CPE = "no_verificado_cpe"
NO_VERIFICADO_NVD = "no_verificado_nvd"

ETIQUETAS = {
    CON_CVE: "CVE encontrados",
    SIN_CVE: "Sin CVE en NVD",
    NO_VERIFICADO_VERSION: "No verificado: versión no detectada",
    NO_VERIFICADO_CPE: "No verificado: producto sin CPE conocido",
    NO_VERIFICADO_NVD: "No verificado: NVD no respondió",
}


def determinar_estado(cpe, version, vulnerabilidades, consulta_fallida=False):
    """
    cpe              : CPE 2.3 calculado para el servicio (o None).
    version          : versión que reportó Nmap (puede ser None o vacía).
    vulnerabilidades : lista devuelta por el NVD (vacía si no se consultó).
    consulta_fallida : True si se intentó consultar y el NVD no respondió.
    """
    if consulta_fallida:
        return NO_VERIFICADO_NVD
    if not cpe:
        if not version or not str(version).strip():
            return NO_VERIFICADO_VERSION
        return NO_VERIFICADO_CPE
    return CON_CVE if vulnerabilidades else SIN_CVE


def etiqueta(estado, total_cve=0):
    """Texto para mostrar al usuario. Con CVE incluye la cantidad: '3 CVE encontrados'."""
    if estado == CON_CVE:
        return f"{total_cve} {ETIQUETAS[CON_CVE]}"
    return ETIQUETAS.get(estado, "—")
