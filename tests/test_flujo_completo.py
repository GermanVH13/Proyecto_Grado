"""
test_flujo_completo.py — Análisis completo con Nmap y NVD simulados:
descubrimiento → CPE → NVD → riesgo → base de datos → dashboard y PDF.
No usa red, Nmap ni esperas reales.
"""
from unittest.mock import patch, MagicMock

from modules.models import db, Analisis, Dispositivo, Servicio
from modules.vulnerability_lookup import NVDError
from modules import estados_nvd as E

INFO_RED = {"interfaz": "wlp1s0", "ip": "192.168.1.6", "prefijo": 24,
            "gateway": "192.168.1.254", "red_cidr": "192.168.1.0/24"}


def servicio(puerto, nombre, producto="", version="", cpes=None):
    return {"puerto": puerto, "protocolo": "tcp", "estado": "open", "nombre_servicio": nombre,
            "producto": producto, "version": version, "cpes_nmap": cpes or []}


def host(ip, servicios):
    return {"ip": ip, "estado": "up", "mac": "AA:BB:CC:DD:EE:FF", "fabricante": None,
            "sistema_operativo": "Linux", "servicios": servicios}


def cve(i, score):
    return {"cve_id": f"CVE-2021-{i:04d}", "cvss_score": score, "descripcion": f"Descripción {i}"}


def ejecutar(jagi, dispositivos, nvd=None, escaneo_falla=None):
    """Corre el análisis completo de forma síncrona. Devuelve (id, mock_nvd)."""
    with jagi.app.app_context():
        a = Analisis(red_cidr="")
        db.session.add(a)
        db.session.commit()
        id_ = a.id
    mock_nvd = MagicMock(side_effect=nvd or (lambda cpe, api_key=None: []))
    escaner = MagicMock(side_effect=escaneo_falla) if escaneo_falla else MagicMock(return_value=dispositivos)
    with patch.object(jagi, "obtener_info_red", return_value=INFO_RED), \
         patch.object(jagi, "escanear_red", escaner), \
         patch.object(jagi, "consultar_vulnerabilidades", mock_nvd):
        jagi.ejecutar_analisis_en_segundo_plano(jagi.app, id_, "wlp1s0")
    return id_, mock_nvd


def servicios_por_puerto(jagi, id_):
    with jagi.app.app_context():
        resultado = {}
        for s in Servicio.query.join(Dispositivo).filter(Dispositivo.analisis_id == id_):
            resultado[s.puerto] = {
                "estado": s.estado_nvd, "total": s.total_cve, "cves": len(s.vulnerabilidades),
                "cvss": s.cvss_max, "riesgo": s.nivel_riesgo, "cpe": s.cpe,
            }
        return resultado


def test_servicio_con_cve_conocido_queda_guardado_y_visible(jagi, cliente):
    nvd = lambda cpe, api_key=None: [cve(1, 9.8), cve(2, 5.0)]
    id_, _ = ejecutar(jagi, [host("192.168.1.9", [servicio(80, "http", "Apache httpd", "2.4.49")])], nvd)

    assert jagi.ESTADOS[id_]["completado"] and jagi.ESTADOS[id_]["error"] is None
    s = servicios_por_puerto(jagi, id_)[80]
    assert s["estado"] == E.CON_CVE and s["total"] == 2 and s["cves"] == 2
    assert s["cvss"] == 9.8 and s["riesgo"] == "Crítico"
    assert s["cpe"] == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"

    html = cliente.get(f"/dashboard/{id_}").get_data(as_text=True)
    assert "CVE-2021-0001" in html and "2 CVE encontrados" in html
    pdf = cliente.get(f"/dashboard/{id_}/pdf")
    assert pdf.status_code == 200 and pdf.data.startswith(b"%PDF-")


def test_riesgo_se_propaga_a_dispositivo_y_red(jagi):
    nvd = lambda cpe, api_key=None: [cve(1, 7.0)] if "nginx" in cpe else []
    dispositivos = [
        host("192.168.1.9", [servicio(9999, "otro", "nginx", "1.18.0")]),   # Alto
        host("192.168.1.10", [servicio(9998, "otro")]),                     # Bajo
    ]
    id_, _ = ejecutar(jagi, dispositivos, nvd)
    with jagi.app.app_context():
        niveles = {d.ip: d.nivel_riesgo for d in Dispositivo.query.filter_by(analisis_id=id_)}
        assert niveles == {"192.168.1.9": "Alto", "192.168.1.10": "Bajo"}
        assert db.session.get(Analisis, id_).riesgo_general == "Alto"


def test_fallo_del_nvd_no_aborta_y_se_distingue_de_sin_cve(jagi):
    def nvd(cpe, api_key=None):
        if "nginx" in cpe:
            raise NVDError("NVD no respondió")
        return []
    dispositivos = [host("192.168.1.9", [
        servicio(443, "https", "nginx", "1.18.0"),
        servicio(21, "ftp", "vsftpd", "3.0.3"),
    ])]
    id_, _ = ejecutar(jagi, dispositivos, nvd)
    assert jagi.ESTADOS[id_]["completado"] and jagi.ESTADOS[id_]["error"] is None
    s = servicios_por_puerto(jagi, id_)
    assert s[443]["estado"] == E.NO_VERIFICADO_NVD
    assert s[21]["estado"] == E.SIN_CVE


def test_servicio_sin_version_no_se_consulta_al_nvd(jagi):
    id_, nvd = ejecutar(jagi, [host("192.168.1.9", [servicio(80, "http", "lighttpd", "")])])
    nvd.assert_not_called()
    assert servicios_por_puerto(jagi, id_)[80]["estado"] == E.NO_VERIFICADO_VERSION


def test_producto_con_version_pero_sin_cpe_conocido(jagi):
    id_, nvd = ejecutar(jagi, [host("192.168.1.9", [servicio(22, "ssh", "ProductoRaro", "1.0")])])
    nvd.assert_not_called()
    assert servicios_por_puerto(jagi, id_)[22]["estado"] == E.NO_VERIFICADO_CPE


def test_se_usa_el_cpe_que_entrega_nmap(jagi):
    cpes = ["cpe:/a:miniupnp_project:miniupnpd:1.9"]
    _, nvd = ejecutar(jagi, [host("192.168.1.1", [servicio(5000, "upnp", "MiniUPnP", "1.9", cpes)])])
    nvd.assert_called_once_with("cpe:2.3:a:miniupnp_project:miniupnpd:1.9:*:*:*:*:*:*:*")


def test_se_guardan_los_10_cve_mas_graves_pero_se_cuentan_todos(jagi):
    nvd = lambda cpe, api_key=None: [cve(i, float(i % 10)) for i in range(15)]
    id_, _ = ejecutar(jagi, [host("192.168.1.9", [servicio(21, "ftp", "vsftpd", "2.3.4")])], nvd)
    s = servicios_por_puerto(jagi, id_)[21]
    assert s["total"] == 15 and s["cves"] == 10 and s["cvss"] == 9.0
    with jagi.app.app_context():
        guardados = [v.cvss_score for v in Servicio.query.one().vulnerabilidades]
        assert min(guardados) >= 2.0


def test_red_sin_dispositivos_termina_bien_con_riesgo_bajo(jagi):
    id_, _ = ejecutar(jagi, [])
    assert jagi.ESTADOS[id_]["error"] is None
    with jagi.app.app_context():
        assert db.session.get(Analisis, id_).riesgo_general == "Bajo"


def test_error_en_el_escaneo_queda_registrado(jagi):
    id_, _ = ejecutar(jagi, [], escaneo_falla=RuntimeError("nmap no instalado"))
    estado = jagi.ESTADOS[id_]
    assert estado["completado"] is True
    assert "nmap no instalado" in estado["error"]
