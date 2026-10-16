# Documentación por fases — Jagi-Sentinel

Este documento registra, fase por fase, **qué se hizo** y **qué decisiones se tomaron**
(con su justificación), en relación con el documento del proyecto de grado. Sirve como
historial de versiones del proyecto: cualquier integrante puede entender en qué estado
está cada fase y por qué se hicieron las cosas de una manera y no de otra.

> Convención: cada fase indica su estado — Completada / En curso / Pendiente —
> y referencia la sección correspondiente del documento de grado cuando aplica.

## Resumen del estado por fase

| Fase | Descripción | Estado | Fechas (cronograma reprogramado) |
|---|---|---|---|
| I | Análisis y diseño | Completada | Agosto |
| II | Desarrollo e integración (MVP) | Completada | hasta el 18 de octubre |
| III | Preparación del laboratorio | Completada | 19-25 de octubre |
| IV | Proceso manual (línea base) | Pendiente | 26-29 de octubre |
| V | Proceso automatizado (con la app) | Pendiente | 30 de octubre - 1 de noviembre |
| VI | Análisis comparativo y documentación | Pendiente | 2-20 de noviembre |

---

## Fase I — Análisis y diseño

**Estado:** Completada · **Documento:** Secciones 7, 9.1-9.4, Anexos C y D.

### Qué se hizo
- Definición de requisitos funcionales (RF-01 a RF-11) y no funcionales (RNF-01 a RNF-06).
- Selección de las herramientas de código abierto a integrar.
- Diseño de la arquitectura modular (un módulo por responsabilidad).
- Diseño del modelo de datos (4 tablas).
- Definición de los parámetros del laboratorio de prueba.
- Diseño de los instrumentos de recolección (checklist y plantilla de detección).

### Decisiones tomadas
- **Herramientas elegidas y por qué:**
  - Nmap para el escaneo: estándar de facto, entrega producto, versión y CPE en XML.
  - API de NVD para los CVE: fuente oficial y gratuita, consultable por CPE.
  - SQLite como base de datos: local, sin servidor, suficiente para el historial.
  - Flask para la interfaz web: ligero y en Python, mismo lenguaje que el orquestador.
  - WeasyPrint para el PDF: convierte HTML a PDF sin dependencias pesadas.
- **Laboratorio virtualizado (Docker) en lugar de dispositivos físicos:** garantiza que el
  entorno sea 100% replicable e idéntico en cada ejecución. Consecuencia asumida: Docker
  asigna MAC genéricas, por lo que no se puede identificar el fabricante por la MAC.
- **Enfoque de evaluación descriptivo (no inferencial):** al haber una única ejecución
  pareada por modalidad, no hay respaldo muestral para pruebas estadísticas. Se declara
  como limitación del estudio.
- **Criterio de detección:** una vulnerabilidad se cuenta como detectada cuando el proceso
  la reporta explícitamente en su resultado final, asociada al dispositivo correcto.

---

## Fase II — Desarrollo e integración (MVP)

**Estado:** Completada · **Documento:** Secciones 7.5-7.6, 9.6 (Fase II), Anexo C.

### Qué se hizo (por componente)
- network_manager: detección de interfaz, IP, máscara, gateway y cálculo del rango CIDR.
- device_discovery: ejecución de Nmap y parseo del XML (incluye todos los CPE por puerto).
- normalizer: conversión a CPE 2.3 (CPE de Nmap -> diccionario propio -> None).
- vulnerability_lookup: consulta a NVD con reintentos, caché, control de límite de uso y
  conexión IPv4 primero. Extrae CVE con CVSS, descripción y referencias.
- estados_nvd: los 5 estados de verificación.
- credenciales: verificación de credenciales por defecto en servicios web (RF-11).
- risk_engine: motor de riesgo contextual (CVSS + exposición + protocolo + credenciales).
- report_generator: informe en PDF con escape de HTML.
- models + migracion: 4 tablas y migración automática de columnas.
- errores: mensajes de fallo claros en español.
- Interfaz: inicio, progreso, dashboard (con gráfico de riesgo propio), historial y PDF.
- Pruebas: 128 casos automáticos, ejecutables sin red.

### Decisiones tomadas
- **CPE tomado de Nmap, sin heurística:** los CPE inventados muchas veces no existen en NVD
  y producían CVSS 0 falsos. Se usa el CPE real de Nmap (2.2 -> 2.3); la tabla curada queda
  solo como respaldo.
- **Cinco estados de verificación:** para no confundir "sin CVE" con "no se pudo verificar".
- **Conexión IPv4 primero:** en redes sin IPv6 funcional un análisis pasó de 1099 s a 21 s.
- **Credenciales por defecto con módulo propio en Python (no scripts NSE de Nmap):** más
  fácil de leer, probar y defender; encaja en la arquitectura. Alcance: solo HTTP; Telnet y
  FTP quedan como trabajo futuro.
- **Credenciales por defecto elevan el riesgo a Alto como mínimo** (piso 7.0): una credencial
  de fábrica es acceso directo al dispositivo.
- **Referencias de cada CVE:** se guardan y se muestran (dashboard y PDF).
- **Gráfico del dashboard propio en HTML/CSS (no Chart.js ni CDN):** funciona sin conexión.
- **Factor "tipo de dispositivo" como trabajo futuro:** MAC genérica en Docker, no fiable.
- **Modo debug desactivado por defecto (C-01):** seguridad, se activa con FLASK_DEBUG=1.
- **install.sh instala las librerías de WeasyPrint (C-13):** libpango.
- **requirements-dev.txt separado:** pytest aparte de las dependencias de la aplicación.
- Se conservaron crear_estructura.sh y static/js/dashboard.js por decisión del equipo.

### Historial de etapas (commits principales)
| Commit / PR | Contenido |
|---|---|
| PR #1-#8 | Orden del repo, CPE de Nmap, estados NVD, dashboard/PDF, pruebas, IPv4, fallos + migración, README/install.sh |
| 8a497bf | Detección de credenciales por defecto (RF-11) — Paso 1 |
| fc8919f | Credenciales (visualización), referencias de CVE, gráfico propio y correcciones C-01/C-13 |

---

## Fase III — Preparación del laboratorio

**Estado:** Completada · **Documento:** Sección 9.6 (Fase III) y Anexo F.

### Qué se hizo
- Montar el laboratorio virtualizado con Docker (red aislada 192.168.56.0/24):
  - Cámara IP simulada (.10): Telnet, panel web HTTP con admin/admin.
  - Impresora simulada (.20): Apache 2.4.49 (CVE-2021-41773).
  - Sensor/NAS simulado (.30): FTP.
- Insertar las vulnerabilidades controladas (V-01 a V-05) y registrar la lista definitiva.
- Verificar que Jagi-Sentinel ve la red y detecta las vulnerabilidades.

### Decisiones tomadas
- Entorno 100% virtualizado: replicable con un solo comando (docker compose).
- El equipo de análisis actúa como gateway de la red del laboratorio (no hay router físico).
- Apache 2.4.49 como versión vulnerable: CVE documentado, CVSS alto e imagen oficial.
- Las credenciales por defecto se mantienen (V-02) y ya están cubiertas por el código.

### Resultado de la verificación (15 de octubre de 2026)

El laboratorio se montó con Docker (3 contenedores) y Jagi-Sentinel lo analizó desde la
interfaz web (interfaz jagi-lab0). Se detectaron las 5 vulnerabilidades insertadas:

| Dispositivo | Riesgo | Hallazgo |
|---|---|---|
| 192.168.56.10 (cámara) | Alto | Credenciales por defecto admin/admin (V-02); Telnet (V-01), HTTP (V-04) |
| 192.168.56.20 (impresora) | Crítico | Apache 2.4.49: 100 CVE, CVSS 9.8, CVE-2021-41773 (V-03) |
| 192.168.56.30 (sensor) | Medio | FTP inseguro, sin CVE en NVD (V-05) |

El gateway (192.168.56.1, el propio equipo) también aparece en el análisis y se excluye del
conteo de dispositivos IoT. Evidencia en docs/evidencias_fase3/.

---

## Fase IV — Proceso manual

**Estado:** Pendiente · **Documento:** Sección 9.6 (Fase IV).

Auditoría manual del laboratorio (Nmap + consultas manuales a NVD) para obtener la línea
base, registrando tiempo, herramientas, comandos, intervenciones y detecciones.

---

## Fase V — Proceso automatizado

**Estado:** Pendiente · **Documento:** Sección 9.6 (Fase V).

Misma auditoría con Jagi-Sentinel, registrando las mismas métricas. La ejecuta un integrante
distinto que no conozca la lista de vulnerabilidades (para reducir el sesgo de aprendizaje).

---

## Fase VI — Análisis y documentación

**Estado:** Pendiente · **Documento:** Sección 9.7 y Plan de análisis.

Comparación descriptiva (tiempo, complejidad, detección), gráficos, interpretación, informe
final y defensa.

---

## Resumen de decisiones de diseño

| Decisión | Alternativa descartada | Por qué |
|---|---|---|
| Orquestar Nmap + NVD | Crear un escáner propio | El valor está en integrar herramientas probadas |
| CPE tomado de Nmap | CPE por heurística | Los CPE inventados no existen en NVD (CVSS 0 falsos) |
| 5 estados de verificación | Reportar "sin CVE" a secas | Distinguir "sin vulnerabilidades" de "no verificado" |
| IPv4 primero | Orden del sistema | En redes sin IPv6 el análisis tardaba minutos |
| Credenciales: módulo Python | Scripts NSE de Nmap | Más fácil de probar y defender |
| Gráfico propio HTML/CSS | Chart.js (CDN) | Funciona sin internet; sin dependencias externas |
| Tipo de dispositivo a futuro | Implementarlo ahora | MAC genérica en Docker: no es fiable |
| Laboratorio virtualizado | Dispositivos físicos | Replicable e idéntico en cada ejecución |
| Debug desactivado por defecto | Dejar debug activo | Seguridad: evita ejecución de código con sudo |

---

*Última actualización: 15 de octubre de 2026 — Fase II cerrada, Fase III en curso.*
