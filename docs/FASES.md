# Documentación por fases — Jagi-Sentinel

Este documento registra, fase por fase, **qué se hizo** y **qué decisiones se tomaron**
(con su justificación), en relación con el documento del proyecto de grado. Sirve como
historial de versiones del proyecto: cualquier integrante puede entender en qué estado
está cada fase y por qué se hicieron las cosas de una manera y no de otra.

> Convención: cada fase indica su estado — Completada / En curso / Pendiente —
> y referencia la sección correspondiente del documento de grado cuando aplica.

## Resumen del estado por fase

| Fase | Descripción | Estado | Fechas reales |
|---|---|---|---|
| I | Análisis y diseño | Completada | Agosto |
| II | Desarrollo e integración (MVP) | Completada | Agosto - 12 de octubre |
| III | Preparación del laboratorio | Completada | 15 de octubre |
| IV | Proceso manual (línea base) | Completada | 8 de noviembre |
| V | Proceso automatizado (con la app) | Completada | 8 de noviembre |
| VI | Análisis comparativo y documentación | En curso | 8 - 20 de noviembre |

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
- Los archivos del laboratorio se subieron al repositorio en la carpeta lab/ (commit 84c67a4)
  para que cualquier integrante pueda replicarlo.

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

**Estado:** Completada (8 de noviembre de 2026) · **Documento:** Sección 9.6 (Fase IV) y Resultados.

### Qué se hizo
- Auditoría manual del laboratorio por Jhoan Vélez, de 14:51 a 15:19 (28 minutos), sin
  Jagi-Sentinel:
  - Descubrimiento de equipos con nmap -sn y escaneo de servicios con nmap -sS -sV -O.
  - Tabla manual de servicios y versiones.
  - Búsqueda en la web de NVD por palabra clave (Apache httpd 2.4.49 y vsftpd 3.0.5).
  - Prueba de credenciales de fábrica con curl (admin/admin funcionó en .10:80).
  - Revisión extra del acceso anónimo al FTP (curl ftp://192.168.56.30/).
  - Priorización manual e informe en texto plano.
- Métricas: 4 herramientas (Nmap, curl, navegador, editor), 7 comandos, 6 consultas a NVD,
  5 cambios de ventana (reconstruido, mínimo). Detección: 5 de 5 (100%).
- Evidencias en docs/evidencias_fase4/: sesión de terminal, salida de Nmap e informe manual.

### Decisiones tomadas
- **Grabar la terminal con script:** sirve de evidencia y permite contar los comandos sin error.
- **La preparación (pruebas y laboratorio) no se cronometra:** el tiempo va del primer
  comando de la auditoría hasta guardar el informe.
- **Para los CVE se toma la nota de NIST: NVD** (no la de CISA-ADP); para los CVE que NVD aún
  no analiza ("Awaiting Enrichment") se usa la nota del CNA, marcada como provisional.
- **La auditoría se hizo con apoyo de un asistente** para el procedimiento y la interpretación.
  Se declara en el informe y en el documento como amenaza a la validez: favorece al proceso
  manual, por lo que la ventaja de Jagi-Sentinel es una estimación conservadora.
- **Cambios de ventana reconstruidos:** no se contaron durante la ejecución; se reporta un
  mínimo reconstruido. Los clics no se registraron y no se comparan.

---

## Fase V — Proceso automatizado

**Estado:** Completada (8 de noviembre de 2026) · **Documento:** Sección 9.6 (Fase V) y Resultados.

### Qué se hizo
- Germán Valencia ejecutó Jagi-Sentinel en su propio equipo (Intel Core i5-7200U, 14 GiB,
  Ubuntu 26.04.1, wifi), siguiendo la guía Guia_Fase_V_Jagi-Sentinel.pdf, sobre el mismo
  laboratorio y el mismo commit (84c67a4), de 15:45 a 15:50 (5 min 27,5 s).
- Métricas: 1 herramienta (Jagi-Sentinel), 1 comando, 0 consultas a NVD, 1 cambio de ventana,
  16 clics. Detección: 5 de 5 (100%).
- Evidencias en docs/evidencias_fase5/: 11 capturas, informe PDF, sesión de terminal y el
  registro de ejecución (Anexos 1 y 2).

### Decisiones tomadas
- **Ejecución en un equipo distinto:** el compañero estaba en otro lugar. El laboratorio es
  idéntico (mismo docker-compose.yml); se registraron los datos del equipo y se declara como
  amenaza a la validez del tiempo.
- **La guía no revela las vulnerabilidades:** el ejecutor levantó el laboratorio sin abrir lab/
  (su README trae la lista completa).
- **Primer intento descartado:** el equipo se quedó sin batería. Se repitió desde el inicio con
  cronómetro nuevo y se conservó la grabación (sesion_terminal_fase5_descartado.txt).
- **Se cuenta 1 comando** (el que inicia la app); el documento decía "ninguno" y se corrigió.

---

## Fase VI — Análisis y documentación

**Estado:** En curso · **Documento:** Resultados, Conclusiones, Anexo E.

### Qué se hizo
- Calificación de la detección con el criterio del Anexo F: 5 de 5 en ambas modalidades.
  Diferencia de 0 puntos porcentuales: cumple el criterio de aceptación (margen de 5).
- Comparación consolidada:

| Indicador | Manual | Jagi-Sentinel | Reducción |
|---|---|---|---|
| Tiempo | 28 min | 5,46 min | 80,5% |
| Herramientas | 4 | 1 | 75% |
| Comandos | 7 | 1 | 85,7% |
| Consultas a NVD | 6 | 0 | 100% |
| Cambios de ventana | 5 (mínimo) | 1 | 80% |
| Detección | 100% | 100% | 0 puntos |

- Tres gráficos de barras (tiempo, complejidad y detección).
- Documento de grado actualizado (proyecto_grado_v3.tex): secciones nuevas de Resultados y
  Conclusiones, Resumen y Summary con resultados, cronograma con fechas reales, Anexo E
  diligenciado y correcciones pendientes (1 comando en la Fase V, 128 pruebas).

### Hallazgos para la discusión
- **Apache 2.4.49:** la búsqueda manual por palabra clave halló 2 CVE; Jagi-Sentinel, 100 (la
  consulta por CPE encuentra los CVE de rangos de versiones). Valor del normalizador CPE.
- **vsftpd 3.0.5:** la búsqueda manual halló 2 CVE recientes ("Awaiting Enrichment"); la app no,
  porque aún no tienen CPE en NVD. Limitación real del enfoque automatizado.
- **FTP anónimo:** lo detectó el proceso manual; la app no lo revisa (trabajo futuro).

### Decisiones tomadas
- **Herramientas: no se cuenta la terminal** en ninguna fase (es el medio, no la herramienta);
  en la Fase V el navegador cuenta como parte de Jagi-Sentinel.
- **Las amenazas a la validez se declaran todas** (asistencia en la Fase IV, equipos distintos,
  conteo reconstruido, intento descartado): ninguna invalida la conclusión.

### Pendiente
- Bitácora de la sesión, pull request de la rama a main y preparación de la sustentación.

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
| Tiempo sin la preparación | Incluir instalación y laboratorio | Medir solo la auditoría, igual en ambas fases |
| No contar la terminal | Contarla como herramienta | Es el medio; regla igual en ambas fases |
| Declarar la asistencia en la Fase IV | Omitirla | Honestidad; además favorece al proceso manual |

---

*Última actualización: 8 de noviembre de 2026 — Fases IV y V completadas, Fase VI en curso.*
