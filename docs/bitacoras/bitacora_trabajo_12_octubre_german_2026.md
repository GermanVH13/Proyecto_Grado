**Bitácora de trabajo**

**Proyecto de grado — Jagi-Sentinel**

Fecha: 12 de octubre de 2026

*Universidad San Buenaventura — Facultad de Ingeniería — Programa de Ingeniería de Datos y Software*

Autores: Jhoan Vélez, Alejandro Zuleta, Germán Valencia, Isaac Ocampo

Este documento resume el trabajo realizado en la sesión de hoy: diagnóstico y corrección del hallazgo pendiente del CVSS en 0.0, rediseño de la verificación de vulnerabilidades contra NVD, manejo de errores, pruebas automáticas, ordenamiento del repositorio y alineación de la documentación. Con esto se da por cerrada la Fase II (desarrollo e integración).

# Historial de revisiones

| **Rev.** | **Fecha**             | **Autores**                                                  | **Resumen de cambios**                                                                                                                                                                                                                                                                                                                                                            |
|----------|-----------------------|--------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1        | 12 de octubre de 2026 | Jhoan Vélez, Alejandro Zuleta, Germán Valencia, Isaac Ocampo | Bitácora inicial de la sesión. Diagnóstico y corrección del CVSS en 0.0 (estados de verificación NVD, CPE tomado de Nmap, reintentos, caché y clave de API), corrección de la latencia por IPv6, análisis fallidos con motivo claro, migración automática de la base de datos, 115 pruebas automáticas sin red, limpieza del repositorio y README alineado. Cierre de la Fase II. |

# 1. Resumen ejecutivo del día

- Se resolvió el pendiente de la bitácora del 18 de septiembre: el CVSS máximo en 0.0 en todos los servicios del primer análisis real. No era un único error sino cuatro causas combinadas (Sección 2).

- El sistema ahora distingue cinco estados de verificación por servicio, de modo que un fallo de NVD, un producto desconocido o una versión no detectada ya no se confunden con «Sin CVE».

- Se encontró y corrigió la causa de que cada consulta a NVD tardara minutos: la red del autor no responde por IPv6 y Python lo intentaba primero. Un análisis completo bajó de 1099 s a 21 s (Sección 4).

- Los análisis que fallan (Nmap ausente, falta de permisos, sin ruta de red, etc.) ahora quedan guardados con un mensaje claro en español, y se muestran así en el dashboard y el historial.

- Se agregó migración automática de columnas para que las bases locales de los demás integrantes sigan funcionando tras los cambios en el modelo.

- Las pruebas automáticas pasaron de 20 a 115 casos, todos ejecutables sin red (Nmap y NVD simulados).

- Se verificó la cadena completa con Nmap real y NVD real sobre un servicio local que anuncia Apache 2.4.49: 100 CVE, CVSS máximo 9.8, riesgo Crítico, visible en dashboard y PDF (Sección 5).

- El trabajo se entregó por etapas, cada una en su rama y su pull request (#1 a #8), todos integrados a main por el equipo. Se ordenó el repositorio (entorno virtual, cachés, base local y PDF con datos de red real fuera del control de versiones) y se reescribió el README para que refleje el código real.

# 2. Cierre del pendiente: CVSS en 0.0

## 2.1 Hallazgo original

En el primer análisis real sobre la red del autor (Sección 9.4 de la bitácora del 18 de septiembre), todos los servicios quedaron con CVSS máximo 0.0 y ninguna vulnerabilidad asociada, incluso en dispositivos donde se esperaba encontrar CVE. La hipótesis inicial era que faltaban producto y versión o que el CPE construido no calzaba con el diccionario de NVD.

## 2.2 Causas encontradas

El diagnóstico se hizo con scripts independientes del repositorio (consultas directas a NVD con distintos CPE). Se encontraron cuatro causas que se sumaban:

| **Causa**                                                                         | **Efecto observado**                                                                 | **Corrección aplicada**                                                                                                                         |
|-----------------------------------------------------------------------------------|--------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| El normalizador construía CPE por heurística, y algunos no existen en NVD.        | NVD responde HTTP 200 con 0 resultados: es indistinguible de «sin vulnerabilidades». | Se usa el CPE que reporta Nmap (convertido de CPE 2.2 a 2.3). La tabla curada de productos queda solo como respaldo y se eliminó la heurística. |
| Un CPE inexistente o un fallo de red terminaban en el mismo resultado silencioso. | Servicios que nunca se consultaron o que fallaron aparecían como «sin CVE».          | Cinco estados explícitos de verificación, mostrados en el dashboard y el PDF (Sección 3.3).                                                     |
| Pocos servicios (sobre todo IoT) exponen producto y versión.                      | No hay forma de verificarlos contra NVD.                                             | Se marcan «No verificado» con su motivo, en lugar de reportarlos como seguros.                                                                  |
| python-nmap conserva únicamente el último \<cpe\> de cada servicio.               | Se perdían CPE válidos que Nmap sí había detectado.                                  | Se analiza el XML crudo de Nmap con ElementTree y se toman todos los CPE de aplicación.                                                         |

# 3. Cambios implementados por etapa

El trabajo se organizó en etapas pequeñas. Cada una se desarrolló en su propia rama y se integró a main mediante un pull request, que el equipo revisó y unió:

| **PR** | **Etapa** | **Contenido**                                                                    |
|--------|-----------|----------------------------------------------------------------------------------|
| \#1    | 0         | Ordenar el repositorio                                                           |
| \#2    | 2.1       | CPE tomado de Nmap (2.2 a 2.3), sin heurística                                   |
| \#3    | 2.2       | Estados de verificación NVD, reintentos, caché y clave de API en .env            |
| \#4    | 2.3       | Dashboard y PDF con estado NVD y lista de CVE                                    |
| \#5    | 3         | Pruebas automáticas con Nmap y NVD simulados                                     |
| \#6    | 4         | Conexión a NVD por IPv4 primero                                                  |
| \#7    | 5         | Análisis fallidos con motivo claro y migración automática de columnas            |
| #8    | 6         | README alineado con el código, install.sh actualizado, PDF fuera del repositorio |

## 3.1 Etapa 0 — Orden del repositorio

Se retiraron del control de versiones el entorno virtual (venv/), los cachés de Python (\_\_pycache\_\_), los de pytest y la base de datos SQLite local, y se agregó un .gitignore. Son archivos generados o locales que no deben versionarse.

## 3.2 Etapa 2.1 — CPE tomado de Nmap

- **normalizer.py:** convierte el CPE 2.2 que entrega Nmap (cpe:/a:…) al formato 2.3 que exige NVD, decodificando y escapando caracteres. Si el CPE no trae versión, usa la versión del servicio; si tampoco la hay, devuelve None.

- **device_discovery.py:** nueva función que extrae del XML crudo de Nmap todos los CPE de aplicación por IP y puerto, y los agrega a cada servicio.

- Orden de decisión: primero el CPE de Nmap; si no hay, la tabla curada de productos conocidos; si tampoco, None (el servicio se marca sin CPE conocido).

## 3.3 Etapa 2.2 — Estados de verificación y robustez de la consulta

Se creó el módulo estados_nvd.py con cinco estados, que se guardan por servicio y se muestran en pantalla:

| **Estado**            | **Texto mostrado**                       | **Cuándo ocurre**                                                      |
|-----------------------|------------------------------------------|------------------------------------------------------------------------|
| con_cve               | N CVE encontrados                        | NVD devolvió una o más vulnerabilidades.                               |
| sin_cve               | Sin CVE en NVD                           | Se consultó con un CPE válido y NVD respondió sin resultados.          |
| no_verificado_version | No verificado: versión no detectada      | El servicio no expone versión; no se puede consultar.                  |
| no_verificado_cpe     | No verificado: producto sin CPE conocido | No hay CPE de Nmap ni entrada en la tabla curada.                      |
| no_verificado_nvd     | No verificado: NVD no respondió          | La consulta falló (tiempo agotado, límite de uso, error del servidor). |

Cambios en vulnerability_lookup.py:

- Excepción propia NVDError, para que un fallo de la consulta no se confunda con una respuesta vacía.

- Reintentos ante tiempo agotado, 403, 429 y errores 5xx; sin reintento ante otros 4xx; un 404 se trata como lista vacía.

- Espera entre consultas para respetar el límite de NVD (cerca de 5 consultas por 30 s sin clave y 50 por 30 s con clave) y caché de resultados dentro del análisis.

- La clave de API de NVD se lee desde el archivo .env (excluido del repositorio, con plantilla .env.example) y nunca se escribe en el código.

- Parámetros ajustables por variable de entorno: NVD_API_KEY, NVD_TIMEOUT (60 s), NVD_REINTENTOS (2) y NVD_IPV4 (1).

## 3.4 Etapa 2.3 — Dashboard y PDF

- Nueva columna «Estado NVD» en la tabla de servicios del dashboard.

- Por cada servicio con CVE, una lista desplegable con los 10 más graves (ID con enlace a nvd.nist.gov, CVSS y descripción).

- El PDF incluye el estado y una sub-tabla de CVE con identificador, CVSS y descripción completa, con la nota «Se muestran los N CVE más graves de M».

- Los textos que vienen de NVD o de Nmap se escapan antes de insertarse en el HTML del informe.

*(captura omitida en esta versión Markdown; está en el .docx)*

*Figura 1. Dashboard con la columna «Estado NVD» y la lista desplegable de CVE. Datos de prueba sembrados (no es una red real); las descripciones de prueba incluyen etiquetas HTML que se muestran como texto.*

## 3.5 Etapa 3 — Pruebas automáticas

Se escribieron pruebas que no necesitan Nmap, internet ni la base real: usan una base SQLite temporal y un directorio de informes temporal (variables JAGI_DATABASE_URI y JAGI_REPORTS_DIR definidas en tests/conftest.py antes de importar la aplicación). Detalle en la Sección 6.

## 3.6 Etapa 5 — Análisis fallidos y migración de la base

- **Estado del análisis:** la tabla analisis ahora guarda estado (en_curso, completado, fallido) y error. Al arrancar, los análisis que quedaron en curso por un cierre inesperado se marcan como interrumpidos.

- **Mensajes claros:** el módulo errores.py traduce las excepciones comunes (Nmap no instalado, falta de permisos de administrador, sin ruta por defecto, sin IPv4, interfaz inexistente, comando ip ausente, errores de base de datos) a texto en español, con el detalle técnico al final.

- **Interfaz:** el dashboard muestra un recuadro de error, el historial etiqueta los análisis como FALLÓ o EN CURSO, y el botón de PDF se oculta cuando el análisis falló (la ruta responde 409 si se fuerza).

- **Migración automática:** create_all() no modifica tablas existentes, así que la base local de cada integrante no tendría las columnas nuevas. migracion.py agrega las que falten con ALTER TABLE al iniciar la aplicación.

*(captura omitida en esta versión Markdown; está en el .docx)*

*Figura 2. Dashboard de un análisis fallido (Nmap ausente), con el motivo en español. Captura con datos de prueba.*

## 3.7 Etapa 6 — README, instalación y privacidad

- README reescrito para reflejar el código real: stack, tabla de variables de .env, tabla de estados NVD, cómo ejecutar las pruebas y una sección «Limitaciones conocidas».

- install.sh instala iproute2, copia .env.example a .env y termina indicando el comando de arranque (sudo venv/bin/python3 app.py).

- Se retiraron del repositorio dos informes PDF generados sobre la red real del autor (contenían IP y MAC de equipos), y .gitignore ahora ignora reports/\*.pdf salvo el informe de ejemplo.

- Por decisión del equipo se conservaron crear_estructura.sh y static/js/dashboard.js.

# 4. Hallazgo de rendimiento: la latencia de NVD era IPv6

## 4.1 Síntoma

Al probar la cadena completa, una sola consulta a NVD podía tardar alrededor de 540 s y un análisis completo llegó a 1099 s. Esto no era lentitud de NVD ni límite de uso: el mismo servidor respondía en menos de un segundo con otras herramientas.

## 4.2 Causa

La red del autor no tiene IPv6 funcional (el mismo problema que ya había afectado a apt en la bitácora del 30 de agosto). Python resolvía el nombre de NVD, intentaba primero la dirección IPv6, esperaba a que agotara el tiempo y solo después pasaba a IPv4, y esto se repetía en cada consulta y en cada reintento.

## 4.3 Mediciones

| **Prueba**                                  | **Resultado**                                                 |
|---------------------------------------------|---------------------------------------------------------------|
| curl por IPv4 hacia la API de NVD           | 0.587 s en total (DNS 0.026 s, conexión 0.069 s, TLS 0.326 s) |
| Python forzando IPv4                        | 0.6 s                                                         |
| Python forzando IPv6                        | falló tras 100.1 s                                            |
| Python con el orden por defecto del sistema | 100.7 s                                                       |
| Después de la corrección: una consulta      | 1.1 s                                                         |
| Análisis completo de extremo a extremo      | 21 s (antes: 1099 s)                                          |

## 4.4 Solución

La consulta usa IPv4 primero mediante un adaptador HTTP propio (HTTPAdapter con dirección de origen 0.0.0.0) y, si falla, vuelve al orden normal del sistema, de modo que en redes con IPv6 funcional nada se rompe. Se puede desactivar con NVD_IPV4=0. Toda la red de este módulo pasa por una única función (\_peticion_get), lo que facilita probarla.

\# .env  
NVD_API_KEY=\<tu clave, solo en .env, nunca en el repositorio\>  
NVD_IPV4=1 \# 0 para desactivar el intento IPv4 primero

# 5. Verificación de extremo a extremo con NVD real

Para comprobar que el CVE llega hasta el dashboard y el PDF sin datos simulados, se levantó en la propia máquina un servicio de prueba en 127.0.0.1:8080 que anuncia «Apache/2.4.49», y se ejecutó la cadena completa con Nmap real y la API real de NVD.

| **Dato**              | **Resultado**                                                                                            |
|-----------------------|----------------------------------------------------------------------------------------------------------|
| Servicio analizado    | Servicio local de prueba que se anuncia como Apache 2.4.49 (no es un Apache real ni un equipo de la red) |
| CPE usado             | El reportado por Nmap, convertido a CPE 2.3                                                              |
| CVE devueltos por NVD | 100 (incluye CVE-2021-41773)                                                                             |
| CVSS máximo           | 9.8                                                                                                      |
| Nivel de riesgo       | Crítico                                                                                                  |
| Visibilidad           | Se ve en el dashboard y en el PDF                                                                        |
| Duración del análisis | 21 s                                                                                                     |

**Alcance de la prueba:** valida el código de extremo a extremo (Nmap, CPE, NVD, riesgo, base de datos, dashboard y PDF), pero el servicio es simulado. La prueba desde la interfaz web sobre una red real sigue pendiente (Sección 10).

# 6. Pruebas automáticas

Resultado en el equipo del autor: 115 pruebas pasan, sin acceso a red (antes eran 20 el 18 de septiembre).

| **Archivo**                  | **Casos** | **Qué cubre**                                                                         |
|------------------------------|-----------|---------------------------------------------------------------------------------------|
| test_vulnerability_lookup.py | 21        | Consulta a NVD simulada: reintentos, errores, caché, clave de API, IPv4 con respaldo. |
| test_normalizer.py           | 19        | Conversión de CPE 2.2 a 2.3, tabla curada y casos sin CPE.                            |
| test_flujo_completo.py       | 14        | Análisis completo con Nmap y NVD simulados, hasta la base de datos.                   |
| test_risk_engine.py          | 13        | Motor de riesgo contextual y niveles.                                                 |
| test_app_rutas.py            | 11        | Rutas de la aplicación (vistas, estado, PDF y JSON).                                  |
| test_errores.py              | 11        | Mensajes claros para cada tipo de fallo.                                              |
| test_network_manager.py      | 8         | Detección de interfaz, IP y gateway.                                                  |
| test_estados_nvd.py          | 7         | Determinación de los cinco estados y sus etiquetas.                                   |
| test_report_generator.py     | 7         | HTML del informe: estado, sub-tabla de CVE y escape de texto.                         |
| test_migracion.py            | 3         | Migración automática de columnas.                                                     |
| test_models.py               | 1         | Modelos de la base de datos.                                                          |
| **Total**                    | **115**   |                                                                                       |

# 7. Estado de la Fase II

Criterios de cierre definidos para esta etapa y su resultado:

- **\[Completado\]** Un CVE real es visible en el dashboard y en el PDF (prueba de extremo a extremo de la Sección 5).

- **\[Completado\]** Un fallo de NVD se distingue de «Sin CVE en NVD» (cinco estados, Sección 3.3).

- **\[Completado\]** Las 115 pruebas pasan sin conexión a internet.

- **\[Completado\]** Los análisis fallidos muestran un error claro y quedan registrados en el historial.

- **\[Completado\]** Repositorio limpio y README alineado con el código.

- **\[Completado\]** Diagnóstico del hallazgo de CVSS en 0.0, que figuraba pendiente en la bitácora del 18 de septiembre.

- **\[Pendiente\]** Prueba manual desde la interfaz web sobre una red real con el código final.

En síntesis: el alcance definido para la Fase II (MVP) queda completo y el pendiente que bloqueaba el inicio de la Fase III está resuelto.

# 8. Limitaciones conocidas

- Los servicios sin versión no se pueden verificar contra NVD; se marcan «No verificado» y su riesgo se calcula solo por contexto (puerto y protocolo).

- Las respuestas de NVD no se paginan: en la prueba el total reportado (100) coincidió con lo devuelto, pero un producto con más de una página de CVE se vería recortado.

- Algunas versiones, como «OpenSSH 7.4p1», pueden no coincidir con el formato de versión de NVD.

- La tabla curada de productos es corta; los productos fuera de ella dependen de que Nmap entregue un CPE.

- El factor «tipo de dispositivo» del motor de riesgo no está implementado.

- La interfaz carga tipografías desde Google Fonts, por lo que sin internet usa tipografía de respaldo.

- Persisten avisos de obsolescencia de SQLAlchemy (Query.get()) que no afectan el funcionamiento.

# 9. Herramientas y entorno utilizados hoy

| **Herramienta**                      | **Uso en la sesión**                                                                                                |
|--------------------------------------|---------------------------------------------------------------------------------------------------------------------|
| Ubuntu 26 / Python 3.14              | Entorno actual del autor (el 30 de agosto era Ubuntu 24.04 y Python 3.12.3); conviene registrarlo en la metodología |
| Flask 2.3.3 / Flask-SQLAlchemy 3.1.1 | Aplicación web y base de datos SQLite                                                                               |
| python-nmap 0.7.1 + XML de Nmap      | Escaneo y extracción de CPE desde el XML crudo                                                                      |
| requests 2.31 / urllib3 2.x          | Consulta a la API de NVD (con adaptador IPv4)                                                                       |
| API pública de NVD (v2.0) con clave  | Fuente de CVE y CVSS; clave guardada en .env                                                                        |
| WeasyPrint 60.1 / python-dotenv      | Informes PDF y lectura de .env                                                                                      |
| pytest                               | 115 pruebas automáticas                                                                                             |
| Git y GitHub                         | Una rama y un pull request por etapa (#1 a #8)                                                                     |
| curl y scripts de diagnóstico        | Mediciones de latencia IPv4/IPv6 y consultas de prueba a NVD (fuera del repositorio)                                |

# 10. Próximos pasos

- Incorporar al documento del proyecto de grado los cambios descritos en esta bitácora (normalizador, estados de verificación, limitaciones y la evidencia de la Sección 5).

- Hacer una prueba manual desde la interfaz web (sudo venv/bin/python3 app.py) sobre una red real, con la clave de NVD configurada.

- Definir la lista definitiva de dispositivos y vulnerabilidades controladas de la red de prueba, pendiente desde el 30 de agosto y necesaria antes de la Fase III.

- Evaluar la paginación de respuestas de NVD y ampliar la tabla curada de productos.
