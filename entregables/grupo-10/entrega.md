# Entregable — TP PHP2Shell / Node2Shell

**Grupo:** 10  
**Fork del grupo:** benjaelizalde/goys-2026-tp-vulnerabilidades  
**Rama:** `grupo-10`  
**Fecha:** viernes 30/10/2026

| Integrante | Usuario de GitHub | Rol en el TP |
|---|---|---|
| Moscuzza, Vicente | VicenteMoscuzza | Inventario y Exposición |
| Rodrigo Capre | RodrigoCapreDev | Priorización y cambios/parche |
| Di Grappa, Emiliano| EmiiDG | Detección |
| Alvite, Damian | DamiiAlvite | Contención |
| Elizalde, Benjamin | benjaelizalde | Comunicación e Integración |

---

## 1. Inventario

| Activo | Versión | ¿Expuesto a Internet? | ¿Procesa contenido no confiable? | ¿Afectado? | Evidencia |
|--------|---------|:---------------------:|:--------------------------------:|:----------:|-----------|
| Portal PHP (`php-lab`) | PHP 8.3.35 NTS, Apache con mod_php (SAPI apache2handler) | No en el lab; sí asumido en producción | Sí (HTTP, puerto 80 interno) | Sí. PHP 8.3.35 es anterior al fix 8.3.36 (versions.env) y corre bajo Apache mod_php, el caso de mayor riesgo según recursos/contexto.md; no depende de la app. Explotación real confirmada, en CISA KEV desde el 26/10/2026 | `capturas/inventario.txt` (salida de `inventario.sh`), `capturas/inventario-php-apache.txt` (`php -v` y `apache2ctl -M` con `php_module (shared)`), `docker-compose.yml` (imagen `php:8.3.35-apache`) |
| API Node.js (`node-lab`) | Node v22.23.3 (bookworm-slim), Brotli 1.1.0 aportado por el runtime, sin paquete externo | No en el lab; sí asumido en producción | Sí (HTTP, puerto 3000 interno) | Sí. Node 22.23.3 es anterior al fix 22.23.4 y su Brotli 1.1.0 está en el rango afectado (1.0.3–1.2.0). El endpoint POST /decode (server.js, líneas 19-25) recibe un body con Content-Encoding br y lo pasa a zlib.brotliDecompressSync, o sea que el decoder procesa entrada no confiable. Explotación real sin confirmar al 27/10; RCE demostrado solo en laboratorio | capturas/inventario.txt, capturas/inventario-brotli.txt, laboratorio/versions.env, recursos/contexto.md, docker-compose.yml |
| Servicio Python (`py-lab`) | Python 3.11.18, paquete brotli 1.0.9 (fijado por `BROTLI_VERSION`) | No en el lab; sí asumido en producción | Sí (HTTP, puerto 8000 interno) | Sí. brotli 1.0.9 está en el rango afectado (1.0.3–1.2.0) y es anterior al fix 1.2.1. app.py (líneas 34-36) aplica brotli.decompress al body cuando Content-Encoding es br, o sea que el decoder procesa entrada no confiable. Explotación real sin confirmar al 27/10. | capturas/inventario.txt, capturas/inventario-brotli.txt, laboratorio/versions.env, recursos/contexto.md, docker-compose.yml |

**Supuestos de exposición:** en el laboratorio no hay `ports:` publicados y la red `labnet` es `internal: true`, por lo que ningún servicio es alcanzable desde Internet ni desde el host; todo se opera con `docker compose exec`. Para el análisis de riesgo se asume un despliegue real equivalente, con los tres servicios detrás de un proxy o balanceador que expone HTTP a Internet y reenvía contenido controlado por el usuario. El compose no incluye ningún proxy, así que ese supuesto no está verificado.

---

## 2. Priorización y decisión

| Activo | CVSS | Explotación real | Exposición | Criticidad | Decisión y plazo |
|--------|:----:|:----------------:|:----------:|:----------:|------------------|
| Portal PHP (`php-lab`) | 9.2 | Confirmada; ambos CVE están en CISA KEV | No expuesto en el laboratorio; se asume expuesto detrás de un proxy en producción | Crítica: portal web y Apache mod_php | Mitigación inmediata y parche a PHP 8.3.36 |
| API Node.js (`node-lab`) | 9.2 | No confirmada; RCE demostrado en laboratorio | No expuesto en el laboratorio; exposición productiva asumida y no verificada | Alta: API que descomprime cuerpos Brotli no confiables | Parche a Node 22.23.4 dentro de 24 h; mientras tanto, restringir exposición y monitorear |
| Servicio Python (`py-lab`) | 9.2 | No confirmada; RCE demostrado en laboratorio | No expuesto en el laboratorio; exposición productiva asumida y no verificada | Alta, pero menor que PHP por ser servicio interno | Actualizar Brotli a 1.2.1 y mantenerlo interno |

**Justificación:** PHP se prioriza primero porque combina CVSS 9.2, explotación real
confirmada, presencia en CISA KEV y el mayor riesgo asociado a Apache mod_php. Node
queda segundo porque recibe contenido Brotli no confiable y tiene RCE demostrado en
laboratorio, aunque no hay explotación real confirmada. Python queda tercero por ser
interno en el laboratorio y no tener explotación confirmada. La confirmación de un
proxy expuesto, una alerta de explotación o datos críticos en Node/Python elevaría su
prioridad; una prueba de que PHP no recibe tráfico no confiable la reduciría.

---

## 3. Mitigación, parche y reversión

| Fecha/hora | Activo | Cambio | Antes | Después | Reversión |
|------------|--------|--------|-------|---------|-----------|
| 29/10/2026 | PHP (`php-lab`) | Mitigación provisoria: editar `laboratorio/php/php.ini`, poner `session.upload_progress.enabled = 0` y reiniciar | PHP 8.3.35; `session.upload_progress.enabled=1` | PHP 8.3.35; `session.upload_progress.enabled=0`; contenedor healthy | Restaurar `session.upload_progress.enabled = 1` y reiniciar `php-lab` |
| 29/10/2026 | PHP (`php-lab`) | Actualizar imagen con `PHP_TAG=8.3.36-apache` | PHP 8.3.35 | PHP 8.3.36; contenedor healthy | Volver a `PHP_TAG=8.3.35-apache` y recrear el servicio |
| 29/10/2026 | Python (`py-lab`) | Actualizar dependencia con `BROTLI_VERSION=1.2.1` | Brotli 1.0.9 | Brotli 1.2.1; contenedor healthy | Volver a `BROTLI_VERSION=1.0.9` y recrear el servicio |
| 29/10/2026 | Node.js (`node-lab`) | Actualizar imagen con `NODE_TAG=22.23.4-bookworm-slim` | Node 22.23.3 | Node 22.23.4; `process.versions.brotli=1.1.0`; contenedor healthy | Volver a `NODE_TAG=22.23.3-bookworm-slim` y recrear el servicio |

**Prueba funcional mínima:** se verificó que los tres contenedores quedaron `healthy`.
PHP pudo abrir el puerto 80 local, Node respondió correctamente a una solicitud HTTP
en `/` y Python respondió HTTP `200` en `/`.

**Qué no se pudo probar:** no se verificó la exposición productiva detrás de un proxy,
porque el laboratorio no incluye ese componente. El primer intento de build de Node
falló por `UNABLE_TO_VERIFY_LEAF_SIGNATURE`; después de cambiar de red, el build se
completó correctamente sin desactivar la verificación TLS.

---

## 4. Detección y caza

**Hipótesis:** Buscamos procesos anómalos o de evasión lanzados por los procesos web (`apache2`, `node`, `python`) entre las 09:40 y las 09:46 UTC del 27/10/2026, específicamente intérpretes de comandos (`sh`, `bash`) o herramientas de red (`curl`, `wget`) que evidencien ejecución remota de código o descarga de payloads.

**Hallazgos en `audit.log`:**

| Línea / timestamp | Host | Padre → hijo | ¿Anómalo? | Por qué |
|-------------------|------|--------------|:---------:|---------|
| 09:42:17–09:42:18 | `web01` | `apache2` → `sh` → `id` | Sí | Un worker de Apache engendra un shell para ejecutar reconocimiento de privilegios (`id`). Indicio claro de explotación RCE en PHP. |
| 09:43:03–09:43:04 | `api01` | `node` → `sh` → `curl` | Sí | El runtime de Node.js engendra `sh` e intenta invocar `curl` hacia una IP aparente. |
| 09:44:22 | `web01` | `apache2` → `wget` | Sí | Apache ejecuta directamente `wget` intentando descargar un payload secundario. |
| 09:45:10–09:45:11 | `svc01` | `python` → `sh` → `uname` | Dudoso / Revisar | Python ejecuta reconocimiento de sistema (`uname -a`). Anómalo para un backend salvo tareas diagnósticas. |

**¿Hay compromiso?** **Indeterminado / Indicios de intrusión sin confirmación plena.** Se observan secuencias de ejecución anómalas e intentos de reconocimiento/descarga (`id`, `curl`, `wget`), pero el log sintético no evidencia si los comandos tuvieron éxito, el entorno carece de salida a Internet y las IPs pertenecen a bloques de documentación (RFC 5737).

**Regla propuesta para Node.js:**
- *Condición:* `ppid_comm == "node"` y `comm in ["sh", "bash", "curl", "wget"]`.
- *Observa:* Intérpretes de comandos y utilidades de transferencia invocados por el runtime de Node.js.
- *Falsos negativos:* Ejecución directa de binarios sin pasar por shell, conexiones de red o exfiltración realizadas nativamente desde el código JavaScript (sin invocar subprocesos del OS), o herramientas invocadas por nietos en la jerarquía (ej. `node` → `sh` → `curl` donde `curl` tiene PPID de `sh`).

**Limitaciones del log:**
- Ausencia de contexto de usuario (UID/GID) e IP de origen de la solicitud HTTP.
- Ventana temporal acotada sin trazabilidad histórica ni retención.
- Falta de telemetría de red para verificar si hubo conexiones establecidas o exfiltración efectiva.
- Sin logs de aplicación (Apache/Node access y error logs) para correlacionar solicitudes con procesos.

_Detalle completo en [`deteccion.md`](deteccion.md)._

---

## 5. Contención

| Control | Configuración | Evidencia | ¿Funciona? |
|---------|---------------|-----------|:----------:|
| Red sin salida | `networks.labnet.internal: true` en `docker-compose.yml` | `capturas/contencion-salida.txt` (prueba de HTTP saliente con timeout en los 3 servicios) | **Sí.** Evita que un RCE descargue payloads de segunda etapa (reverse shells, scripts, herramientas de post-explotación) o que exfiltre credenciales/datos a servidores C2 externos. |
| Usuario sin privilegios | `user: node` (uid 1000) en `node-lab`, `user: nobody` (uid 65534) en `py-lab`. En `php-lab` corre Apache con workers `www-data` (uid 33). | Salida de `docker compose exec [servicio] id` y `ps aux` en `capturas/contencion-compose-config.txt` | **Sí.** Si se compromete el proceso de la aplicación, el atacante queda contenido con permisos acotados, sin acceso a archivos de otros usuarios ni capacidad de modificar archivos del sistema o configuraciones globales. |
| Filesystem read-only | `read_only: true` con directorios volátiles y temporales en memoria (`tmpfs: /tmp`, `/var/run/apache2`, `/var/lock/apache2`, `/var/log/apache2`) | Intento de escritura `touch /test-ro` arroja `Read-only file system`; `capturas/contencion-compose-config.txt` | **Sí.** Impide que un atacante persista en el contenedor escribiendo web shells, binarios modificados, tareas programadas (cron) o troyanos en el sistema de archivos raíz. |
| Capabilities mínimas | `cap_drop: - ALL` en todos los servicios. `php-lab` añade únicamente las mínimas indispensables para Apache (`CHOWN`, `SETUID`, `SETGID`, `DAC_OVERRIDE`, `NET_BIND_SERVICE`) y `security_opt: no-new-privileges:true`. | `/proc/1/status` muestra `CapEff: 0000000000000000` en `node-lab`/`py-lab` y acotadas en `php-lab`; `capturas/contencion-compose-config.txt` | **Sí.** Bloquea técnicas de escalamiento de privilegios y ataques de escape del contenedor hacia el host (como montar filesystems, manipular interfaces de red con `NET_ADMIN` o rastrear memoria con `SYS_PTRACE`). |
| Límites de memoria/PIDs | `mem_limit: 256m` / `pids_limit: 100` (`php-lab`, `node-lab`), `mem_limit: 128m` / `pids_limit: 50` (`py-lab`) | Directivas verificadas en `capturas/contencion-compose-config.txt` | **Sí.** Mitiga denegaciones de servicio (DoS): exploits que provoquen memory corruption/leaks en el decoder Brotli o fork-bombs en PHP solo tiran su contenedor aislado y no saturan los recursos del host ni tumban otros servicios. |
| Rechazo de Brotli innecesario | Deshabilitar o filtrar cabecera `Content-Encoding: br` en proxy/WAF o descartar decompresión en endpoints donde no sea requerido por la lógica de negocio | Configuración a nivel proxy/WAF y código de aplicación (mitigación arquitectural previa al parche) | **Sí.** Reduce a cero la superficie de ataque de Node2Shell (CVE-2026-111497), ya que el decoder vulnerable de Brotli nunca llega a procesar contenido provisto por usuarios no confiables. |

**Prueba de salida a Internet:**
Se ejecutó `./scripts/verificar-contencion.sh` realizando solicitudes salientes hacia `http(s)://example.com` con un timeout de 3 segundos desde los tres contenedores:
- **`php-lab`:** arrojó `SIN SALIDA` (timeout al intentar resolver y conectar mediante `file_get_contents`).
- **`node-lab`:** arrojó `SIN SALIDA TypeError` (fallo de red en `fetch` al no poder alcanzar gateway a Internet).
- **`py-lab`:** arrojó `SIN SALIDA URLError` (excepción de `urllib.request` por red inalcanzable).

La evidencia completa quedó registrada en `capturas/contencion-salida.txt` y la configuración en `capturas/contencion-compose-config.txt`. Ambos demuestran que la red `labnet` con `internal: true` bloquea eficazmente cualquier canal de salida directa a Internet.

---

## 6. Conclusión (5 líneas)

En las primeras 2 horas no hubiéramos intentado parches de código apresurados en caliente, sino aislar y contener la exposición: verificar el inventario frente a CISA KEV, bloquear el procesamiento innecesario de compresión Brotli en el proxy y desactivar `session.upload_progress.enabled` en PHP de inmediato.
Con esa contención perimetral activa, habríamos evitado la interrupción del servicio mientras se preparaban las imágenes corregidas.
Luego habríamos validado el entorno de pruebas, comprobando que las pruebas funcionales mínimas y el procedimiento de rollback estuvieran documentados antes de tocar producción.
En paralelo, habríamos desplegado monitoreo específico sobre procesos anómalos (`auditd`/EDR) para cazar shells hijos de los runtimes web sin depender de conjeturas.
Finalmente, habríamos establecido un canal de comunicación transparente hacia el comité y los clientes, informando medidas preventivas sin revelar vectores de ataque que beneficien a terceros.

---

## 7. Checklist antes de entregar

- [x] El laboratorio arrancó y los 3 servicios quedaron `healthy`.
- [x] Inventario con evidencia (versión, SAPI, configuración).
- [x] Matriz con decisión y plazo.
- [x] Parche aplicado y verificado; reversión documentada.
- [x] Al menos 3 controles de contención probados.
- [x] `deteccion.md` completo.
- [x] `informe.md` individual completo.
- [x] Sin claves, tokens ni placeholders.
- [x] Repo pusheado y PR abierto.
