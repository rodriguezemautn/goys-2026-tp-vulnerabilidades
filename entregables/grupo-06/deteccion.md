# Detección y caza — Grupo 06

**Integrantes:** VIJANDI IVAN, NICOLAS VALDES, FACUNDO OTERO, FRANCO PIETRANTUONO · **Fecha:** jueves 29/10/2026

---

## 1. Hipótesis de caza

Entre las 09:40 y las 09:50 UTC, buscar hijos `sh`, `bash`, `curl`, `wget` o `nc`
creados por `apache2`, `php-fpm`, `node` o `python`; se espera una cadena de
procesos con reconocimiento o conexión saliente desde un servicio.

---

## 2. Hallazgos en `audit.log`

| Línea / timestamp | Host | Padre → hijo | ¿Anómalo? | Por qué |
|---|---|---|---|---|
| 09:42:17–09:42:18 | web01 | `apache2 → sh → id` | Investigar | Un servidor web crea un shell y ejecuta reconocimiento de identidad (`id`). |
| 09:43:03–09:43:04 | api01 | `node → sh → curl` | **Sí** | Node.js lanza un shell que intenta conectarse a `198.51.100.7`; coincide con el patrón de Node2Shell. |
| 09:44:22 | web01 | `apache2 → wget` | **Sí** | `wget` descargando desde `198.51.100.9` es un hijo de un servicio web y puede indicar descarga de payload. |

**¿Hay compromiso?** **Indeterminado, con evidencia de ejecución sospechosa.** Las
cadenas `node → sh → curl` y `apache2 → wget` justifican contención e investigación.
El log es sintético y no demuestra que la descarga haya terminado ni que se haya
ejecutado un payload.

---

## 3. Falsos positivos

`sshd → bash` en `db01` (09:42:40 y 09:44:10) puede ser una sesión administrativa
legítima, y `python → sh → uname -a` en `svc01` (09:45:10–09:45:11) puede ser una
rutina de inventario. Se distinguen cruzando usuario, IP de origen, horario de
guardia, ticket de cambio y la línea de comandos completa.

---

## 4. Regla propuesta para Node.js

La regla observa la relación padre-hijo y los argumentos. Debe disparar cuando un
`node` cree directamente `sh`, `bash`, `curl`, `wget` o `nc`, y elevar la alerta si
se correlaciona una conexión saliente del mismo PID o contenedor.

```yaml
title: Node.js Spawns Shell Or Network Utility
id: 4f9d1c48-6d3c-4f37-9f3c-6e9a1f2c0d11
status: experimental
logsource:
  category: process_creation
detection:
  parent_node:
    ParentImage|endswith:
      - '/node'
      - '\node.exe'
  suspicious_child:
    Image|endswith:
      - '/sh'
      - '/bash'
      - '/curl'
      - '/wget'
      - '/nc'
      - '\sh.exe'
      - '\bash.exe'
      - '\curl.exe'
      - '\wget.exe'
      - '\nc.exe'
  condition: parent_node and suspicious_child
level: high
```

Puede tener falsos negativos si Node invoca la herramienta mediante un wrapper, una
ruta no contemplada, otro intérprete o un binario renombrado. Conviene normalizar el
árbol de procesos y correlacionar `execve` con telemetría de red.

---

## 5. Limitaciones del log

- No registra usuario, UID, contenedor, imagen, IP de origen/destino, puerto, resultado
  de la ejecución ni si la conexión fue bloqueada.
- No incluye hash, ruta completa, entorno, stdin/stdout, árbol completo ni eventos de
  red; no permite confirmar descarga, persistencia o exfiltración.
- Es un log sintético de una ventana de diez minutos, sin retención, secuencia de
  sesión ni línea base del comportamiento normal.
- Puede generar ruido por tareas de administración e inventario y perder wrappers,
  intérpretes alternativos o procesos renombrados.
