# Detección y caza — Grupo 03

**Integrantes:** Facundo Daza (Shelldaza) y Irineo Hiriart (irineoHiriart215).  
**Fecha de análisis:** 28/10/2026.  
**Fuente:** `laboratorio/logs/audit.log`, log sintético proporcionado por la cátedra. Las horas indicadas están en UTC.

## 1. Hipótesis de caza

Entre las 09:42 y las 09:45 UTC del 27/10/2026, un posible atacante podría haber utilizado procesos de Apache, Node.js o Python para ejecutar shells, reconocer el sistema e intentar descargar archivos. Esperamos encontrar relaciones padre-hijo inusuales y correlacionar sus PID, argumentos y horarios.

## 2. Hallazgos en `audit.log`

| Línea / timestamp UTC | Host | Padre → hijo | ¿Anómalo? | Por qué |
|---|---|---|---|---|
| 6–7 / 09:42:17–18 | web01 | apache2 → sh → id | Sí | Apache ejecuta un shell que consulta la identidad del usuario. Compatible con reconocimiento posterior a una ejecución de comandos. |
| 9–10 / 09:43:03–04 | api01 | node → sh → curl | Sí | Node ejecuta un shell y luego `curl` hacia una URL. El PID 601 vincula ambos eventos. Indica un intento de acceso a un recurso remoto; no demuestra descarga exitosa. |
| 14 / 09:44:22 | web01 | apache2 → wget | Sí | Apache inicia directamente una herramienta de descarga, comportamiento inesperado para el portal sin una función legítima que lo justifique. |
| 16–17 / 09:45:10–11 | svc01 | python → sh → uname | Sí | Python ejecuta un shell que consulta información del sistema. El PID 704 permite reconstruir la cadena. |
| 8, 13 y 21 / 09:42:40, 09:44:10 y 09:49:00 | db01 | sshd → bash | No concluyente | Puede corresponder a sesiones administrativas legítimas. Requiere correlación con registros de autenticación. |

**¿Hay compromiso?** Indeterminado con esta única fuente, aunque existen indicios fuertes de posible ejecución no autorizada en `web01`, `api01` y `svc01`. Corresponde investigarlos como posibles incidentes y preservar evidencia.

Los eventos registran ejecución de shells y herramientas de reconocimiento o acceso remoto. No identifican el acceso inicial, no prueban explotación de PHP2Shell o Node2Shell y no confirman persistencia, exfiltración ni éxito de las conexiones.

Al ser un registro sintético, estos hallazgos pertenecen al escenario del ejercicio: no demuestran que los contenedores locales hayan sido comprometidos.

## 3. Falsos positivos

La línea 8 muestra `sshd → bash` en `db01`. Puede ser una sesión de administración autorizada.

Para distinguirla de una intrusión necesitamos usuario, IP de origen, método de autenticación, horario autorizado y registro de la tarea realizada. Las líneas 13 y 21 requieren la misma validación.

También una aplicación puede lanzar herramientas externas por una función legítima. Cualquier excepción debe estar documentada y restringida al proceso, ruta y contexto esperados.

## 4. Regla propuesta para Node.js

**Fuente necesaria:** eventos de creación de procesos que incluyan nombre del proceso padre y del hijo.

**Condición lógica:**

`ppid_comm == "node" AND comm IN ("sh", "bash", "curl", "wget")`

**Qué observa:** creación directa de shells o herramientas de acceso remoto desde Node.js.

**Resultado sobre este log:** dispara en la línea 9, donde `node` crea `sh`. La línea 10 aporta contexto: ese shell crea `curl`. La regla directa no detecta por separado esa segunda relación porque su padre es `sh`.

**Respuesta:** revisar argumentos, árbol de procesos, conexiones y función de la aplicación. Preservar los registros y evaluar aislamiento si la ejecución no tiene justificación.

**Falsos positivos:** aplicaciones que utilizan procesos externos para tareas autorizadas.

**Falsos negativos:** ejecución maliciosa dentro del propio proceso Node sin crear hijos, uso de otras herramientas o nombres de proceso, y descendientes indirectos. Para mejorar la cobertura, correlacionar el árbol completo y agregar telemetría de red.

## 5. Limitaciones del log

- No contiene usuario, UID ni IP de origen del acceso inicial.
- No incluye solicitudes HTTP para vincular un comando con una petición.
- No muestra códigos de salida ni resultados: ejecutar `curl` o `wget` no prueba que la conexión funcionara.
- No registra cambios de archivos, persistencia ni contenido transferido.
- Solo cubre de 09:40:01 a 09:49:00 UTC del 27/10/2026 (menos de 10 minutos): sin retención histórica ni línea base para saber qué es normal.
