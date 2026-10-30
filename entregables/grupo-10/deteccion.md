# Detección y caza — Grupo 10

**Integrantes:** Di Grappa, Emiliano; Moscuzza, Vicente; Capre, Rodrigo; Alvite, Damián; Elizalde, Benjamín.  
**Fecha:** 29-10-26

---

## 1. Hipótesis de caza

Vamos a buscar procesos sospechosos lanzados por `apache2`, `node` o `python`, principalmente entre las 09:40 y las 09:46 UTC del 27/10/2026. Nos interesa encontrar shells (`sh` o `bash`) y herramientas como `curl` o `wget`, porque podrían indicar que una aplicación está ejecutando comandos que no forman parte de su funcionamiento normal.

---

## 2. Hallazgos en `audit.log`

| Línea / timestamp (UTC) | Host | Padre → hijo | ¿Anómalo? | Por qué |
|---|---|---|---|---|
| 09:42:17–09:42:18 | `web01` | `apache2` → `sh` → `id` | Sí | Apache ejecuta un shell que termina lanzando `id`. Puede ser un intento de ejecutar comandos desde el servidor web. |
| 09:43:03–09:43:04 | `api01` | `node` → `sh` → `curl` | Sí | Node.js ejecuta un shell que intenta usar `curl` contra una dirección externa aparente. |
| 09:44:22 | `web01` | `apache2` → `wget` | Sí | Aparece `wget` como hijo de Apache. Podría tratarse de un intento de descargar un archivo. |
| 09:45:10–09:45:11 | `svc01` | `python` → `sh` → `uname` | Dudoso | Python ejecuta `uname -a`. Puede ser una comprobación del sistema legítima, aunque en este contexto conviene revisarlo. |

### ¿Hay compromiso?

Por ahora, diríamos que **hay indicios de una posible intrusión, pero no se puede confirmar solo con este log**.

En `web01`, Apache lanza `sh` para ejecutar `id` y después aparece un `wget` asociado a Apache. En `api01`, Node.js lanza `sh` y este ejecuta `curl`. Son comportamientos que no esperaríamos normalmente de estos servicios y que habría que investigar.

En `svc01`, el comando `uname -a` también llama la atención, pero puede usarse para consultar información del sistema. Además, el log no demuestra que las descargas hayan terminado bien ni que los comandos hayan producido algún cambio.

Las direcciones `198.51.100.7` y `198.51.100.9` pertenecen a un rango reservado para ejemplos y documentación, por lo que no podemos afirmar que haya habido una conexión real con un servidor externo.

---

## 3. Falsos positivos

Un ejemplo es esta línea:

`2026-10-27T09:42:40Z host=db01 ppid=1001 ppid_comm=sshd pid=1002 comm=bash args="-bash"`

Puede parecer sospechosa porque aparece una consola `bash`, pero también puede ser una sesión normal de un administrador que se conectó por SSH.

Para saber si es legítima, habría que revisar quién inició sesión, desde qué IP, a qué hora y si tenía autorización para acceder al servidor. El log no incluye esos datos, así que no alcanza para decidirlo.

También puede ser legítimo que un servicio ejecute `uname -a` para revisar la versión del sistema. En ese caso, habría que compararlo con las tareas habituales de mantenimiento y con los registros de la aplicación.

---

## 4. Regla propuesta para Node.js

La regla sería generar una alerta cuando un proceso `node` lance alguno de estos procesos: `sh`, `bash`, `curl` o `wget`.

**Condición de la regla:**

```text
SI ppid_comm = "node"
Y comm ES "sh", "bash", "curl" o "wget"
ENTONCES generar una alerta
```

La regla busca detectar si una aplicación Node.js intenta ejecutar comandos del sistema o usar herramientas para descargar archivos. En el log, el caso que la activaría es el de `api01`, a las 09:43:03, cuando Node.js lanza `sh`. La línea siguiente muestra que ese shell ejecuta `curl`.

Un posible falso negativo es que el proceso use otra herramienta o haga la conexión directamente desde el código, sin ejecutar `sh`, `curl` ni `wget`. También puede pasar que la regla solo mire al padre inmediato: en la cadena `node` → `sh` → `curl`, `curl` tiene como padre a `sh`, no a `node`. Por eso conviene revisar el árbol completo de procesos.

La alerta no confirma por sí sola un ataque; sirve para identificar casos que necesitan revisión.

---

## 5. Limitaciones del log

El log sirve para ver algunos procesos y sus argumentos, pero tiene información incompleta:

- **Usuario:** no muestra con qué usuario se ejecutó cada proceso ni qué permisos tenía.
- **IP de origen:** no permite saber quién hizo la petición que pudo haber iniciado la actividad ni desde dónde se conectó una persona por SSH.
- **Retención:** solo tenemos un fragmento de unos minutos. No sabemos qué pasó antes o después ni cuánto tiempo se guardan los registros.
- **Ruido:** algunos comandos pueden ser legítimos, por ejemplo los usados para mantenimiento o diagnóstico. Hace falta revisar el contexto antes de marcar todo como ataque.
- **Resultado de los comandos:** ver `curl` o `wget` no demuestra que la descarga haya funcionado.
- **Falta de registros de red:** no tenemos información para confirmar si hubo conexiones, qué datos se enviaron o si se llegó a otro equipo.
- **Contexto de la aplicación:** no aparecen las peticiones HTTP ni los errores de Apache o Node.js que permitan relacionar la actividad con una solicitud concreta.
- **Árbol de procesos:** el log ayuda a reconstruir la relación entre procesos, pero no alcanza para conocer todo lo que ocurrió ni para confirmar por qué se lanzaron.

Para investigar mejor, revisaríamos también los logs de Apache y de la API, los accesos SSH y los registros de red. Con esa información sería más fácil distinguir una tarea legítima de una posible ejecución no autorizada.
