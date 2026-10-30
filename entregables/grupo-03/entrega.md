# Entregable — TP PHP2Shell / Node2Shell

**Grupo:** 03  
**Fork:** https://github.com/Shelldaza/goys-2026-tp-vulnerabilidades  
**Rama:** `grupo-03`  
**Fecha:** 29/10/2026

| Integrante | GitHub | Rol |
|---|---|---|
| Facundo Daza | Shelldaza | Detección y cambios/parche |
| Irineo Hiriart | irineoHiriart215 | Inventario y contención/comunicación |

## 1. Inventario

Estado inicial, anterior al parche. La clasificación de versiones afectadas corresponde al material de la cátedra.

| Activo | Versión inicial | ¿Expuesto a Internet? | ¿Procesa contenido no confiable? | ¿Afectado? | Evidencia |
|---|---|---|---|---|---|
| Portal PHP | PHP 8.3.35 con Apache, SAPI `apache2handler` | No | Sí, solicitudes y archivos enviados al formulario | Sí, según el TP. Progreso de subida habilitado | [Inventario](capturas/01-inventario-antes.txt), [módulo PHP](capturas/02-sapi.txt) y [respuesta web](capturas/08-portal-tras-mitigacion.txt) |
| API Node.js | Node 22.23.3 con Brotli embebido 1.1.0 | No | Sí, cuerpos de solicitudes en la ruta de decodificación | Sí, según la versión de Node indicada en el TP | [Arranque e inventario](capturas/06-arranque-facundo.txt) |
| Servicio Python | Python 3.11.18 y Brotli 1.0.9 | No | Sí, cuerpos que pueden estar comprimidos con Brotli | Sí, por la versión de Brotli indicada en el TP | [Arranque e inventario](capturas/06-arranque-facundo.txt) |

**Exposición:** los tres servicios están en una red Docker interna, sin puertos publicados. No hay un proxy público en este laboratorio. Los contenedores pueden comunicarse entre sí.

**SAPI:** el comando `php -v` consulta PHP desde la terminal y muestra CLI. El portal web informa `apache2handler`, que es la SAPI relevante para analizar el servicio Apache.

## 2. Priorización y decisión

CVSS y explotación se toman de la consigna. La criticidad es un supuesto del ejercicio, ya que no contamos con un caso de negocio asignado.

| Activo | CVSS | Explotación real | Exposición | Criticidad supuesta | Decisión y plazo |
|---|---|---|---|---|---|
| Portal PHP | 9.2 | Confirmada y en KEV según la consigna | Red interna | Alta | Primero mitigar y después parchear. Objetivo: 45 minutos |
| API Node.js | 9.2 | Sin confirmación en el escenario, con demostración en laboratorio | Red interna | Media | Actualizar Node y probar la API. Objetivo: 75 minutos |
| Servicio Python | 9.2 para la falla de Brotli | Sin confirmación en el escenario, con demostración en laboratorio | Red interna | Media | Actualizar Brotli y probar el servicio. Objetivo: 90 minutos |

**Justificación:** PHP tiene prioridad por la explotación real conocida. Node y Python también deben corregirse. El orden entre ambos es provisional porque no hay evidencia suficiente para distinguir su impacto.

Los plazos son objetivos desde el inicio de la respuesta. En la práctica, el script actualizó los tres servicios en una misma operación.

**Qué cambiaría el orden:** detectar compromiso, exposición a Internet o acceso a datos críticos. Ante indicios de ataque, evaluaríamos aislar el servicio antes de parchearlo.

## 3. Mitigación, parche y reversión

Horarios del 29/10/2026, UTC−03:00.

| Inicio registrado | Activo | Cambio | Antes | Después | Reversión documentada |
|---|---|---|---|---|---|
| 22:28:57 | PHP | Deshabilitar progreso de subida en `php/php.ini` y reiniciar | `session.upload_progress.enabled=1` | Valor `0`, portal funcionando | Restablecer `1` y reiniciar. Retira la mitigación |
| 22:31:48 | PHP | Ejecutar `./scripts/parchear.sh` | 8.3.35 | 8.3.36, manteniendo el valor `0` | Recrear con la imagen anterior, conservando mitigación y aislamiento |
| Misma operación | Node | Actualizar mediante el script | 22.23.3 | 22.23.4 | Recrear con la imagen anterior bajo aislamiento |
| Misma operación | Python/Brotli | Actualizar mediante el script | Brotli 1.0.9 | Brotli 1.2.1 | Recrear con la imagen anterior bajo aislamiento |

**Comandos aplicados**, desde `laboratorio`:

```bash
# Después de cambiar el valor a 0 en php/php.ini
docker compose restart php-lab

# Actualización de los tres servicios
./scripts/parchear.sh

# Consulta de versiones y configuración
./scripts/inventario.sh
```

Evidencias: [mitigación](capturas/07-mitigacion-php.txt), [portal tras mitigación](capturas/08-portal-tras-mitigacion.txt) y [parche](capturas/09-parche.txt).

**Prueba funcional posterior, 22:33:16:**

| Prueba | Resultado |
|---|---|
| `docker compose ps` | Los tres servicios `healthy` |
| GET del portal PHP | HTML del portal con PHP 8.3.36, SAPI `apache2handler` y mitigación en `0` |
| GET de la API Node | HTTP 200, Node 22.23.4 y Express 5.3.0 |
| GET del servicio Python | HTTP 200, Python 3.11.18 y Brotli 1.2.1 |

Las consultas se hicieron desde los contenedores a sus rutas locales: PHP en el puerto 80, Node en 3000 y Python en 8000.

Evidencia: [pruebas posteriores](capturas/10-funcional-despues.txt).

El string Brotli de Node siguió en `1.1.0`. Según la guía, puede conservarse por el backport de la corrección. Para este TP se verifica la versión corregida de Node.

**Reversión de versiones, documentada pero no ejecutada:**

```bash
PHP_TAG=8.3.35-apache \
NODE_TAG=22.23.3-bookworm-slim \
BROTLI_VERSION=1.0.9 \
docker compose --env-file versions.env up -d --build --wait
```

Volver atrás recuperaría versiones vulnerables. Solo se contempla ante una incompatibilidad y manteniendo el laboratorio aislado.

**Precaución de operación:** `parchear.sh` no modifica `versions.env`. Un arranque posterior con la configuración inicial puede recuperar las versiones anteriores. Para levantar el estado parcheado debe utilizarse el script de parcheo.

**Límites:** se probaron las rutas principales. No se probaron subidas, descompresión de cuerpos Brotli, carga, agotamiento de recursos ni reversión efectiva. No se ejecutaron exploits ni PoCs.

## 4. Detección y caza

**Hipótesis:** identificar procesos Apache, Node o Python que lancen shells o herramientas de acceso remoto. Correlacionar padre, hijo, PID, horario y argumentos.

| Líneas del log | Host | Cadena | Interpretación |
|---|---|---|---|
| 6–7 | web01 | apache2 → sh → id | Shell y reconocimiento del usuario |
| 9–10 | api01 | node → sh → curl | Intento de acceso a un recurso remoto |
| 14 | web01 | apache2 → wget | Herramienta de descarga iniciada por Apache |
| 16–17 | svc01 | python → sh → uname | Shell y reconocimiento del sistema |
| 8, 13 y 21 | db01 | sshd → bash | Posibles sesiones administrativas legítimas |

**¿Hay compromiso?** Indeterminado. Hay indicios para investigar posible ejecución no autorizada en tres hosts, pero el registro no demuestra el acceso inicial, una descarga exitosa ni la vulnerabilidad utilizada.

El log es sintético. No demuestra un ataque contra los contenedores locales.

**Regla propuesta para Node:**

```text
ppid_comm == "node" AND comm IN ("sh", "bash", "curl", "wget")
```

Detecta la línea 9. Puede generar alertas por funciones legítimas que ejecuten herramientas externas. Puede perder descendientes indirectos, otros ejecutables o actividad maliciosa dentro del propio proceso.

**Limitaciones:** faltan usuario, IP de origen del acceso inicial, solicitudes HTTP, códigos de salida y cambios en archivos. La ventana del log es menor a diez minutos. La ausencia de otras señales no descarta compromiso.

Análisis completo: [deteccion.md](deteccion.md). Salida del script: [04-detectar.txt](capturas/04-detectar.txt).

## 5. Contención

Se inspeccionó la configuración efectiva después del parche y se realizaron pruebas de salida a Internet.

| Control | Resultado verificado | Daño que reduce y límite |
|---|---|---|
| Red interna | `internal=true`, sin puertos publicados y solicitudes externas fallidas en los tres servicios | Restringe acceso externo y descarga de recursos. Permite comunicación entre contenedores |
| Usuarios | Node usa `node`, Python usa `nobody`. Apache tiene un principal `root` y workers `www-data` | Reduce permisos en Node, Python y workers PHP. No permite afirmar que todo PHP corre sin privilegios |
| Filesystem read-only | Activado en los tres contenedores | Restringe cambios en la raíz. Los espacios temporales siguen siendo escribibles |
| Capabilities | Node y Python sin capabilities añadidas. PHP recupera cinco después de `cap_drop=ALL` | Reduce operaciones privilegiadas. PHP conserva permisos adicionales |
| Memoria y procesos | PHP/Node: 256 MiB y 100 PIDs. Python: 128 MiB y 50 PIDs | Acota consumo de recursos. No se probó agotamiento |
| Nuevos privilegios | `no-new-privileges:true` en los tres | Restringe adquisición de privilegios. No elimina los existentes |
| Rechazo de Brotli innecesario | No implementado | Se propone para rutas que no necesiten Brotli, previa prueba de compatibilidad |

PHP conserva `CHOWN`, `DAC_OVERRIDE`, `NET_BIND_SERVICE`, `SETGID` y `SETUID`.

Evidencia de configuración efectiva y procesos: [12-controles-efectivos.txt](capturas/12-controles-efectivos.txt). No se realizaron pruebas de escritura ni de evasión de estos controles.

**Salida a Internet, 22:33:27:** PHP mostró `SIN SALIDA`, Node `SIN SALIDA TypeError` y Python `SIN SALIDA URLError`.

Evidencia: [11-contencion-despues.txt](capturas/11-contencion-despues.txt).

Estos resultados respaldan el aislamiento junto con la configuración. No prueban por sí solos el bloqueo de todos los destinos y protocolos.

**Apagado y limpieza, desde las 22:34:12:**

```bash
docker compose --env-file versions.env down -v
docker compose --env-file versions.env ps -a
```

Se eliminaron los tres contenedores y la red. La consulta posterior quedó sin servicios.

Evidencia: [13-limpieza.txt](capturas/13-limpieza.txt).

## 6. Conclusión - cinco líneas

Guardaríamos el inventario y la exposición antes de modificar servicios.  
Priorizaríamos por explotación real e impacto, además del CVSS.  
Prepararíamos mitigación, parche y reversión con responsables definidos.  
Verificaríamos versiones, funcionamiento y controles después de cada cambio.  
Comunicaríamos los resultados y las pruebas que no pudimos realizar.

## 7. Checklist

- [x] Tres servicios `healthy` antes y después del parche.
- [x] Inventario con versiones, SAPI y configuración.
- [x] Priorización con justificación y plazos.
- [x] Mitigación y parche con evidencia.
- [x] Prueba funcional mínima y reversión documentada.
- [x] Controles efectivos inspeccionados y salida externa probada.
- [x] `deteccion.md` completo.
- [x] Laboratorio apagado y eliminado.
- [x] Informe individual completo.
- [x] Revisión final de archivos y secretos.
- [x] Cambios finales pusheados y PR abierto.

[Checklist de la cátedra](../../docs/checklist-entrega.md).