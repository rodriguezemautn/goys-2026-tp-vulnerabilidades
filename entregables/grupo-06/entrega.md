# Entregable — TP PHP2Shell / Node2Shell

**Grupo:** Grupo 06 · **Fork del grupo:** `https://github.com/IvanVijandi/goys-2026-tp-vulnerabilidades` · **Rama:** `grupo-06`
**Fecha:** jueves 29/10/2026

| Integrante | Usuario de GitHub | Rol en el TP |
|---|---|---|
| VIJANDI IVAN | `IvanVijandi` | Inventario |
| NICOLAS VALDES | `Nico-valdes` | Priorización de riesgo y comité de crisis |
| FACUNDO OTERO | `facuotero11` | Mitigación, parche y reversión |
| FRANCO PIETRANTUONO | _completar_ | Contención/comunicación |

> Roles sugeridos: inventario, cambios/parche, detección, contención/comunicación.
> Todos tienen que poder explicar su parte y una parte ajena.

---

## 1. Inventario

| Activo | Versión | ¿Expuesto a Internet? | ¿Procesa contenido no confiable? | ¿Afectado? | Evidencia |
|--------|---------|:---------------------:|:--------------------------------:|:----------:|-----------|
| Portal PHP | PHP 8.3.35 (NTS, built Oct 21 2026), Apache 2.4 con SAPI mod_php (`mpm_prefork`) | Sí | Sí | Sí | `php -v` devuelve `PHP 8.3.35`; `apache2ctl -M` muestra `php_module (shared)`; `ini_get('session.upload_progress.enabled')` devuelve `1` |
| API Node.js | Node.js v22.23.3 con Brotli 1.1.0 nativo del runtime, Express 5.3.0 | Sí | Sí | Sí | `node -p "process.version + ' / brotli ' + process.versions.brotli"` devuelve `v22.23.3 / brotli 1.1.0`; `npm ls --all` confirma ausencia de paquetes externos de brotli |
| Servicio Python | Python 3.11.18, Brotli 1.0.9 (PyPI) | No | Sí (condicional) | Sí | `python -c "import sys, brotli; print('python', sys.version.split()[0], 'brotli', brotli.__version__)"` devuelve `python 3.11.18 brotli 1.0.9` |

**Supuestos de exposición:**
1. **Red y perimetral:** En el laboratorio Docker, ningún servicio publica puertos al host (`ports: []`) y conviven en la red interna `labnet` (`internal: true`). En un escenario de producción (TransacRed S.A.), se asume un proxy reverso / gateway perimetral que expone el Portal PHP (`web01`) a Internet sobre HTTPS y enruta peticiones hacia la API Node.js (`api01`).
2. **SAPI y procesamiento pre-aplicación en PHP:** Al usar Apache con `mod_php`, la inicialización del request y el mecanismo de sesiones `session.upload_progress` son procesados directamente por el worker antes de que cualquier código de aplicación o capa de autenticación se ejecute, habilitando el vector RCE de PHP2Shell sin credenciales.
3. **Dependencias del Runtime vs Paquetes Externos en Node.js:** En la API Node.js, `npm audit` no reporta vulnerabilidades ya que el decodificador Brotli (v1.1.0) se encuentra compilado directamente en el runtime de Node.js v22.23.3 y no en el árbol de `node_modules`.
4. **Servicio Python:** Servicio backend interno confinado a la red `labnet` sin exposición directa a usuarios externos.

---

## 2. Priorización y decisión

| Activo | CVSS | Explotación real | Exposición | Criticidad | Decisión y plazo |
|--------|:----:|:----------------:|:----------:|:----------:|------------------|
| **Portal PHP** (`web01`) | **4.0: 9.2** (Crítico) | **Sí (CISA KEV)**. Ataques activos masivos *in the wild* y PoCs públicos. | **Internet (Alta)**. Expuesto vía HTTPS en perímetro; Apache `mod_php` procesa `session.upload_progress` pre-auth. | **Crítica**. Portal web transaccional y facturación de clientes de TransacRed S.A. | **Mitigación inmediata (< 2 h)** vía `php.ini` (`session.upload_progress.enabled = 0`). **Parche definitivo (< 12 h)** a PHP 8.3.36. |
| **API Node.js** (`api01`) | **4.0: 9.2** (Crítico) | **No en producción**. RCE demostrado solo en laboratorio (sin registro en KEV al 29/10). | **Internet (Media/Alta)**. Expuesta vía API Gateway; endpoint `/decode` procesa Brotli de clientes externos. | **Alta**. Servicio de procesamiento y compresión de payloads transaccionales. | **Mitigación perimetral (< 6 h)** (rechazo de `br` en Gateway). **Parche programado (12–24 h)** a Node.js 22.23.4. |
| **Servicio Python** (`svc01`) | **4.0: 9.2** (Crítico) | **No**. Sin reportes de explotación dirigida ni presencia en KEV. | **Interna (Baja)**. Backend en `labnet`, sin puertos expuestos a Internet. Procesa datos prefiltrados. | **Media**. Servicio interno de cálculo y soporte asincrónico. | **Parche estándar (24–48 h)** en ventana regular de mantenimiento (actualizar a Brotli >= 1.0.10 / 1.2.1). Monitoreo pasivo. |

**Justificación:**
1. **Riesgo real vs. severidad teórica (CVSS vs. KEV/Exposición):**
   Aunque los tres activos comparten un puntaje base idéntico (**CVSS 4.0: 9.2**), el riesgo operativo no es uniforme. La priorización adopta el modelo RBVM (*Risk-Based Vulnerability Management*):
   - **PHP va primero (< 2 h):** La presencia confirmada en **CISA KEV** con campañas automatizadas activas, sumada a la arquitectura Apache + `mod_php` (donde la vulnerabilidad se gatilla en memoria del worker *antes* de cualquier middleware o capa de aplicación), convierte al Portal PHP en un blanco de compromiso inminente. Además, la mitigación por configuración (`session.upload_progress.enabled = 0`) es no invasiva, instantánea y con riesgo cero de interrupción del negocio.
   - **Node.js en segundo lugar (12–24 h):** El decodificador Brotli embebido en el runtime expone al endpoint público `/decode`, pero la ausencia de explotación masiva en el mundo real (sin KEV al 29/10) descarta una crisis descontrolada en curso. Se mitiga preventivamente a nivel perimetral y se planifica una ventana controlada de cambio con pruebas de regresión de APIs.
   - **Python en tercer lugar (24–48 h):** Es un servicio estrictamente interno, no ruteable desde Internet y confinado en la red Docker (`labnet`). No procesa tráfico no confiable directo, reduciendo drásticamente la probabilidad de explotación.

2. **¿Qué evidencia nueva cambiaría la decisión?**
   - **Elevación de Node.js a < 2 h:** Si CISA añade CVE-2026-111497 al catálogo KEV, si se publica un exploit funcional confiable dirigido a APIs REST sobre Node 22, o si el SIEM detecta fallos de segmentación anómalos en el proceso `node`.
   - **Elevación de Python a < 12 h:** Si una auditoría de arquitectura revela que el backend Python consume colas de mensajes o webhooks originados directamente por terceros sin sanitización en el Gateway.
   - **Paso a protocolo de respuesta a incidentes (contención/apagado):** Si en la correlación de logs de auditoría se descubren llamadas no autorizadas a shells (`/bin/sh`, `curl`, `wget`) o conexiones salientes desde cualquiera de los tres servicios, se suspende el cronograma de parcheo y se procede a aislar el activo comprometido de la red inmediatamente.

---

## 3. Mitigación, parche y reversión

| Fecha/hora | Activo | Cambio | Antes | Después | Reversión |
|------------|--------|--------|-------|---------|-----------|
| 29/10 19:11 | Portal PHP | Mitigación: `session.upload_progress.enabled = 0` en `laboratorio/php/php.ini` + `docker compose restart php-lab` | `ini_get('session.upload_progress.enabled')` → `1` a las 19:09 ([captura](capturas/03-php-antes.png)) | `ini_get(...)` → `0` ([captura](capturas/03-php-despues.png)) | Volver la directiva a `1` (o `git revert` del commit `fix(php)`) y `docker compose restart php-lab`. **No se recomienda revertirla** aunque ya esté el parche: también mitiga CVE-2026-115560, que no tiene parche |
| 29/10 19:20 | Portal PHP | Parche: `PHP_TAG=8.3.36-apache` + `docker compose --env-file laboratorio/versions.env up -d --build` | PHP 8.3.35 (Sección 1) | `php -v` → `PHP 8.3.36`; contenedor `healthy` ([captura](capturas/03-parche-versiones.png)) | Borrar la variable (`Remove-Item Env:PHP_TAG`) y repetir `up -d --build` con `versions.env` original |
| 29/10 19:20 | API Node.js | Parche: `NODE_TAG=22.23.4-bookworm-slim` | Node.js v22.23.3 con Brotli 1.1.0 nativo (Sección 1) | Imagen `goys-vuln-lab-node:22.23.4-bookworm-slim`, contenedor `healthy` ([captura](capturas/03-parche-versiones.png)) | Borrar `NODE_TAG` y repetir `up -d --build` |
| 29/10 19:20 | Servicio Python | Parche: `BROTLI_VERSION=1.2.1` | Brotli 1.0.9 (PyPI) (Sección 1) | Build ejecutó `pip install "brotli==1.2.1"`; imagen `goys-vuln-lab-py:1.2.1`, contenedor `healthy` ([captura](capturas/03-parche-versiones.png)) | Borrar `BROTLI_VERSION` y repetir `up -d --build` |

**Orden y criterio:** se siguió el orden de la Sección 2. Primero, la mitigación de PHP,
aplicada dentro del plazo de < 2 h, porque compra tiempo sin reconstruir imágenes. La
mitigación es parcial: corta el camino confirmado de CVE-2026-109619 (upload progress),
pero no CVE-2026-109618, que se dispara por agotamiento de memoria al procesar uploads
multipart. Por eso el parche a 8.3.36 es la corrección real. Costo de la mitigación: se
pierden las barras de progreso de subida. En el laboratorio, los tres parches se
aplicaron juntos porque el comando reconstruye todo el stack de una vez; en producción
se escalonarían según los plazos de la Sección 2. Después del parche se volvió a
verificar la mitigación (`ini_get` → `0`): sigue activa con la imagen nueva.

**Incidente durante el parche:** el primer intento (19:14) falló al construir `node-lab`
en `RUN npm install --omit=dev`, con `UNABLE_TO_VERIFY_LEAF_SIGNATURE` ("unable to verify
the first certificate") contra `registry.npmjs.org`. PHP y Python sí habían descargado sus
versiones nuevas, pero al fallar el build Docker no recreó ningún contenedor: los tres
siguieron con la versión vulnerable. Se descartó desactivar la verificación de
certificados, porque abre un riesgo de seguridad y obliga a modificar el Dockerfile. Se
cambió de red y se repitió el mismo comando, que completó sin errores. Lección operativa:
el parcheo depende de que haya acceso confiable al registro de paquetes, y un fallo
parcial deja todo sin parchear.

**Prueba funcional mínima:** después del parche, `docker compose ps` muestra los tres
servicios (`php-lab`, `node-lab`, `py-lab`) en estado `Up (healthy)`
([captura](capturas/03-parche-versiones.png)).

**Qué no se pudo probar:**
- No se ejecutaron exploits ni PoCs (regla de la cátedra). Se verificó la configuración
  y la versión, no que el ataque quede bloqueado.
- La verificación de la mitigación se hizo con `php -r` (la consola de PHP, no el
  servidor web). Se asume que Apache usa el mismo `php.ini`; no se confirmó con un
  `phpinfo()` servido por web.
- La prueba funcional se basa en el healthcheck de Docker. No se hizo una petición HTTP
  manual a cada servicio, ni se revisó qué endpoint consulta ese healthcheck.
- Las versiones de Node 22.23.4 y Brotli 1.2.1 se evidencian por las imágenes y el log
  del build, no consultándolas desde adentro del contenedor en ejecución. En particular,
  no se verificó qué versión de Brotli nativo trae Node 22.23.4.
- La reversión del parche está documentada pero no se ejecutó.

---

## 4. Detección y caza

**Hipótesis:** entre las 09:40 y las 09:50 UTC, buscar hijos `sh`, `bash`, `curl`,
`wget` o `nc` creados por `apache2`, `php-fpm`, `node` o `python`; se espera un árbol
de procesos con reconocimiento o conexión saliente desde un servicio.

**Hallazgos en `audit.log`:**

| Línea / timestamp | Host | Padre → hijo | ¿Anómalo? | Por qué |
|-------------------|------|--------------|:---------:|---------|
| 09:42:17–09:42:18 | web01 | `apache2 → sh → id` | Investigar | El servidor web crea un shell para reconocimiento de identidad. |
| 09:43:03–09:43:04 | api01 | `node → sh → curl` | **Sí** | Node.js lanza un shell y una herramienta de red hacia `198.51.100.7`. |
| 09:44:22 | web01 | `apache2 → wget` | **Sí** | Un proceso web descarga desde `198.51.100.9`; posible segunda etapa. |

**¿Hay compromiso?** **Indeterminado, pero hay ejecución sospechosa que exige
contención.** Las líneas de `api01` y `web01` sostienen la alerta, pero el log
sintético no prueba que la descarga haya finalizado, que el tráfico haya salido ni que
se haya ejecutado un payload.

**Regla propuesta para Node.js:** observar creación de procesos (`process_creation`)
y disparar cuando `ParentImage` sea `node` y el hijo sea `sh`, `bash`, `curl`, `wget`
o `nc`; elevar la alerta si se correlaciona una conexión saliente del mismo PID o
contenedor. Un falso negativo posible es que Node invoque la herramienta mediante un
wrapper, ruta alternativa, intérprete distinto o binario renombrado.

```yaml
title: Node.js Spawns Shell Or Network Utility
logsource:
  category: process_creation
detection:
  parent_node:
    ParentImage|endswith: ['/node', '\node.exe']
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

**Limitaciones del log:** no hay usuario/UID, IP ni puerto de origen o destino,
contenedor o imagen, hash, resultado de ejecución, salida estándar, telemetría de red
ni retención. Es un log sintético de diez minutos: puede haber ruido por
administración/inventario y falsos negativos por wrappers o procesos renombrados.

---

## 5. Contención

| Control | Configuración | Evidencia | ¿Funciona? |
|---------|---------------|-----------|:----------:|
| Red sin salida | `networks.labnet.internal: true` | `docker compose config` muestra `internal: true`; `verificar-contencion.sh` prueba HTTP externo en los tres contenedores. | **Sí**: se espera `SIN SALIDA` en PHP, Node.js y Python. |
| Usuario sin privilegios | `user: node` / `user: nobody` | Declarado para `node-lab` y `py-lab`; PHP no fija usuario porque Apache requiere cambios de identidad. | **Parcial**: Node y Python no son root; verificar el usuario efectivo de PHP. |
| Filesystem read-only | `read_only: true` + `tmpfs` | `docker compose config` muestra `read_only: true`; solo `/tmp` y directorios operativos son temporales. | **Sí**, como control contra persistencia en la capa de imagen. |
| Capabilities mínimas | `cap_drop: ALL` | `docker compose config` muestra `cap_drop: ALL`; PHP agrega solo capacidades operativas explícitas. | **Sí**, con la salvedad de las capacidades agregadas a PHP. |
| Límites de memoria/PIDs | `mem_limit` y `pids_limit` | PHP/Node: `256m` y `100`; Python: `128m` y `50`, visibles en `docker compose config`. | **Sí**, limita consumo del contenedor; no sustituye monitoreo. |
| Rechazo de Brotli innecesario | Rechazar `Content-Encoding: br` en proxy/app | No está implementado en `docker-compose.yml`; queda como control compensatorio recomendado para el gateway. | **No verificado** en este laboratorio. |

**Prueba de salida a Internet:** `./scripts/verificar-contencion.sh` ejecuta una
solicitud externa desde cada servicio. La evidencia esperada es:

```text
-- PHP:
SIN SALIDA
-- Node.js:
SIN SALIDA <error de red>
-- Python:
SIN SALIDA <error de red>
```

El nombre exacto de la excepción puede variar según la imagen, pero los tres
resultados deben ser `SIN SALIDA`. La red `internal: true` bloquea el tráfico externo
en runtime; no debe confundirse con el acceso temporal a Internet necesario para
construir las imágenes.

---

## 6. Conclusión (5 líneas)

_¿Qué harían distinto en las primeras 2 horas?_

---

## 7. Checklist antes de entregar

- [ ] El laboratorio arrancó y los 3 servicios quedaron `healthy`.
- [x] Inventario con evidencia (versión, SAPI, configuración).
- [x] Matriz con decisión y plazo.
- [ ] Parche aplicado y verificado; reversión documentada.
- [ ] Al menos 3 controles de contención probados.
- [ ] `deteccion.md` completo.
- [ ] `informe.md` individual completo.
- [ ] Sin claves, tokens ni placeholders.
- [ ] Repo pusheado y PR abierto.

Checklist completa: [`../docs/checklist-entrega.md`](../docs/checklist-entrega.md).
