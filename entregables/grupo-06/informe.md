# Informe individual — Grupo 06

**Integrante:** VIJANDI IVAN · **Fecha:** jueves 29/10/2026  
**Destinatario:** gerente de operaciones / comité de crisis (TransacRed S.A.)

---

## 1. Situación y riesgo

En octubre de 2026 se divulgaron dos vulnerabilidades críticas que comprometen directamente los servicios tecnológicos de nuestra organización:

1. **PHP2Shell (CVE-2026-109618 y CVE-2026-109619):** Afecta al núcleo de PHP y se manifiesta con severidad máxima bajo Apache con `mod_php`. Un error en la gestión de memoria durante el seguimiento de subida de archivos (`session.upload_progress`) permite la ejecución remota de código (RCE) previa a la autenticación. Se encuentra en **CISA KEV** con ataques activos masivos en Internet. Compromete de forma crítica nuestro **Portal PHP** (`web01`).
2. **Node2Shell / HTTP2Shell (CVE-2026-111497):** Falla de escritura fuera de límites (*out-of-bounds write*) en la biblioteca Brotli embebida en el runtime de Node.js v22.23.3 y en paquetes Python. Afecta al endpoint `/decode` de nuestra **API Node.js** (`api01`) y al servicio interno **Python** (`svc01`). Cuenta con RCE demostrado en laboratorio, aunque sin explotación masiva confirmada en producción.

**Nivel de riesgo:** **CRÍTICO**. Nuestro portal web público se encuentra directamente expuesto a RCE inmediato sin requerir credenciales ni interacción de usuarios.

---

## 2. Plan de acción priorizado

| Acción | Activo | Plazo | Dueño | Reversión |
|---|---|---|---|---|
| Deshabilitar `session.upload_progress.enabled = 0` en `php.ini` y reiniciar workers | Portal PHP (`web01`) | < 2 horas | Ivan Vijandi / Facundo Otero | Volver a configurar en `1` en `php.ini` y reiniciar Apache |
| Filtrar/rechazar compresión Brotli en el WAF / Gateway perimetral | API Node.js (`api01`) | < 6 horas | Nicolas Valdes | Desactivar regla de rechazo de cabecera `Content-Encoding: br` en WAF |
| Desplegar parches oficiales a imágenes seguras (PHP 8.3.36, Node 22.23.4, Brotli 1.2.1) | Todos (`web01`, `api01`, `svc01`) | < 24 horas | Facundo Otero | Revertir tags de imágenes en Compose y re-ejecutar `docker compose up -d` |
| Desplegar reglas de detección de creación de procesos (`node`/`apache` -> `sh`/`curl`/`wget`) | Host y contenedores | < 12 horas | Franco Pietrantuono | Desactivar regla en SIEM si genera alertas de falsos positivos |

**Justificación del orden:**  
Se prioriza en primera instancia el Portal PHP no por su CVSS (ambos incidentes tienen CVSS 4.0 9.2), sino por su presencia en **CISA KEV** (explotación real activa) y su exposición directa a Internet con SAPI `mod_php`. La mitigación por configuración en `php.ini` se aplica en minutos sin riesgo de romper dependencias. En la API Node.js se mitiga a nivel de proxy mientras se planifica la ventana de parcheo oficial, ya que no se observan ataques masivos en el mundo real. El servicio Python se atiende en última instancia por encontrarse segmentado en la red interna.

---

## 3. Indicadores de compromiso

- **Señales que confirmarían un compromiso:**
  - Presencia de procesos hijos no autorizados originados desde workers de Apache o Node.js (ej. `apache2` o `node` ejecutando `sh`, `bash`, `curl`, `wget`, `id` o `uname`), tal como se observó en las trazas de `audit.log` en los hosts `web01` y `api01`.
  - Intentos de conexiones salientes hacia direcciones IP públicas sospechosas para descarga de scripts o reverse shells.
  - Creación de archivos en directorios `/tmp` o modificaciones anómalas en el árbol web.

- **Señales que lo descartarían:**
  - Logs de Apache sin errores de OOM / abortos forzados de procesos workers durante subidas de archivos.
  - Ausencia de procesos secundarios (`ppid` correspondiente a servidores web) en los registros de auditoría del kernel (`auditd`).
  - Tráfico HTTP en `/decode` con payloads Brotli que cumplen estrictamente con las especificaciones RFC 7932 sin provocar fallas de segmentación.

- **Qué no se puede saber con la telemetría actual:**
  - La telemetría de `audit.log` solo registra creación de procesos en el sistema operativo; no captura las direcciones IP de origen de los atacantes, las cabeceras HTTP de las peticiones, ni la salida devuelta por los comandos (`stdout`).
  - No es posible detectar ataques que operen enteramente en memoria sin spawnear subprocesos en disco (ej. reverse shells nativas en JavaScript puro o código PHP in-memory).

---

## 4. Transferencia

**Vulnerabilidad analizada:** **CVE-2026-115560** (vulnerabilidad hipotética de *Server-Side Request Forgery* - SSRF en la librería de procesamiento de webhooks de pago en microservicios backend).

- **Qué miraría:**
  - Si el componente que procesa los webhooks tiene visibilidad hacia redes internas corporativas o hacia la dirección de metadatos de la nube (`169.254.169.254`).
  - Si la biblioteca valida listas blancas de dominios o si permite redirecciones HTTP arbitrarias hacia esquemas internos (`file://`, `gopher://`, `http://localhost`).
  - Si existen registros de explotación activa en KEV o PoCs públicas funcionales.

- **Cómo priorizaría:**
  - Si el servicio es interno y no tiene conectividad directa al servicio de metadatos ni a Internet, se clasificaría como prioridad Media/Baja con parcheo programado.
  - Si el microservicio se encuentra en la nube pública y cuenta con permisos IAM asociados al rol de la instancia, se clasificaría como Prioridad Alta / Inmediata para evitar el robo de tokens temporales de infraestructura.

- **Qué cambiaría en el plan:**
  - En lugar de deshabilitar módulos del runtime como en PHP2Shell, la mitigación provisoria pasaría por aplicar reglas de firewall perimetral y políticas de red (NetworkPolicies en Kubernetes) que bloqueen de forma terminante las peticiones salientes hacia rangos privados (RFC 1918) y a la IP de metadatos de nube, neutralizando el impacto del SSRF sin necesidad de apagar la recepción de pagos.

---

## 5. Lecciones y procesos

1. **Inventario más allá del gestor de paquetes:** Las herramientas como `npm audit` o `pip list` no detectan vulnerabilidades arraigadas en el código C/C++ del runtime del lenguaje o en el servidor web. Se debe implementar análisis estático y dinámico de imágenes Docker completas (SBOM) en el pipeline de CI/CD.
2. **Superación de arquitecturas monolíticas web:** Reemplazar el uso de `mod_php` en Apache por una arquitectura desacoplada basada en `php-fpm` o contenedores distroless mínimos, eliminando el procesamiento prematuro de requests por parte del servidor web.
3. **Contención por diseño como estándar:** El aislamiento de red (`internal: true`), el sistema de archivos de solo lectura (`read_only: true`) y la privación de capacidades (`cap_drop: ALL`) demostraron ser la línea de defensa decisiva que neutralizó la post-explotación (`SIN SALIDA`), por lo que deben ser directivas obligatorias en todos los despliegues corporativos.
4. **Telemetría integral y correlación:** Los logs de auditoría de procesos (`auditd`) deben correlacionarse en un SIEM unificado con los logs de acceso web y WAF para identificar tanto la IP atacante como el comando ejecutado.

