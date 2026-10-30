# Informe individual — Grupo 10

**Integrante:** Benjamín Elizalde (Rol: Comunicación e Integración)  
**Fecha:** viernes 30/10/2026  
**Destinatario:** Gerente de Operaciones / Comité de Crisis  
**Organización Asignada:** Servicios Digitales Cono Sur S.A. (Fintech / Pagos Electrónicos)  

---

## 1. Situación y Evaluación del Nivel de Riesgo

Durante la segunda quincena de octubre de 2026 se divulgaron dos amenazas críticas que comprometen componentes estructurales de nuestros entornos tecnológicos:

1. **PHP2Shell (CVE-2026-109618 y CVE-2026-109619, CVSS 9.2):** Falla en la gestión de memoria del núcleo de PHP (corrupción por Out-Of-Memory y reutilización de estado global sucio). En entornos basados en Apache con `mod_php`, permite la ejecución remota de código (RCE) sin requerir autenticación previa ni interacción del usuario. La vulnerabilidad está confirmada en el catálogo **CISA KEV** con explotación activa masiva en la naturaleza desde el 26/10/2026.
2. **Node2Shell / HTTP2Shell (CVE-2026-111497, CVSS 9.2):** Desbordamiento de escritura fuera de límites (*out-of-bounds write*) en la librería de descompresión Brotli (versiones 1.0.3 a 1.2.0), embebida nativamente en Node.js y utilizada como paquete en microservicios Python. Si bien existe prueba de concepto de RCE demostrada en laboratorio, **al día de hoy no cuenta con evidencia de explotación maliciosa en el mundo real ni presencia en CISA KEV**.

### Impacto y Riesgo para el Negocio
Para nuestra plataforma fintech, el **Portal de Clientes y Cobranzas** corre bajo PHP 8.3.35 sobre Apache. Dada la presencia en CISA KEV, el riesgo es **CRÍTICO e INMINENTE**: un atacante podría comprometer el servidor web, extraer tokens de sesión, acceder a la base de datos transaccional o utilizar la infraestructura como pivote de ataque lateral.

Por su parte, la **API de Integración (Node.js)** y el **Servicio de Validación (Python)** presentan un riesgo **ALTO pero NO INMEDIATO**, ya que no están siendo explotados activamente y sus endpoints son de uso interno o controlable a nivel de cabeceras HTTP.

---

## 2. Plan de Acción Priorizado

El plan se estructuró separando la **contención compensatoria inmediata** de las **ventanas de cambio de parcheo**, evitando paradas descontroladas en producción:

| # | Acción | Activo Afectado | Plazo Máximo | Responsable / Dueño | Procedimiento de Reversión (Rollback) |
|---|---|---|---|---|---|
| **1** | **Mitigación perimetral PHP:** Desactivar `session.upload_progress.enabled = 0` en `php.ini` y recargar workers Apache. | Portal Web PHP (`php-lab`) | **Inmediato (< 2 horas)** | Damián Alvite (Ops) / Rodrigo Capre (Parches) | Revertir directiva a `1` en `php.ini` y reiniciar el contenedor / servicio. |
| **2** | **Contención perimetral Brotli:** Regla en WAF/Proxy reverso para rechazar o desestimar peticiones HTTP con cabecera `Content-Encoding: br`. | API Node.js (`node-lab`) / Servicio Python (`py-lab`) | **Inmediato (< 4 horas)** | Vicente Moscuzza (Redes/WAF) | Quitar regla de filtrado en WAF y restablecer negociación de compresión Brotli. |
| **3** | **Actualización definitiva de PHP:** Despliegue de imagen validada PHP 8.3.36 en entorno productivo. | Portal Web PHP (`php-lab`) | **24 horas** (Ventana nocturna de bajo tráfico) | Rodrigo Capre (Release Manager) | Desplegar tag anterior (`php:8.3.35-apache`) mediante imagen preservada en registry. |
| **4** | **Actualización de Runtime Node.js:** Despliegue de Node.js v22.23.4 (que backportea el fix de Brotli) y brotli 1.2.1 en Python. | API Node (`node-lab`) y Svc Python (`py-lab`) | **48 a 72 horas** (Ventana de cambio estándar) | Rodrigo Capre (Release Manager) | Volver a imágenes de Node 22.23.3 y Python brotli 1.0.9 en el orquestador. |

### Criterio de Priorización
No se aplicó un criterio ingenuo de "parchear todo urgente" por CVSS nominal (ambos son 9.2). Se priorizó en base a:
- **Explotación Real (Threat Intelligence):** PHP2Shell está en CISA KEV con ataques en curso; Node2Shell solo cuenta con exploits de prueba académica.
- **Exposición:** El portal PHP atiende tráfico directo de clientes, mientras que los servicios Node y Python son consumidos detrás de capas de agregación.

---

## 3. Indicadores de Compromiso (IoC) y Evaluación Forense

A partir de la telemetría recolectada en nuestros registros de auditoría (`audit.log`), se efectuó una caza de amenazas (*threat hunting*) determinando:

### Señales que Confirmarían un Compromiso
- Procesos de servidores web o APIs (`apache2`, `php-fpm`, `node`, `python`) engendrando intérpretes de comandos (`/bin/sh`, `/bin/bash`).
- Ejecución de comandos de reconocimiento de privilegios o sistema (`id`, `whoami`, `uname -a`) bajo el árbol de procesos de la aplicación.
- Conexiones de red salientes o herramientas de descarga (`curl`, `wget`, `nc`) intentando alcanzar direcciones IP externas de servidores de comando y control (C2).

### Señales que Descartan el Compromiso Efectivo
- La arquitectura cuenta con **red interna sin salida a Internet (`internal: true`)** confirmada mediante pruebas funcionales, lo que impidió la descarga de payloads secundarios.
- Los contenedores operan con **sistema de archivos en modo de solo lectura (`read_only: true`)** y **usuario sin privilegios (`node`, `nobody`)**, evitando la creación de web shells o la instalación de persistencia.
- Las solicitudes observadas en los logs sintéticos hacia IPs reservadas de prueba (`198.51.100.x`) no establecieron sesiones interactivas ni alteraron ficheros del sistema.

### Limitaciones de la Telemetría Actual
El registro analizado presenta limitaciones severas que deben ser subsanadas: no registra identidades de usuario del sistema operativo (UID/GID), no captura las IPs de origen de las peticiones HTTP externas, carece de correlación con logs de acceso web y el tiempo de retención es insuficiente para descartar actividades previas. El estado se clasifica como **Indeterminado con indicios de intrusión contenidos**.

---

## 4. Transferencia de Metodología a un Nuevo Caso (CVE-2026-115560)

Para demostrar la solidez de este marco metodológico ante futuros incidentes, analizamos el tratamiento de **CVE-2026-115560** (vulnerabilidad reportada en el motor de subida multipart de PHP posterior a PHP2Shell):

1. **Relevamiento de Exposición:** No basta con saber si usamos PHP. Se audita si la aplicación utiliza subida de archivos multipart activa y si la directiva `file_uploads` está habilitada en los endpoints públicos.
2. **Priorización por Riesgo:**
   - Si no figura en CISA KEV y no existe exploit funcional público, su prioridad pasa a ciclo de parcheo programado (no de emergencia).
   - Si el activo procesa facturación sensible pero está contenido tras una red aislada y WAF con inspección de payloads, la criticidad disminuye.
3. **Plan de Mitigación sin Parche:** Si la actualización no puede desplegarse de inmediato, se mitiga a nivel de configuración (ej. limitando `upload_max_filesize = 0` en rutas no requeridas o bloqueando peticiones `multipart/form-data` anómalas en el proxy inverso).
4. **Validación:** Todo cambio debe contemplar prueba funcional mínima (smoke test) y comando de rollback testeado en pre-producción antes de impactar el entorno operativo.

---

## 5. Lecciones Aprendidas y Mejora de Procesos

A raíz del incidente, se proponen cinco reformas estructurales inmediatas:

1. **Inventario Continuo de Software (SBOM):** Implementar escaneo automatizado en la integración continua (CI/CD) para mapear librerías transitivas (como Brotli embebido en Node o módulos de Python) sin depender de auditorías manuales durante una crisis.
2. **Entornos de Staging Homogéneos:** Garantizar que los ambientes de homologación repliquen con fidelidad la topología de red y proxies de producción para realizar pruebas funcionales de parches en minutos sin incertidumbre.
3. **Telemetría y Detección Centralizada:** Desplegar agentes EDR o reglas de auditoría de kernel (`auditd`) en producción que capturen árbol genealógico de procesos, usuarios e IPs de origen de las sesiones, resolviendo la ceguera actual.
4. **Política de Defensa en Profundidad por Defecto:** Mantener como estándar obligatorio en toda la infraestructura de contenedores el uso de usuarios sin privilegios (`USER nonroot`), filesystems de solo lectura y bloqueo de tráfico de egreso no autorizado.
5. **Comunicación Institucional Controlada:** Protocolizar las comunicaciones hacia clientes y reguladores; se debe informar la aplicación de protocolos de seguridad preventivos y el estado operacional sin divulgar versiones específicas ni vectores técnicos que otorguen ventajas a atacantes externos.

