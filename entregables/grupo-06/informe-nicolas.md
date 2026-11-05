# Informe Individual de Gestión de Vulnerabilidades — TransacRed S.A.

**Integrante:** NICOLAS VALDES · **Rol:** Priorización de Riesgo, Matriz CVSS/KEV y Comité de Crisis  
**Fecha:** jueves 29/10/2026  
**Destinatario:** Dirección de Operaciones y Comité de Seguridad de la Información (TransacRed S.A.)  
**Contexto del Negocio:** TransacRed S.A. procesa operaciones financieras, cobros recurrentes y emisión de facturación electrónica en tiempo real para clientes corporativos.

---

## 1. Situación y Nivel de Riesgo

Durante el presente mes de octubre de 2026, la comunidad internacional de ciberseguridad alertó sobre la divulgación y explotación de dos familias de vulnerabilidades de severidad extrema que impactan de manera directa sobre la infraestructura productiva de TransacRed S.A.:

1. **PHP2Shell (CVE-2026-109618 y CVE-2026-109619):**  
   Vulnerabilidad crítica en el núcleo de PHP que afecta a versiones 8.3.x (específicamente la versión 8.3.35 desplegada en nuestro Portal de Clientes y Facturación `web01`). Bajo servidores Apache configurados con el módulo embebido `mod_php` (`mpm_prefork`), un fallo de corrupción de memoria desencadenado durante la carga de archivos multipart a través del rastreador de sesiones (`session.upload_progress`) permite a un atacante remoto no autenticado alcanzar la Ejecución Remota de Código (RCE). Esta falla se encuentra formalmente catalogada en **CISA KEV** con evidencia de explotación masiva en el mundo real (*in the wild*) sin necesidad de credenciales ni interacción de la víctima.

2. **Node2Shell / HTTP2Shell (CVE-2026-111497):**  
   Falla de escritura fuera de límites (*out-of-bounds write*, CWE-787) en la implementación nativa del decodificador Brotli (versiones 1.0.3 a 1.2.0), compilada directamente dentro del runtime de Node.js v22.23.3 utilizado por nuestra API transaccional (`api01`), y presente como dependencia en nuestro microservicio interno de Python (`svc01`). La vulnerabilidad permite corrupción de memoria y potencial RCE al procesar payloads comprimidos en el endpoint `/decode`. Si bien cuenta con exploits probados en entornos de laboratorio controlados, al día de la fecha no cuenta con reportes de explotación masiva activa en producción ni inclusión en KEV.

**Evaluación del Nivel de Riesgo Corporativo: CRÍTICO (Prioridad Inmediata de Negocio).**  
La conjunción de exposición directa a Internet en el Portal PHP, la existencia de exploits públicos automatizados y la capacidad de ejecutar código en el contexto del proceso web sin autenticación previa expone a la compañía a riesgos de interrupción del servicio de facturación, acceso ilícito a registros transaccionales y eventual movimiento lateral.

---

## 2. Plan de Acción Priorizado

La estrategia de remediación no se fundamenta ciegamente en el puntaje teórico CVSS (ambos eventos registran **CVSS 4.0: 9.2**), sino en la **probabilidad real de explotación (KEV), la superficie de ataque y el impacto sobre la continuidad operativa de TransacRed S.A.**

| Acción Priorizada | Activo Alcanzado | Plazo de Ejecución | Responsable Directo | Plan de Reversión (Rollback) |
|---|---|:---:|---|---|
| **1. Mitigación en caliente por configuración:** Deshabilitar `session.upload_progress.enabled = 0` en `php.ini` y recarga suave (*graceful reload*) de Apache. | Portal PHP (`web01`) | **< 2 horas** (Inmediato) | Facundo Otero / Nicolas Valdes | Restablecer `session.upload_progress.enabled = 1` en `php.ini` y recargar Apache (`apache2ctl graceful`). |
| **2. Mitigación perimetral de compresión:** Desactivar temporalmente la descompresión Brotli en el API Gateway o bloquear cabeceras `Content-Encoding: br` no indispensables. | API Node.js (`api01`) | **< 6 horas** | Nicolas Valdes | Reincorporar la directiva de admisión de codificación Brotli en la configuración de rutas del Gateway. |
| **3. Parcheo definitivo del runtime Node.js:** Actualización controlada a la imagen con Node.js 22.23.4 (con Brotli 1.1.1 integrado) tras validación en staging. | API Node.js (`api01`) | **12 a 24 horas** (Ventana nocturna) | Facundo Otero / Nicolas Valdes | Revertir el tag de la imagen Docker en `versions.env` a `22.23.3-bookworm-slim` y reejecutar `docker compose up -d`. |
| **4. Parcheo definitivo del motor PHP:** Despliegue de imagen base con PHP 8.3.36 en la ventana regular de mantenimiento. | Portal PHP (`web01`) | **< 24 horas** (Ventana nocturna) | Facundo Otero | Revertir el tag en el archivo de variables a `8.3.35-apache` y reconstruir el contenedor. |
| **5. Parcheo de dependencias internas:** Rebuild y actualización de librería `brotli>=1.0.10` en el microservicio backend. | Servicio Python (`svc01`) | **24 a 48 horas** (Mantenimiento estándar) | Franco Pietrantuono | Revertir `requirements.txt` a la versión previa y redesplegar imagen. |

### Justificación de Plazos y Criterio de Decisión:
- **¿Por qué PHP va primero (< 2 h)?** Porque presenta explotación activa real confirmada en CISA KEV y una exposición pública total donde el bug se dispara a nivel de Apache antes de que la aplicación valide usuarios. La mitigación aplicada en `php.ini` toma segundos, no interrumpe el servicio y tiene riesgo cero de incompatibilidad funcional.
- **¿Por qué Node.js en 12–24 h?** No se justifica una parada de emergencia en horario transaccional crítico dado que no hay campañas activas en producción. Se contiene en el borde perimetral y se programa un cambio seguro con pruebas de smoke test.
- **¿Por qué Python en 48 h?** Se encuentra totalmente confinado a la red privada `labnet`, sin acceso público ni procesamiento de peticiones no sanitizadas.

---

## 3. Indicadores de Compromiso (IoCs) y Evaluación Forense

Para dictaminar si la infraestructura de TransacRed S.A. ha sido vulnerada previo o durante la aplicación de las medidas, el equipo de ciberseguridad analizó la telemetría del sistema operativo (`audit.log`):

### A. Señales que confirmarían un compromiso:
1. **Creación de procesos secundarios anómalos:** Evidencia de procesos hijos como `/bin/sh`, `/bin/bash`, `curl`, `wget`, `id` o `uname` engendrados directamente por los ejecutables del servidor web (`apache2` o `node`).
2. **Intentos de conectividad saliente no autorizada:** Registros de conexiones hacia direcciones IP públicas desconocidas para descargar herramientas de post-explotación o establecer sesiones de Command & Control (C2).
3. **Escritura y ejecución en directorios temporales:** Aparición de scripts o archivos ejecutables en `/tmp`, `/var/tmp` o `/dev/shm`.

### B. Señales que descartarían un compromiso:
1. Ausencia total de invocaciones a shells o binarios del sistema derivadas de los workers web en los logs de auditoría del kernel (`auditd`).
2. Comportamiento volumétrico y códigos de respuesta regulares en Apache sin caídas intempestivas de procesos por violaciones de memoria (*core dumps* o abortos OOM anormales).
3. Peticiones hacia `/decode` con payloads que respetan la especificación RFC 7932 sin provocar interrupciones en el event loop de Node.js.

### C. Limitaciones y puntos ciegos de la telemetría actual:
- **Falta de contexto de red en `audit.log`:** El registro de auditoría del kernel captura la relación padre-hijo de los procesos en el sistema operativo, pero no contiene las direcciones IP de origen del atacante, las URLs exactas ni las cabeceras HTTP de la solicitud.
- **Ataques enteramente residentes en memoria:** No es posible detectar técnicas avanzadas que operen exclusivamente en el espacio de memoria del proceso sin realizar llamadas a `fork()` / `execve()`.

---

## 4. Transferencia de Aprendizaje — Caso CVE-2026-115560

Para demostrar la capacidad de adaptación del marco metodológico ante escenarios diversos, se analiza la gestión de una vulnerabilidad alternativa: **CVE-2026-115560** (vulnerabilidad crítica de *Server-Side Request Forgery* - SSRF en un motor de suscripción de Webhooks de pago):

- **Qué analizaría:**
  - Si el componente expuesto a los clientes permite ingresar URLs arbitrarias para recibir notificaciones de pago y si dicho servicio tiene visibilidad hacia redes internas corporativas o hacia el endpoint de metadatos de infraestructura en la nube (`169.254.169.254`).
  - La existencia de controles de validación de dominios, resolución previa de nombres DNS para evitar técnicas de *DNS Rebinding*, o presencia del CVE en bases de explotación activa (KEV).
- **Cómo priorizaría:**
  - Si el servicio corre con roles de IAM asignados con privilegios de lectura en la nube (ej. acceso a buckets S3 o KMS), la prioridad es **Crítica / Inmediata (< 4 horas)** para evitar el robo de credenciales de infraestructura.
  - Si el servicio reside en un contenedor aislado con políticas de salida bloqueadas, se maneja como prioridad Media con actualización programada.
- **Qué cambiaría en el plan de acción:**
  - A diferencia de PHP2Shell donde se modifica un parámetro del runtime (`php.ini`), la mitigación rápida de un SSRF no pasa por el código del lenguaje sino por **políticas de red perimetrales y de salida**:
    1. Implementar reglas estrictas de firewall o *NetworkPolicies* de Kubernetes que prohíban al microservicio de webhooks entablar conexiones hacia rangos de IP privadas (RFC 1918) y hacia la IP de metadatos de nube (`169.254.169.254/32`).
    2. Enrutar las peticiones salientes a través de un proxy egress dedicado con lista blanca estricta de dominios y resolución DNS validada. Esto neutraliza la amenaza de inmediato sin frenar el procesamiento de transacciones.

---

## 5. Lecciones Aprendidas y Maduración de Procesos

1. **Visibilidad holística del Software Supply Chain:** Las herramientas estándar de auditoría de paquetes (`npm audit`, `pip audit`) resultan insuficientes para identificar fallas incrustadas en el código nativo en C/C++ del propio runtime o de los servidores web. Debemos incorporar escaneo estático de imágenes completas (SBOM con Trivy/Grype) en los pipelines de CI/CD.
2. **Desacoplamiento de la arquitectura web:** La arquitectura basada en `mod_php` dentro de Apache representa un modelo obsoleto y riesgoso, ya que antepone la ejecución de módulos de sesión antes de que la aplicación tenga control. Debe migrarse hacia arquitecturas basadas en `php-fpm` con contenedores mínimos y aislados.
3. **Imprescindibilidad de la Contención por Diseño:** El laboratorio evidenció que cuando el perímetro falla, las restricciones a nivel de contenedor (`internal: true`, `read_only: true`, `cap_drop: ALL`, cuotas de memoria y procesos) son las que efectivamente impiden que un exploit logre exfiltrar datos o descargar malware (`SIN SALIDA`). Estas configuraciones deben ser adoptadas como directiva no negociable de arquitectura en TransacRed S.A.
4. **Correlación SIEM unificada:** Es imperativo unificar los logs de acceso de los reverse proxies/WAF con los logs de llamadas al sistema (`auditd`) en un SIEM centralizado para poder trazar la petición HTTP de entrada directamente con el proceso hijo resultante en el sistema.
