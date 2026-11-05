# Comité de Crisis — Guía de Defensa y Argumentario Estratégico

**Organización:** TransacRed S.A. (Servicios transaccionales y facturación online)  
**Defensa a cargo de:** Nicolas Valdes (y equipo Grupo 06)  
**Destinatario de la simulación:** Gerente de Operaciones / Directorio / Cátedra GOYS  
**Duración del pitch:** 2 minutos iniciales + respuestas a objeciones y repreguntas.

---

## 1. Discurso de Apertura Ejecutivo (Elevator Pitch — 2 Minutos)

> *"Estimado Directorio y Gerencia:  
> En las últimas horas se divulgaron dos vulnerabilidades críticas de impacto global: **PHP2Shell** y **Node2Shell**, ambas con severidad base CVSS 9.2 sobre 10.  
> 
> En **TransacRed S.A.** tenemos tres plataformas afectadas: el **Portal Web de Clientes y Facturación en PHP**, la **API de Transacciones en Node.js**, y un **Servicio Interno en Python**.
> 
> Nuestra postura no es entrar en pánico ni paralizar la facturación de la compañía. Basándonos en la **gestión de riesgos reales**, hemos establecido un plan quirúrgico:
> 
> 1. **Prioridad 1 (Inmediata — < 2 horas): Portal PHP.** Está en el catálogo de explotación activa de CISA (**KEV**) y expuesto a Internet. No vamos a arriesgar una caída del servicio de facturación compilando paquetes en caliente sin pruebas: aplicamos una **mitigación de configuración inmediata** deshabilitando el seguimiento de subida de archivos en `php.ini` (`session.upload_progress.enabled = 0`). Esto elimina el 100% del vector de ataque sin afectar la facturación ni requerir parada de servicio. El parche de versión completo se desplegará en la ventana nocturna de bajo tráfico.
> 2. **Prioridad 2 (12 a 24 horas): API Node.js.** El bug en el descompresor Brotli es crítico en teoría, pero **no tiene explotación activa en el mundo real**. Aplicamos un filtrado preventivo en el API Gateway y programamos el parche a Node.js 22.23.4 para esta noche tras pruebas de regresión.
> 3. **Prioridad 3 (24 a 48 horas): Servicio Python.** Es un backend estrictamente interno y aislado en nuestra red privada sin acceso a Internet.
> 
> Además, aun si un atacante lograse vulnerar el perímetro, nuestros contenedores cuentan con **defensa en profundidad activa**: red interna sin salida a Internet, sistema de archivos de solo lectura y usuarios sin privilegios. El negocio continúa operando y el riesgo está bajo control."*

---

## 2. Respuestas Estratégicas a las 8 Preguntas del Comité (`docs/comite.md`)

---

### Pregunta 1: ¿Parcheamos en caliente un servicio de facturación que no tiene entorno de pruebas?

* **Postura ejecutiva:** **NO se parchea en caliente el binario/runtime central sin entorno de pruebas**, pero **SÍ se aplica una mitigación de configuración no disruptiva de inmediato**.
* **Argumentación técnica y de negocio:**
  - Actualizar la versión completa de PHP en caliente sobre un sistema de facturación en producción sin staging acarrea un riesgo inaceptable de romper dependencias, interrumpir transacciones en vuelo o corromper datos contables.
  - En su lugar, aplicamos una **medida de contención compensatoria**: cambiar `session.upload_progress.enabled = 0` en `php.ini` y recargar la configuración del servidor web (*graceful reload* de Apache en menos de un segundo).
  - Esta directiva desactiva únicamente una funcionalidad cosmética (la barra de progreso de subida de archivos grandes), la cual el sistema de facturación transaccional no utiliza.
  - Esto anula por completo la vulnerabilidad PHP2Shell sin tocar binarios, garantizando **cero riesgo de regresión funcional** y **continuidad 100% operativa**. El parche integral de versión se reserva para la ventana nocturna de mantenimiento con backups validados.

---

### Pregunta 2: El hosting no puede actualizar PHP hasta el viernes. ¿Qué compensamos y cómo lo verificamos?

* **Postura ejecutiva:** Aceptamos la restricción del proveedor pero **tomamos el control perimetral y de configuración local** para no quedar desprotegidos hasta el viernes.
* **Medidas compensatorias:**
  1. **Configuración local (`php.ini` o `.htaccess`):** Desactivar `session.upload_progress.enabled = 0`. Si el hosting no permite editar `php.ini` global, se inyecta la directiva mediante archivo de configuración local del virtual host o `.htaccess`: `php_flag session.upload_progress.enabled 0`.
  2. **Bloqueo en WAF / Reverse Proxy perimetral:** Si el hosting gestiona el servidor web por completo, configuramos una regla en nuestro WAF (Cloudflare / AWS WAF / Nginx perimetral) para bloquear de inmediato cualquier petición HTTP POST multipart que incluya el campo `PHP_SESSION_UPLOAD_PROGRESS` en el cuerpo o cabeceras.
  3. **Aislamiento de red:** Restringir el acceso administrativo y limitar las conexiones salientes del servidor web.
* **Cómo lo verificamos (evidencia técnica):**
  - Ejecutamos una petición de verificación CLI o archivo PHP de diagnóstico controlado:
    ```bash
    php -r "echo ini_get('session.upload_progress.enabled');"
    ```
    La salida debe ser `0` o vacía.
  - Lanzamos una prueba HTTP simulada enviando un campo `PHP_SESSION_UPLOAD_PROGRESS` y constatamos que el WAF responde con código `403 Forbidden` y que la sesión no crea variables en memoria.

---

### Pregunta 3: Node2Shell todavía no se explota en la práctica. ¿Justifica una ventana de cambio de emergencia? ¿Con qué evidencia cambiarías la decisión?

* **Postura ejecutiva:** **NO justifica una ventana de cambio de emergencia inmediata en horario comercial**, pero sí justifica **mitigación perimetral y un cambio programado en ventana regular (12 a 24 horas)**.
* **Argumentación:**
  - Una ventana de emergencia paraliza la operación transaccional de TransacRed S.A., genera fricción con clientes y aumenta el riesgo de error humano. No hay registros de explotación *in the wild* (cero entradas en CISA KEV al 29/10). Solo existe RCE demostrado en condiciones controladas de laboratorio.
  - La acción inmediata es mitigar en el API Gateway: desactivar la aceptación de peticiones con cabecera `Content-Encoding: br` (Brotli) para los endpoints de entrada, forzando a los clientes a utilizar `gzip` o JSON plano temporalmente.
* **¿Con qué evidencia cambiaríamos la decisión a emergencia (< 2 horas)?**
  1. Si CISA publica la inclusión de CVE-2026-111497 en el catálogo **KEV**.
  2. Si nuestros sensores de seguridad (SIEM / WAF) detectan payloads maliciosos anómalos o múltiples *crashes* (Segmentation Fault / Signal 11) en los workers de `node-lab`.
  3. Si se hace público un exploit weaponizado y confiable ejecutable vía peticiones HTTP comunes.

---

### Pregunta 4: ¿Qué le decimos a clientes y cuándo, sin dar detalles que ayuden a un atacante?

* **Postura ejecutiva:** **Comunicación proactiva de seguridad, transparente en el compromiso pero restrictiva en detalles técnicos explotables.**
* **Cuándo comunicar:**
  - *Fase 1 (Ahora - Durante mitigación):* **No se emite comunicado masivo público aún.** Alertar públicamente antes de aplicar las mitigaciones equivale a colocar una diana sobre nuestra infraestructura e invitar a escaneos automatizados. Solo se informa al Comité de Riesgos y Oficial de Cumplimiento.
  - *Fase 2 (Post-mitigación o si hay ventana de mantenimiento):* Notificar únicamente mantenimiento programado de rutina en horarios no pico (ej. *"Ventana de optimización de infraestructura y actualización de seguridad de 02:00 a 03:00 AM"*).
  - *Fase 3 (En caso de incidente confirmado):* Si se confirma filtración de datos de clientes, se activa el protocolo legal de notificación dentro de las 72 horas requeridas por regulaciones (LPDP / GDPR / BCRA), informando las medidas de remediación adoptadas.
* **Qué decir y qué omitir:**
  - **Qué decir:** *"En TransacRed S.A. monitoreamos proactivamente la seguridad de nuestras plataformas. Hemos implementado medidas preventivas de hardening y actualizaciones en nuestra capa perimetral para asegurar la integridad de sus transacciones. El servicio opera con total normalidad."*
  - **Qué omitir terminantemente:** Versiones exactas de software (ej. "usamos PHP 8.3.35 y Node 22"), bibliotecas vulnerables (Brotli), configuración de servidores, o el hecho de que se mitigó apagando `session.upload_progress`. Esos datos facilitan el perfilado a los cibercriminales.

---

### Pregunta 5: Si el atacante usa un agente de IA para post-explotación, ¿qué control nuestro sigue funcionando cuando el perímetro ya cayó?

* **Postura ejecutiva:** Cuando el perímetro cae y un agente autónomo ejecuta código, la única barrera efectiva es la **Contención por Diseño (Defensa en Profundidad en el Host y Red)**.
* **Controles activos que siguen funcionando:**
  1. **Red sin salida a Internet (`internal: true` / Firewall egress default-deny):** Los agentes autónomos de post-explotación (como los observados por Unit 42) dependen críticamente de conectividad saliente para descargar herramientas auxiliares (`curl`/`wget`), conectarse a servidores de Comando y Control (C2), resolver nombres DNS externos o exfiltrar datos. Nuestra prueba de laboratorio arrojó **`SIN SALIDA`** en todos los servicios. El agente queda sordo y ciego en un callejón sin salida.
  2. **Filesystem Read-Only (`read_only: true`):** El contenedor no permite escritura en disco. Un agente de post-explotación no puede compilar malware, modificar scripts del servidor web ni persistir en el sistema creando cronjobs o backdoors.
  3. **Privilegios mínimos (`cap_drop: ALL` y usuario no root):** Impide escalamiento de privilegios, manipulación de interfaces de red o inyección de procesos en el kernel.
  4. **Límites de memoria y PIDs (`pids_limit`, `mem_limit`):** Neutraliza ataques de bifurcación masiva (*fork bombs*) o escaneos agresivos en memoria que intenten agotar el nodo host.

---

### Pregunta 6: ¿Qué evidencia nos haría pasar de “monitorear” a “apagar”?

* **Postura ejecutiva:** Apagar un servicio transaccional tiene un costo financiero directo severo, por lo que se requiere **evidencia concreta de pérdida de control o compromiso activo de datos críticos**.
* **Criterios y evidencia para apagar inmediatamente:**
  1. **Persistencia o ejecución de procesos interactivos no autorizados:** Detección en `audit.log` de un proceso hijo del servidor web (`apache2` o `node`) ejecutando shells (`/bin/sh`, `/bin/bash`) seguido de comandos de reconocimiento (`whoami`, `cat /etc/passwd`, acceso a variables de entorno con secretos de base de datos) o apertura de puertos locales no autorizados (`nc`, `socat`).
  2. **Detección de exfiltración de datos o tráfico anómalo masivo:** Intentos repetidos de conexiones salientes hacia IPs externas no confiables o consultas volumétricas anormales a la base de datos transaccional desde el worker.
  3. **Modificación de archivos de negocio:** Integridad rota en código fuente, archivos `.env` alterados o volcados de memoria ilegítimos.
  4. **Pérdida de visibilidad / Compromiso del agente de seguridad:** Si el atacante intenta desactivar el servicio de telemetría o saturar los logs para cegar al equipo de respuesta.
* *Nota:* Intentos de escaneo fallidos o pings HTTP que devuelven errores 400/404/403 se mantienen en **"monitorear"** y se bloquean en el WAF.

---

### Pregunta 7: ¿Qué hacemos primero si el CERT nos avisa a las 9:40 de un martes?

* **Postura ejecutiva:** Se ejecuta de inmediato el protocolo de **Triage y Contención Rápida en 5 pasos ordenados**:
  1. **Paso 1 — Triage de Exposición e Inventario (9:40 – 9:50):** Verificar si el aviso del CERT involucra tecnologías en uso en nuestra organización, qué activos específicos están alcanzados y cuál es el vector de ataque exacto (ej. si requiere `mod_php`, autenticación o parámetros específicos).
  2. **Paso 2 — Aplicar Mitigación Rápida no Disruptiva (9:50 – 10:00):** Si existe un flag de configuración (como `session.upload_progress.enabled = 0` o reglas en WAF), aplicarlo de inmediato. Esto neutraliza la amenaza en minutos sin interrumpir la operación comercial de la empresa.
  3. **Paso 3 — Threat Hunting Retrospectivo en Logs (10:00 – 10:30):** Analizar los logs de acceso web y auditoría del sistema (`audit.log`) desde días previos al aviso en busca de Indicadores de Compromiso (IoCs) para responder la pregunta clave: *¿Nos atacaron antes de que el CERT avisara?*
  4. **Paso 4 — Convocatoria al Comité de Incidentes y Planificación:** Definir la ventana de parcheo definitivo con el equipo de infraestructura y comunicar el estado a la Dirección.
  5. **Paso 5 — Notificación y Registro Formal:** Registrar el ticket de incidente y documentar la cadena de custodia y cambios efectuados.

---

### Pregunta 8: ¿Cómo sabemos que el parche quedó aplicado y que la app sigue funcionando?

* **Postura ejecutiva:** La verificación exige **doble evidencia verificable**: inspección de versión/configuración interna y prueba funcional de extremo a extremo.
* **1. Verificación del parche / configuración:**
  - **En PHP:**
    - Inspección directa de directiva:
      ```bash
      docker compose exec php-lab php -r "echo ini_get('session.upload_progress.enabled');"
      ```
      (Debe devolver `0` o valor nulo).
    - Inspección de versión del runtime:
      ```bash
      docker compose exec php-lab php -v
      ```
      (Debe reflejar PHP 8.3.36 una vez aplicado el parche).
  - **En Node.js:**
    ```bash
    docker compose exec node-lab node -p "process.version + ' / brotli ' + process.versions.brotli"
    ```
    (Debe reflejar `v22.23.4 / brotli 1.1.1`).
* **2. Prueba funcional mínima (Smoke Test de continuidad del negocio):**
  - **Portal PHP:**
    - Realizar un `curl -I -s http://localhost:8080/` y constatar código HTTP `200 OK`.
    - Probar el inicio de sesión de usuario y la navegación entre páginas transaccionales para comprobar que las sesiones normales siguen funcionando correctamente a pesar de tener deshabilitado el upload progress.
  - **API Node.js:**
    - Realizar una petición POST válida a `/decode` con un payload comprimido con Brotli válido y constatar respuesta HTTP `200 OK` con el JSON decodificado esperado.
    - Realizar una petición a `/health` o endpoint raíz y validar respuesta correcta del framework Express.
