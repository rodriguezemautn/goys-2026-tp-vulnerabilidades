# Cuestionario de entrada — Clase 10 (PHP2Shell / Node2Shell)

**Individual · 25 minutos · se entrega antes de la clase**
**Objetivo:** llegar con los conceptos mínimos para decidir, no para memorizar CVE.

> Respondé sin buscar durante el cuestionario. Si no sabés algo, escribí **“no lo sé”**
> y una línea de cómo lo averiguarías. Eso también se evalúa.

---

## Parte A — 8 preguntas

**1.** Dos vulnerabilidades tienen CVSS 4.0 9.2. Una está expuesta a Internet y se explota en el mundo real; la otra está en un servicio interno sin datos críticos y solo tiene PoC de laboratorio. ¿Cuál priorizás primero y por qué? Nombrá al menos dos criterios además del CVSS.

Se prioriza primero la que está expuesta a Internet y se explota en el mundo real. El CVSS mide gravedad intrínseca, pero no alcanza para decidir el orden de parcheo. Criterios además del CVSS:

- **Explotación real:** si el CVE está en CISA KEV o hay explotación confirmada, el riesgo de compromiso es inminente.
- **Exposición:** un servicio público frente a Internet tiene una superficie de ataque mucho mayor que uno interno sin datos críticos.

Otros criterios relevantes: criticidad del activo (¿procesa datos sensibles o facturación?), disponibilidad de parche y ventana de cambio, y el daño potencial si se vulnera.

---

**2.** PHP2Shell (CVE-2026-109618 y CVE-2026-109619) está en el núcleo de PHP. Un sitio corre WordPress actualizado, pero con PHP 8.3.30. ¿Está afectado? ¿Por qué?

Sí, está afectado. PHP2Shell es una vulnerabilidad del **runtime de PHP** (núcleo/interprete), no de la aplicación WordPress. Tener el CMS actualizado no protege porque el ataque puede ejecutarse en el worker de PHP **antes** de que la aplicación procese el request (especialmente en Apache con mod_php). PHP 8.3.30 es anterior a la versión corregida (8.3.36 o superior), por lo que el runtime es vulnerable independientemente del sitio que corra encima.

---

**3.** El equipo de sistemas actualizó el core de Drupal y puso el sitio en modo mantenimiento. ¿Eso protege contra PHP2Shell? Justificá.

No. El modo mantenimiento detiene la aplicación Drupal, pero no detiene la vulnerabilidad en el intérprete de PHP. PHP2Shell se aprovecha del núcleo de PHP (por ejemplo, en mod_php o PHP-FPM), por lo que un request malicioso aún puede alcanzar al worker y disparar la corrupción de memoria o RCE antes de que la aplicación entre en juego. Actualizar el CMS y poner modo mantenimiento no parchea el runtime.

---

**4.** Node2Shell (CVE-2026-111497) está en el decodizador Brotli. Mencioná dos caminos por los que una aplicación puede llegar al decoder sin llamar directamente a una API de Brotli.

1. **`fetch()` del navegador o cliente HTTP:** descomprime automáticamente respuestas con `Content-Encoding: br`, por lo que el decoder de Brotli se invoca implícitamente al recibir la respuesta.
2. **Express 5 / body-parser 2:** descomprimen bodies de request con codificación `br` por defecto, antes de que la aplicación los procese.

Otros caminos válidos: clientes HTTP de Python con Brotli instalado, Envoy/Istio con el decompresor habilitado, y .NET si se habilita la descompresión.

---

**5.** ¿Qué diferencia hay entre `npm audit` limpio y una imagen Docker segura para Node2Shell? ¿Dónde vive el decoder?

`npm audit` solo revisa dependencias de JavaScript declaradas en `package.json`. El decoder de Brotli en Node.js **vive embebido en el runtime** (se expone como `process.versions.brotli`), no como un paquete npm instalado por la app. Por eso `npm audit` puede estar limpio mientras la imagen de Node siga usando un runtime con Brotli vulnerable. Una imagen Docker segura requiere actualizar la imagen base de Node.js a una versión con Brotli parcheado (por ejemplo, Node 22.23.4 o superior), no solo correr `npm audit`.

---

**6.** ¿Por qué un inventario basado solo en el manifiesto de dependencias puede fallar con Brotli? Pensá en runtimes, binarios, appliances y copias vendorizadas.

Porque Brotli puede estar presente sin aparecer en el manifiesto de la aplicación:

- **Runtimes:** embebido en Node.js, Bun, Python o .NET (no declarado en `package.json` ni `requirements.txt`).
- **Binarios del sistema:** instalado como paquete del SO (apt, apk, yum) dentro del contenedor o host.
- **Appliances / contenedores base:** viene precargado en la imagen base o en dispositivos de red.
- **Copias vendorizadas:** copiadas directamente en el código o imagen sin pasar por un gestor de paquetes.

Un inventario confiable debe inspeccionar el runtime, las imágenes de contenedor y el sistema operativo, no solo los manifiestos de dependencias de la app.

---

**7.** Ordená de mayor a menor urgencia y justificá:  
(a) CVE 9.2 en un servicio interno sin datos críticos,  
(b) CVE 7.5 expuesto a Internet y en KEV,  
(c) CVE 9.2 con PoC de laboratorio y sin explotación real,  
(d) CVE 9.2 en un appliance EOL que no se puede parchear.

| Orden | Caso | Justificación |
|-------|------|---------------|
| 1 | **(b)** CVE 7.5 expuesto a Internet y en KEV | Explotación real confirmada (KEV) + exposición directa a Internet. Es el riesgo más inminente, aunque el CVSS sea menor. |
| 2 | **(c)** CVE 9.2 con PoC de laboratorio sin explotación real | Gravedad alta y PoC funcional, pero aún no hay confirmación de explotación en el mundo real. Priorizar si el activo es accesible o crítico. |
| 3 | **(a)** CVE 9.2 en servicio interno sin datos críticos | Gravedad alta, pero exposición limitada (interno) y sin datos sensibles; menor urgencia relativa que los anteriores. |
| 4 | **(d)** CVE 9.2 en appliance EOL no parcheable | Aunque sea 9.2, si no se puede parchear la acción no es "aplicar parche" sino contención/aislamiento/reemplazo, por lo que la urgencia de parcheo es nula; requiere plan de mitigación compensatoria. |

---

**8.** Un PHP worker empieza a lanzar `sh`, `curl` o `wget` después de un request sospechoso. ¿Qué señal de detección construirías y qué falso positivo esperarías?

Señal de detección: una regla que alerte cuando un proceso de aplicación (`apache2`, `php-fpm`, `php`) cree como hijo un proceso `sh`, `bash`, `curl`, `wget` o `nc`. En pseudocódigo:

```
ppid_comm IN (apache2, php-fpm, php) AND comm IN (sh, bash, curl, wget, nc) → alerta alta
```

**Falso positivo esperado:** tareas legítimas del servidor que invocan un shell, por ejemplo scripts de salud (healthchecks), tareas de mantenimiento programadas o procesos del propio servidor que lancen workers con el mismo nombre (`apache2 → apache2`). Se reduce con una lista blanca de argumentos (`args`) conocidos y horarios esperados.

---

## Parte B — Tarea corta

Elegí un sistema real o ficticio (por ejemplo, el portal de una cooperativa con
WordPress y una API en Node.js) y respondé:

1. **¿Qué datos necesitarías** para saber si está afectado por PHP2Shell y por
   Node2Shell? Listá al menos 5.
2. **¿Qué es lo que todavía no sabés** y cómo lo averiguarías? Tres líneas.
3. **¿Qué harías en las primeras 2 horas** si el CERT te avisa de un RCE crítico?
   Listá 5 acciones, en orden.

Sistema ficticio: **una clínica odontológica con sistema de agendamiento de turnos desarrollado en PHP (Laravel) y una API de recordatorios automáticos por WhatsApp/SMS en Node.js.**

### 1. ¿Qué datos necesitarías para saber si está afectado por PHP2Shell y por Node2Shell? Listá al menos 5.

1. **Versión de PHP y SAPI** del servidor que corre el sistema de turnos (mod_php, PHP-FPM, php-cgi).
2. **Versión de Node.js y `process.versions.brotli`** de la API de recordatorios.
3. **Si los servicios están expuestos a Internet** (puertos publicados, proxy inverso, balanceador o reglas de firewall que permitan entrada externa).
4. **Si las aplicaciones procesan contenido no confiable** (formularios de agendamiento y subida de archivos de pacientes en PHP; bodies HTTP con `Content-Encoding: br` en la API de Node).
5. **Versión de Brotli en otros componentes del stack** (por ejemplo, si la clínica usa Python para reportes, .NET en alguna integración, o Envoy/Istio como proxy).
6. **Presencia de WAF, reglas de red o segmentación** que restrinjan el acceso al sistema de turnos y a la API de recordatorios.

---

### 2. ¿Qué es lo que todavía no sabés y cómo lo averiguarías? Tres líneas.

No sé si existe un proxy inverso o un balanceador que exponga el sistema de turnos o la API de recordatorios a Internet más allá de lo que asumo. Lo averiguaría revisando la configuración del proxy/balanceador y los grupos de seguridad o reglas de firewall del servidor. Tampoco sé con certeza si la API de Node descompone cuerpos Brotli por defecto o si el sistema de turnos permite subida de archivos sin restricciones; lo verificaría inspeccionando el código de la aplicación y la configuración del servidor web.

---

### 3. ¿Qué harías en las primeras 2 horas si el CERT te avisa de un RCE crítico? Listá 5 acciones, en orden.

1. **Inventario rápido:** identificar todos los activos que usan la versión vulnerable del runtime (PHP y Node.js) y determinar su exposición a Internet.
2. **Mitigación inmediata:** aplicar controles de configuración disponibles (por ejemplo, deshabilitar `session.upload_progress.enabled` en PHP o reglas de WAF que bloqueen cuerpos `Content-Encoding: br`) para reducir la superficie de ataque mientras se prepara el parche.
3. **Aislamiento de red:** restringir el acceso a los servicios afectados mediante reglas de firewall o segmentación para bloquear posible explotación externa.
4. **Preparación del parche:** descargar las versiones corregidas, probarlas en un entorno de staging y definir una ventana de cambio con los responsables del sistema de turnos.
5. **Comunicación:** informar a la dirección de la clínica y al equipo de sistemas el estado de los servicios, qué se hizo, qué riesgo residual queda y cuál es el plan de parcheo con horarios estimados.

---

## Entrega

Subí tu respuesta al aula virtual antes de la clase. En clase se discuten los
errores comunes, no las respuestas correctas.
