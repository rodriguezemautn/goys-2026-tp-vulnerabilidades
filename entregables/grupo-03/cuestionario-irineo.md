# Cuestionario de entrada — Clase 10 (PHP2Shell / Node2Shell)

**Alumno:** Irineo Hiriart (irineoHiriart215) · **Grupo:** 03 · **Fecha:** 29/10/2026

---

## Parte A

**1.** Dos vulnerabilidades tienen CVSS 4.0 9.2. Una está expuesta a Internet y se explota en el mundo real; la otra está en un servicio interno sin datos críticos y solo tiene PoC de laboratorio. ¿Cuál priorizás primero y por qué? Nombrá al menos dos criterios además del CVSS.

Respuesta: Priorizo la vulnerabilidad expuesta a Internet y explotada en el mundo real. Ambas tienen CVSS 9.2, así que hay que mirar el contexto para decidir. Los criterios son: exposición, porque la expuesta puede ser atacada desde Internet y la otra solo es alcanzable desde la red interna; explotación real, porque la expuesta está confirmada como explotada (por ejemplo, en el catálogo KEV de CISA) y la otra solo tiene un PoC de laboratorio; y criticidad del activo, porque el servicio interno no tiene datos críticos.


**2.** PHP2Shell (CVE-2026-109618 y CVE-2026-109619) está en el **núcleo de PHP**. Un sitio corre WordPress actualizado, pero con PHP 8.3.30. ¿Está afectado? ¿Por qué?

Respuesta: Sí, está afectado. PHP2Shell está en el núcleo de PHP, no en la aplicación. Aunque WordPress esté actualizado, el runtime de PHP sigue sin el parche. El sitio queda expuesto a peticiones que procesa PHP, aunque la aplicación esté al día.


**3.** El equipo de sistemas actualizó el core de Drupal y puso el sitio en modo mantenimiento. ¿Eso protege contra PHP2Shell? Justificá.

Respuesta: No, no protege. El modo mantenimiento y la actualización de Drupal actúan a nivel de aplicación, pero PHP2Shell está en el núcleo de PHP y puede ejecutarse antes de que la aplicación procese el request, sobre todo con mod_php. El servidor sigue escuchando y PHP sigue recibiendo y procesando las peticiones, así que el motor vulnerable se ejecuta igual. La solución es actualizar PHP a una versión corregida o aplicar mitigaciones en el runtime.


**4.** Node2Shell (CVE-2026-111497) está en el decodificador Brotli. Mencioná **dos caminos** por los que una aplicación puede llegar al decoder sin llamar directamente a una API de Brotli.

Respuesta: 
    1. fetch(): descomprime automáticamente las respuestas, incluidas las Content-Encoding: br. Si la app consume una respuesta Brotli de un servidor no confiable, pasa por el decoder sin llamar a ninguna API de Brotli.
    2. Express / body-parser: descomprimen por defecto los cuerpos de request con Content-Encoding: br. Un atacante puede enviar un body Brotli a la API y llegar al decoder sin que la app lo pida.


**5.** ¿Qué diferencia hay entre `npm audit` limpio y una imagen Docker segura para Node2Shell? ¿Dónde vive el decoder?

Respuesta: npm audit solo revisa las dependencias declaradas en el package.json. El decoder de Brotli no vive ahí: viene embebido en el runtime de Node.js (el binario). Por eso un npm audit limpio no dice nada sobre Node2Shell. Una imagen Docker segura es la que incluye una versión corregida del runtime, además del sistema operativo y las librerías compartidas. En el laboratorio se vio esto: npm ls no mostró ningún paquete brotli, pero el runtime de Node traía su propio Brotli.


**6.** ¿Por qué un inventario basado solo en el manifiesto de dependencias puede fallar con Brotli? Pensá en runtimes, binarios, appliances y copias vendorizadas.

Respuesta: Los manifiestos de dependencia unicamente registran paquetes y librerias de alto nivel declarados para el gestor de paquetes del lenguaje. No contemplan versiones compiladas del runtime, binarios precompilados o appliances cerrados donde el codigo fuente no esta expuesto y copias estaticas de codigo incrustadas dentro de otros componentes sin usar el gestor de paquetes tradicional. Por eso un inventario basado solo en el manifiesto subestima la exposición real, y hay que inventariar también imágenes, binarios y runtimes.


**7.** Ordená de mayor a menor urgencia y justificá: (a) CVE 9.2 en un servicio interno sin datos críticos, (b) CVE 7.5 expuesto a Internet y en KEV, (c) CVE 9.2 con PoC de laboratorio y sin explotación real, (d) CVE 9.2 en un appliance EOL que no se puede parchear.

Respuesta: 1° (b): expuesto a Internet y en KEV. Hay explotación real confirmada, así que el riesgo de compromiso es inmediato aunque el CVSS sea menor.
2° (d): CVE crítico en un appliance EOL sin parche posible. Hay que compensar ya con aislamiento de red, restricción de acceso y monitoreo, y planificar su reemplazo. Si además está expuesto a Internet, pasaría al primer lugar.
3° (c): severidad crítica pero solo con PoC de laboratorio y sin ataques conocidos. Se parchea con prioridad y se monitorea, porque un PoC puede convertirse en explotación real.
4° (a): servicio aislado en red interna y sin datos críticos. Se parchea en el ciclo normal.


**8.** Un PHP worker empieza a lanzar `sh`, `curl` o `wget` después de un request sospechoso. ¿Qué señal de detección construirías y qué falso positivo esperarías?

Respuesta: Señal: una regla sobre el log de auditoría de procesos que alerte cuando un worker de PHP (padre apache2 o php-fpm) crea un hijo sh, bash, curl o wget. Un portal web normal no necesita lanzar shells ni descargar archivos, y es lo que se ve cuando alguien ejecuta comandos tras explotar el servidor.
Falso positivo esperado: aplicaciones PHP que usan funciones del sistema por una razón legítima, por ejemplo un plugin que genera miniaturas con una herramienta externa o un script de respaldo. Se distingue revisando los argumentos y verificando que sea una función conocida de la aplicación; las excepciones legítimas se documentan.


---

## Parte B

Sistema elegido: Aplicación Web Corporativa de Pagos en PHP/Node

**1. ¿Qué datos necesitarías para saber si está afectado por PHP2Shell y por Node2Shell? (al menos 5)**
1. Version exacta del runtime.
2. Metodo de despliegue.
3. Modulos y extensiones cargados.
4. Matriz de exposicion a red.
5. Inventario de dependecias vendoreadas.

**2. ¿Qué es lo que todavía no sabés y cómo lo averiguarías? (tres líneas)**
Lo que todavía no sé: si los filtros de borde (proxy, WAF) bloquean cargas maliciosas dirigidas al motor, y qué librerías del sistema operativo base incluyen Brotli. Lo averiguaría revisando la configuración del proxy y del WAF, escaneando las versiones del runtime y auditando la imagen base del contenedor.

**3. ¿Qué harías en las primeras 2 horas si el CERT te avisa de un RCE crítico? (5 acciones, en orden)**
1. Confirmar si estoy afectado y expuesto (versiones y exposición de red) y avisar a los responsables.
2. Mitigación temporal: reglas defensivas en el borde y restricción o aislamiento del sistema si hay explotación activa.
3. Hardening: deshabilitar los módulos o extensiones afectados cuando se pueda.
4. Parche oficial: probarlo, desplegarlo con plan de reversión y verificar que la aplicación sigue funcionando.
5. Revisar los logs en busca de indicadores de compromiso, preservar evidencia, monitorear y comunicar a gerencia.