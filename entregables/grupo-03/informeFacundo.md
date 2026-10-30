# Informe individual — Grupo 03

**Integrante:** Facundo Daza  
**Fecha:** 29/10/2026  
**Destinatario:** Gerente de Operaciones

## 1. Situación y riesgo

Para este análisis tomo una organización ficticia que administra legajos mediante un portal PHP, una API en Node.js y un servicio interno Python. Si estos servicios fueran comprometidos, podrían quedar fuera de funcionamiento o permitir el acceso y la modificación de documentación.

En el laboratorio encontramos PHP 8.3.35, Node 22.23.3 y Brotli 1.0.9 en Python. Según la información del TP, esas versiones estaban afectadas. El portal usaba PHP integrado con Apache y tenía habilitado el progreso de subida de archivos.

Le di prioridad a PHP porque la consigna informa que la vulnerabilidad ya se estaba explotando en ataques reales. Node y Python también necesitaban actualizarse, pero el escenario no indicaba explotación real confirmada de la falla de Brotli.

Los tres servicios estaban en una red interna y sin puertos publicados a Internet. Eso reduce la exposición, pero no corrige las vulnerabilidades. También hay que considerar que pueden comunicarse entre sí.

## 2. Plan de acción priorizado

El orden que propongo es confirmar qué está afectado, reducir el riesgo y aplicar las correcciones sin perder de vista el funcionamiento del servicio.

| Acción | Plazo desde el aviso | Responsable | Reversión |
|---|---|---|---|
| Revisar versiones, exposición y guardar registros de los tres servicios | Primeros 15 minutos | Irineo | Son consultas, no modifican el sistema |
| Aplicar la mitigación temporal de PHP | Primeros 15 minutos | Facundo | Restaurar la configuración anterior si falla, manteniendo restricciones |
| Actualizar PHP y probar el portal | Primeros 45 minutos | Facundo | Recuperar la imagen anterior bajo aislamiento |
| Actualizar Node y Brotli de Python y probar ambos servicios | Primeros 90 minutos | Facundo | Recuperar las imágenes anteriores bajo aislamiento |
| Revisar controles y comunicar resultados | Dentro de las dos horas | Ambos | Retirar restricciones cuando el riesgo esté controlado |

Estos plazos son una propuesta. En el laboratorio, el script actualizó los tres servicios en una misma operación.

Primero deshabilité el progreso de subida de PHP y comprobé que el portal siguiera respondiendo. Después apliqué el parche. El resultado fue PHP 8.3.36, Node 22.23.4 y Brotli 1.2.1 en Python.

Los tres servicios quedaron `healthy`. El portal devolvió su página y Node y Python respondieron HTTP 200. Las pruebas de salida a Internet fallaron en los tres contenedores. Al terminar, apagué y eliminé el entorno.

La reversión quedó documentada, pero no la ejecutamos. Tampoco probamos subidas, descompresión de cuerpos ni carga. Por eso podemos afirmar que las versiones cambiaron y las rutas principales respondieron, pero no que se probó toda la aplicación.

Evidencias: [parche](capturas/09-parche.txt), [pruebas funcionales](capturas/10-funcional-despues.txt), [controles](capturas/12-controles-efectivos.txt) y [limpieza](capturas/13-limpieza.txt).

## 3. Indicadores de compromiso

Investigaría especialmente que Apache, Node o Python empiecen a ejecutar shells o herramientas de descarga sin una función que lo justifique. En el log aparecen casos de Apache lanzando `sh` y `wget`, Node ejecutando `sh` seguido de `curl`, y Python lanzando un shell para consultar información del sistema.

Son señales sospechosas, pero no alcanzan para afirmar que hubo robo de datos o que se utilizó una vulnerabilidad concreta. El registro es sintético y no demuestra un ataque contra nuestros contenedores.

Para confirmar un incidente buscaría solicitudes relacionadas, comandos no autorizados, archivos modificados y conexiones inesperadas. También revisaría si alguna tarea legítima explica la actividad. Por ejemplo, una sesión `sshd → bash` podría ser de un administrador.

Con este log no podemos descartar un compromiso. Faltan usuarios, origen del acceso inicial, resultados de los comandos e historial suficiente. Si encontrara indicios fuertes, aislaría el servicio y conservaría la evidencia antes de seguir modificándolo.

A gerencia le comunicaría el impacto conocido, las medidas tomadas y cuándo habrá una nueva actualización. No afirmaría una filtración sin pruebas ni divulgaría detalles que faciliten otro ataque.

## 4. Transferencia a otra vulnerabilidad

Elegí CVE-2024-4577, una vulnerabilidad de PHP-CGI en Windows que puede permitir ejecución de código bajo determinadas configuraciones. Para evaluarla hay que revisar versión, sistema operativo, modo de ejecución y condiciones de configuración. No alcanza con saber que el servidor utiliza PHP.

En nuestro laboratorio el servicio corre en Linux y usa `apache2handler`. Por esas condiciones, no corresponde considerarlo afectado por esta falla de PHP-CGI en Windows.

Si encontrara otro servidor que sí cumpliera las condiciones, revisaría su exposición, importancia y corrección disponible. Tampoco asumiría que deshabilitar el progreso de subida sirve para este caso. Cada mitigación debe responder a la falla que intenta controlar.

Fuente: [registro de CVE-2024-4577](https://www.cve.org/CVERecord?id=CVE-2024-4577).

## 5. Lecciones y procesos

Mantendría un inventario con versiones, configuración, exposición y responsable de cada servicio. Mirar solo las dependencias de la aplicación puede dejar afuera componentes que vienen dentro de Node u otros programas.

También dejaría preparada la prueba funcional y la reversión antes de cambiar algo. En este laboratorio vimos que `parchear.sh` no modifica `versions.env`, por lo que un arranque con la configuración inicial puede recuperar las versiones anteriores. Eso debe quedar documentado para evitar volver atrás por error.

Mejoraría los registros para relacionar solicitudes, procesos, usuarios y conexiones. Con más contexto se puede investigar sin confundir una actividad legítima con un ataque.

El cierre debe decir qué se corrigió, qué se probó y qué quedó sin verificar. Para mí, esa distinción es necesaria para que gerencia decida con información real y para que el próximo responsable pueda continuar el trabajo.