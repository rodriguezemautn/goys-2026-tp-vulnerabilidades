# Informe individual — Grupo 07

**Integrante:** Tomás Terruli  
**Fecha:** 06/11/2026  
**Destinatario:** Gerente de Operaciones / Comité de Crisis

---

## 1. Situación y riesgo

Se analizaron tres servicios de un laboratorio Docker: un portal PHP, una API Node.js y un servicio Python. El objetivo fue identificar vulnerabilidades críticas, priorizar su corrección y verificar el funcionamiento posterior.

El portal utilizaba PHP 8.3.35 con Apache mod_php, afectado por PHP2Shell (CVE-2026-109618 y CVE-2026-109619), vulnerabilidades que pueden permitir ejecución remota de código sin autenticación. La API utilizaba Node.js 22.23.3 y Python incorporaba Brotli 1.0.9, componentes afectados por Node2Shell (CVE-2026-111497).

Las vulnerabilidades tienen CVSS 9.2 y antecedentes de explotación activa. Sin embargo, los tres servicios estaban aislados de Internet en el laboratorio. En producción, el riesgo dependería de la exposición, los datos procesados y la criticidad de cada servicio.

## 2. Plan de acción priorizado

| Acción | Activo | Plazo | Responsable | Reversión |
|---|---|---|---|---|
| Mitigar y actualizar PHP a 8.3.36. | Portal PHP | 2 h | Infraestructura | Restaurar imagen anterior con autorización. |
| Actualizar Node.js a 22.23.4 y limitar Brotli innecesario. | API Node.js | 4 h | Desarrollo e infraestructura | Restaurar imagen anterior bajo control. |
| Actualizar Brotli a 1.2.1 y restringir accesos. | Python | 24 h | Administrador del servicio | Restaurar versión anterior si fuera indispensable. |
| Verificar servicios y registrar evidencias. | Todos | Tras cada cambio | Operaciones y seguridad | Detener o revertir el cambio si falla. |

Se priorizó PHP por la explotación conocida y el mayor riesgo asociado a mod_php; luego Node.js por el procesamiento de contenido Brotli, y finalmente Python por su menor exposición supuesta. El orden cambiaría ante evidencia de compromiso, exposición pública o mayor criticidad de otro servicio.

En el laboratorio se deshabilitó `session.upload_progress.enabled` como mitigación temporal y posteriormente se aplicaron los parches. PHP quedó en 8.3.36, Node.js en 22.23.4 y Brotli de Python en 1.2.1. Los tres servicios permanecieron saludables y respondieron correctamente a las pruebas HTTP.

Los plazos corresponden a una propuesta para producción. Las reversiones fueron documentadas, pero no ejecutadas porque reintroducirían versiones vulnerables.

## 3. Indicadores de compromiso

Una señal sospechosa sería que Apache, Node.js o Python ejecutaran inesperadamente procesos como `sh`, `bash`, `curl` o `wget`. También deberían investigarse solicitudes HTTP anómalas, descargas inesperadas y modificaciones no autorizadas.

Para confirmar un compromiso se necesitaría correlacionar procesos, horarios, solicitudes, usuarios y registros del sistema. Para descartarlo razonablemente se requerirían registros completos, comprobaciones de integridad y revisión de accesos.

El `audit.log` del laboratorio permite identificar comportamientos sospechosos, pero no incluye información suficiente de usuarios e IP de origen. Por eso, una alerta aislada no demuestra un ataque exitoso y la ausencia de alertas tampoco descarta compromisos anteriores.

Se verificaron las actualizaciones y el funcionamiento básico, pero no se realizaron análisis forenses ni pruebas de explotación, respetando las restricciones del ejercicio.

## 4. Transferencia

El mismo procedimiento podría aplicarse a una vulnerabilidad distinta, como CVE-2026-115560, mencionada en el material de la cátedra.

Primero se consultaría el aviso oficial para identificar el componente, las versiones afectadas, el impacto y la corrección disponible. Después se inventariarían los sistemas involucrados, incluyendo runtimes, dependencias e imágenes Docker.

La prioridad dependería del CVSS, la explotación real, la exposición y la criticidad del negocio. Se definirían responsables, plazos y mitigaciones temporales, seguidos del parche y las pruebas funcionales.

A diferencia del ejercicio, las medidas concretas deberían adaptarse a la nueva vulnerabilidad. No corresponde reutilizar automáticamente las mitigaciones de PHP o los parches de Brotli sin verificar su aplicabilidad.

## 5. Lecciones y procesos

El ejercicio demostró que gestionar vulnerabilidades implica más que actualizar software: requiere identificar activos, evaluar riesgos, decidir prioridades y verificar resultados.

Como mejoras, se propone mantener un inventario actualizado, centralizar registros, definir responsables y establecer procedimientos de cambios con evidencias antes/después y planes de reversión.

La comunicación con gerencia debe explicar el riesgo, las medidas adoptadas, los resultados comprobados y las limitaciones existentes, evitando afirmaciones que no estén respaldadas.

La principal conclusión es que una respuesta efectiva combina **prevención, mitigación, parcheo, detección, verificación y comunicación**, con decisiones justificadas mediante evidencia.