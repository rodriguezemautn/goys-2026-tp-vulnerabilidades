# Informe individual — Grupo 03

**Integrante:** Irineo Hiriart  
**Grupo:** 03  
**Fecha:** 29/10/2026  
**Destinatario:** Gerencia de Operaciones

## 1. Situación y riesgo

Mi recomendación es mantener los servicios actualizados y conservar los controles de aislamiento. La actualización fue comprobada, pero las pruebas realizadas no alcanzan para autorizar por sí solas una publicación en Internet.

El caso de análisis es una organización ficticia que utiliza un portal PHP para administrar legajos, una API Node.js y un servicio Python. Una interrupción podría frenar la gestión de documentación. Un compromiso también podría afectar los datos y permitir que el atacante intente alcanzar otros servicios.

El inventario inicial identificó versiones consideradas vulnerables por la consigna: PHP 8.3.35, Node 22.23.3 y Brotli 1.0.9 en Python. Los tres servicios estaban dentro de una red Docker interna y no tenían puertos publicados.

Considero que el riesgo debe separarse en dos aspectos. Las fallas tienen una gravedad técnica alta, pero la posibilidad de alcanzarlas depende del despliegue. Nuestro aislamiento reduce la exposición externa, aunque no protege de toda actividad originada dentro de la red.

PHP recibió prioridad por la explotación real informada en el material. Node y Python también necesitaban corrección. No justificaría mantenerlos vulnerables solamente porque todavía no se conozcan ataques reales contra esa falla.

## 2. Plan de acción priorizado

Organizaría la respuesta con un responsable de cambios y otro de verificación. Así se evita que una actualización se considere terminada apenas finaliza el comando.

| Acción | Activo | Plazo desde el aviso | Responsable | Reversión |
|---|---|---|---|---|
| Registrar versiones y confirmar las vías de acceso | Los tres servicios | 0–15 minutos | Irineo | Sin cambios que revertir |
| Reducir la superficie vulnerable de PHP | Portal | 0–15 minutos | Facundo | Recuperar la configuración anterior si afecta una función necesaria, manteniendo restricciones |
| Aplicar versiones corregidas y consultar las rutas principales | Los tres servicios | Dentro de 90 minutos, comenzando por PHP | Facundo | Volver a imágenes anteriores bajo aislamiento si hay una incompatibilidad |
| Comprobar controles efectivos y revisar señales sospechosas | Los tres servicios | Durante las primeras dos horas | Irineo, con apoyo de Facundo | Revisar cada restricción antes de retirarla |
| Informar resultado, límites y riesgo restante | Organización | Al cierre de la revisión | Irineo | Corregir la comunicación si aparece nueva evidencia |

Facundo realizó la mitigación de PHP y ejecutó el parche. Las evidencias posteriores muestran PHP 8.3.36, Node 22.23.4 y Brotli 1.2.1 en Python. Los tres servicios quedaron `healthy` y respondieron a las consultas de sus rutas principales.

Desde el punto de vista de contención, se comprobó que la red era interna y que las solicitudes externas fallaban. También se inspeccionaron filesystem de solo lectura, límites de memoria y procesos, usuarios y permisos especiales.

Estos controles tienen límites. Node y Python utilizan usuarios sin privilegios, pero Apache mantiene un proceso principal como `root`. PHP también conserva cinco capabilities. El filesystem restringe la escritura en la raíz, aunque existen espacios temporales escribibles. Por eso no afirmaría que una ejecución de código sería inofensiva.

La reversión quedó preparada como procedimiento, sin ejecutarse. Antes de autorizar una operación real pediría pruebas de las funciones utilizadas por la organización, además de las consultas básicas realizadas.

Evidencias: [inventario inicial](capturas/01-inventario-antes.txt), [funcionamiento posterior](capturas/10-funcional-despues.txt), [salida externa](capturas/11-contencion-despues.txt) y [controles efectivos](capturas/12-controles-efectivos.txt).

## 3. Indicadores de compromiso

Usaría como alerta inicial la creación inesperada de shells y herramientas de descarga desde los servicios. El log del ejercicio muestra ese comportamiento en los hosts del portal, la API y Python.

Para decidir una contención urgente buscaría evidencia adicional: ejecución de comandos sin autorización, cambios en archivos, acceso a credenciales o conexiones hacia destinos sin relación con el servicio. Si esas señales se sostienen, aislaría el componente y preservaría los registros antes de continuar.

También hay situaciones que pueden parecer maliciosas y ser legítimas. Las sesiones de Bash iniciadas por SSH podrían corresponder a administración. Para aclararlo necesitaríamos identificar usuario, origen y tarea autorizada.

No encontrar actividad sospechosa durante unos minutos no permite descartar una intrusión. El log disponible tiene una ventana corta y carece de información para reconstruir todo el acceso. Además, es sintético y no representa un compromiso real de nuestros contenedores.

A gerencia le informaría hechos confirmados y decisiones concretas. A los clientes les comunicaría una interrupción o afectación comprobada, sin adelantar conclusiones sobre pérdida de datos ni publicar detalles internos que favorezcan nuevos ataques.

## 4. Transferencia

Para aplicar el mismo criterio a otro caso considero CVE-2024-4577. Esta vulnerabilidad afecta determinadas instalaciones de PHP-CGI con Apache en Windows y depende de condiciones de configuración. Puede permitir ejecución de código.

La primera decisión sería comprobar si esas condiciones existen. No actualizaría servicios por asociación con el nombre PHP sin revisar el aviso y el entorno. En nuestro laboratorio, Linux y la SAPI `apache2handler` no corresponden al escenario de PHP-CGI en Windows.

Si apareciera un servidor que sí cumpliera las condiciones, lo incorporaría al plan según exposición y función. Si estuviera publicado y procesara documentación sensible, propondría restringirlo mientras se prepara la corrección.

Este caso demuestra por qué el inventario debe registrar sistema operativo y modo de ejecución, además de la versión. También muestra que una mitigación válida para una falla no necesariamente sirve para otra.

Fuente: [registro de CVE-2024-4577](https://www.cve.org/CVERecord?id=CVE-2024-4577).

## 5. Lecciones y procesos

Establecería un cierre de cambio con tres comprobaciones: versión instalada, funcionamiento de la aplicación y controles de seguridad activos. Cada resultado debe tener evidencia y un responsable.

Revisaría también cómo se conserva la actualización. En este laboratorio, el script utiliza versiones corregidas sin modificar `versions.env`. Volver a arrancar con los valores iniciales puede recuperar componentes vulnerables.

Otra mejora sería conservar registros fuera de los contenedores. Los logs temporales pueden perderse al eliminar el entorno, lo que dificulta una investigación posterior. El apagado debe realizarse después de guardar la evidencia necesaria.

Finalmente, dejaría explícito quién puede aceptar una interrupción o un riesgo residual. El equipo técnico debe explicar las consecuencias y proponer alternativas. La decisión de negocio necesita esa información, no solamente un mensaje indicando que el parche terminó.