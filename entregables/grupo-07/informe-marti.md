# Informe individual — Grupo 07

**Integrante:** Martina Castellani  
**Fecha:** 07/11/2026  
**Destinatario:** Gerente de Operaciones / Comité de Crisis

## 1. Situación y riesgo

En este trabajo analizamos tres servicios que tenían versiones vulnerables: un portal PHP con Apache, una API desarrollada en Node.js y un servicio Python que utiliza Brotli.

Las versiones iniciales eran PHP 8.3.35, Node.js 22.23.3 y Brotli 1.0.9. Según la información que nos dio la cátedra, las vulnerabilidades tienen un CVSS de 9.2, por lo que representan un riesgo crítico.

Si estos servicios estuvieran publicados en Internet, podrían ser aprovechados por un atacante y afectar el funcionamiento o la seguridad del sistema. En nuestro laboratorio esto no ocurría, porque los contenedores estaban aislados y no tenían puertos publicados hacia el exterior.

Mi parte del trabajo consistió en revisar qué medidas de seguridad tenían los contenedores y comprobar si servían para limitar las consecuencias de un posible ataque.

## 2. Plan de acción priorizado

| Acción | Activo | Plazo | Responsable | Reversión |
|---|---|---|---|---|
| Aislar el servicio y desactivar temporalmente `session.upload_progress` | PHP | Primeras 2 horas | Operaciones y Seguridad | Restaurar la configuración anterior solo si es necesario y con controles adicionales |
| Actualizar a PHP 8.3.36 y comprobar su funcionamiento | PHP | Primeras 2 horas | Infraestructura | Volver a la versión anterior ante una falla grave, teniendo en cuenta que vuelve a ser vulnerable |
| Restringir Brotli cuando no sea necesario y actualizar Node.js a 22.23.4 | Node.js | Primeras 4 horas | Desarrollo y Operaciones | Restaurar la versión anterior solo con autorización |
| Actualizar Brotli a 1.2.1 | Python | Dentro de 24 horas | Desarrollo y Operaciones | Volver a la versión anterior únicamente si fuera indispensable |

Elegimos este orden considerando la gravedad de las vulnerabilidades, los antecedentes de explotación, la exposición que podría tener cada servicio y su importancia para el sistema. Estos plazos son una propuesta para un entorno real, no tiempos que hayamos medido en el laboratorio.

En las pruebas que realicé comprobé que la red de Docker estaba configurada como interna y que ninguno de los tres servicios podía conectarse a Internet.

También revisé que los contenedores tuvieran el sistema de archivos en modo solo lectura, las capacidades restringidas y límites de memoria y procesos.

PHP y Node.js tenían un máximo de 256 MB y 100 procesos, mientras que Python tenía 128 MB y 50 procesos.

Por último, revisé los usuarios. Node.js se ejecutaba con el usuario `node` y Python con `nobody`. En PHP encontré que Apache tenía un proceso principal ejecutándose como `root`, pero los procesos que atendían las solicitudes utilizaban `www-data`.

## 3. Indicadores de compromiso

Para detectar si alguno de estos servicios fue comprometido, revisaría si aparecen procesos que normalmente no deberían ejecutarse desde Apache, Node.js o Python.

Por ejemplo, sería sospechoso que alguno iniciara una terminal como `sh` o `bash`, o herramientas como `curl` y `wget` sin una razón justificada.

De todas formas, encontrar uno de estos procesos no significa necesariamente que hubo un ataque. Habría que revisar otros registros, las conexiones realizadas y qué actividad estaba ocurriendo en ese momento.

En mi parte comprobé que los intentos de conexión a Internet fallaban en los tres contenedores. Esto demuestra que el aislamiento funcionó en esas pruebas, pero no permite confirmar ni descartar que haya ocurrido un ataque.

Además, algunos controles solamente los verificamos revisando su configuración. No hicimos pruebas de agotamiento de recursos, escalada de privilegios ni escritura en el sistema de archivos.

## 4. Transferencia

Si tuviera que aplicar este mismo procedimiento a otra vulnerabilidad, como la CVE-2026-115560 que aparece como ejemplo en la consigna, empezaría buscando información oficial para entender qué componente afecta, qué versiones son vulnerables y si existe una actualización disponible.

Después revisaría si ese componente se utiliza en alguno de los sistemas de la organización y qué tan expuesto está.

Con esa información definiría la prioridad, teniendo en cuenta la gravedad, si se conoce explotación activa y qué consecuencias podría tener para el servicio.

Si el sistema estuviera expuesto a Internet o hubiera señales de explotación, actuaría con mayor urgencia. Si todavía no existiera un parche, aplicaría restricciones de acceso y otras medidas de contención hasta poder actualizarlo.

## 5. Lecciones y procesos

Este trabajo me permitió entender que no alcanza solamente con actualizar los servicios. También es importante tener medidas de seguridad que reduzcan el daño si aparece una vulnerabilidad.

Para mejorar el proceso, mantendría un inventario actualizado, revisaría periódicamente las configuraciones de los contenedores y guardaría los registros necesarios para investigar posibles incidentes.

También definiría quién es responsable de cada tarea, qué plazos se deben cumplir y cómo actuar si una actualización genera problemas.

Por último, considero importante comunicar los riesgos y las decisiones de forma clara, además de comprobar que los servicios sigan funcionando después de aplicar los cambios.