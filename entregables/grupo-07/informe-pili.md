# Informe individual — Grupo 07

**Integrante:** Pilar Giannelli  
**Fecha:** 08/11/2026  
**Destinatario:** Gerente de Operaciones / Comité de Crisis

## 1. Situación y riesgo

En el trabajo analizamos tres servicios que tenían versiones vulnerables. Uno era un portal hecho en PHP que corría sobre Apache, con PHP 8.3.35. Otro era una API en Node.js 22.23.3, y el último un servicio interno en Python que usaba la librería Brotli en la versión 1.0.9.

Las vulnerabilidades que vimos fueron dos. La primera es PHP2Shell, que permite que alguien ejecute código en el servidor sin tener usuario ni contraseña. La segunda es Node2Shell, que es un error en la parte que descomprime datos en formato Brotli y que afecta tanto a Node.js como a Python. Las dos tienen una gravedad de 9.2 sobre 10 y ya se están usando en ataques reales, por eso CISA las agregó a su lista de vulnerabilidades explotadas.

A mí me tocó la parte de detección, que consistía en revisar el registro de procesos de los servidores para ver si había señales de que alguien ya las hubiera aprovechado. Y encontré cosas que cambian bastante el panorama. En menos de tres minutos, los tres servicios ejecutaron comandos que no tienen nada que ver con lo que hacen normalmente. En el portal se ejecutó un comando para ver con qué usuario estaba corriendo y después una descarga desde una IP externa. En la API también hubo una descarga desde otra IP del mismo rango, y en el servicio Python se pidió información del sistema.

Por eso creo que no se trata solamente de servidores que hay que actualizar. Para mí es un incidente probable en el portal y en la API, y posible en el servicio interno. De todas formas, el registro que teníamos es de laboratorio y tiene bastantes límites, porque no dice quién ejecutó los comandos ni desde dónde, y tampoco si las descargas funcionaron. Entonces no podemos saber hasta dónde llegó el ataque, pero sí que pasó algo que hay que atender.

## 2. Plan de acción priorizado

| Acción | Activo | Plazo | Responsable | Reversión |
|---|---|---|---|---|
| Guardar una copia de los registros antes de hacer cambios | Los tres servidores | Inmediato | Seguridad | No corresponde |
| Aislar el portal y la API y bloquear las IP 198.51.100.7 y 198.51.100.9 | Portal PHP y API | Primera hora | Operaciones | Sacar la regla de bloqueo |
| Volver a levantar el portal desde una imagen limpia con PHP 8.3.36 y la mitigación | Portal PHP | Primeras 2 horas | Infraestructura | Volver a la imagen anterior solo si hay una falla grave |
| Volver a levantar la API con Node.js 22.23.4 y no aceptar Brotli donde no se usa | API Node.js | Primeras 4 horas | Desarrollo y Operaciones | Volver a la imagen anterior con autorización |
| Actualizar Brotli a 1.2.1 y revisar quién se conecta al servicio | Servicio Python | Primeras 24 horas | Encargado del servicio | Volver a la versión anterior solo si es necesario |
| Cambiar las contraseñas y claves que usaban estos servicios | Todos | Primeras 24 horas | Seguridad | No corresponde |
| Revisar las sesiones SSH del servidor de base de datos | db01 | Primeras 24 horas | Seguridad | No corresponde |

Para ordenar las tareas tuve en cuenta si la vulnerabilidad ya se está explotando, si el servicio está expuesto, qué tan importante es y lo que encontramos en el registro. El portal va primero porque PHP2Shell se está explotando, porque el portal recibe archivos de los usuarios y porque fue donde vimos más actividad rara. La API va después por motivos parecidos, aunque lo más probable con ella es que la dejen fuera de servicio. Python queda tercero porque es interno, pero no lo dejaría para más adelante, porque también ejecutó comandos.

Algo que me parece importante es que, si un servidor ya fue atacado, actualizarlo no borra lo que el atacante pudo haber dejado adentro. Por eso propongo volver a armarlo desde una imagen limpia en lugar de solamente aplicar el parche encima.

## 3. Indicadores de compromiso

La señal más clara de que algo anda mal es que el servidor web, la API o el servicio Python abran una consola (`sh` o `bash`) o usen programas para descargar archivos, como `curl` o `wget`. Eso es justo lo que aparece en las líneas 6, 9, 14 y 16 del registro. También sirve mirar qué hicieron esas consolas después, que es lo que aparece en las líneas 7, 10 y 17. El filtro que nos dio la cátedra no muestra esas líneas, así que propuse seguir también a esos procesos, porque son los que muestran qué se ejecutó de verdad.

Otras cosas que revisaría son las conexiones hacia las IP 198.51.100.7 y 198.51.100.9 en el firewall, si aparecieron archivos nuevos en carpetas temporales y si la API se reinició varias veces seguidas, porque eso puede pasar cuando un intento de Node2Shell falla y hace caer el servicio.

Para descartar el compromiso tendríamos que poder demostrar que esos comandos los lanzó alguna tarea interna autorizada y que no hubo conexiones hacia afuera. Con lo que tenemos ahora no se puede hacer.

También hay varias cosas que el registro directamente no muestra. No sabemos con qué usuario corrieron los comandos, así que no sabemos si el atacante llegó a tener permisos de administrador. Tampoco sabemos desde qué dirección vino el ataque, si las descargas funcionaron ni qué pasó antes o después de esos nueve minutos. El caso de las sesiones SSH en el servidor de base de datos lo muestra bien: pueden ser de alguien del equipo revisando el problema o del atacante pasando a otro servidor, y sin el usuario y la IP de origen no lo podemos saber.

Algo positivo es que en el laboratorio Marti comprobó que los contenedores no podían conectarse a Internet. Si en producción pasara lo mismo, las descargas de las líneas 9 y 14 no habrían funcionado.

## 4. Transferencia

Para aplicar lo mismo a otra vulnerabilidad elegí Fragnesia (CVE-2026-46300), que aparece en el material de la cátedra pero que no trabajamos en el laboratorio. Es una falla del kernel de Linux y es distinta a las otras, porque no sirve para entrar a un servidor. Lo que permite es que alguien que ya entró con un usuario común se convierta en administrador (root). Tiene una gravedad de 7.8, afecta a los kernels anteriores al 13/05/2026 y CISA la agregó a su lista de explotación activa el 28/10. Además, ya se usó junto con PHP2Shell: el atacante entró por PHP con un usuario sin permisos y en menos de 15 minutos llegó a root modificando el archivo `/etc/pam.d/su`.

Si lo pienso con el mismo método, en el inventario ya no importa tanto la versión de PHP o de Node, sino la versión del kernel de cada equipo. Los contenedores usan el kernel de la máquina donde corren, así que actualizar las imágenes de Docker no alcanza.

En la prioridad, aunque tiene un 7.8 y está por debajo de PHP2Shell, en nuestro caso la pondría al mismo nivel, porque ya vimos señales de que alguien ejecutó comandos. De hecho, en la línea 16 del registro aparece un `uname -a`, que es el comando que se usa para ver qué kernel tiene el equipo antes de intentar este tipo de ataque.

Para corregirla hay que actualizar el kernel y reiniciar el equipo, así que hay que organizar una ventana de mantenimiento. Los controles de los contenedores, como el usuario sin privilegios o el disco de solo lectura, siguen sirviendo, pero no frenan una falla del kernel porque el kernel está por debajo de todo eso. Para detectarla buscaría cambios en `/etc/pam.d/su` y en otros archivos de acceso al sistema, entradas a root sin contraseña y procesos de root que salgan de un usuario común.

## 5. Lecciones y procesos

Lo que más me quedó del trabajo es que la detección tiene que empezar desde el principio y no al final. En el registro, la actividad sospechosa apareció pocos minutos después de que arrancaron los servicios, así que cuando llega un aviso de vulnerabilidad, revisar qué procesos están corriendo debería ser de las primeras cosas que se hagan.

También me di cuenta de que el registro necesita más información para que sirva de verdad. Debería tener el usuario y la IP de origen, guardarse por más tiempo y mandarse a un lugar donde un atacante no lo pueda borrar.

Otra cosa que aprendí es la diferencia entre un sistema vulnerable y uno comprometido. El vulnerable se parchea, pero el comprometido hay que aislarlo, investigarlo y volver a armarlo, porque si se trata igual que al otro el atacante puede seguir adentro.

Por último, creo que hay que tener un inventario completo, que incluya también el kernel de los equipos y no solo las aplicaciones, y explicarle a la gerencia con claridad qué sabemos, qué no sabemos y qué haría falta para averiguarlo.