# Informe individual — Grupo 12

**Integrante:** Martin Espamer · **Fecha:** jueves 29/10/2026
**Destinatario:** gerente de operaciones / comité de crisis
**Organización:** PanificadoraSerrucho (ficticia). Tiene un portal web donde los
empleados cargan su documentación y una API que usan los locales y distribuidores
para hacer pedidos.

---

## 1. Situación y riesgo

El 21/10 se publicaron dos fallas de seguridad en programas que usamos. Las dos, en
el peor caso, dejan que alguien de afuera ejecute comandos en nuestros servidores sin
necesitar usuario ni contraseña.

- PHP2Shell afecta al portal de empleados. No importa cómo esté programado el portal,
  alcanza con tener la versión vieja de PHP. Ya hay atacantes usándola y la agencia
  de ciberseguridad de Estados Unidos (CISA) la puso en su lista de fallas que se
  están explotando.
- Node2Shell afecta a la API de pedidos. Se demostró en laboratorio, pero todavía no
  hay ataques reales confirmados.

Están afectados el portal (público), la API de pedidos (pública) y un servicio interno
(no público).

El riesgo es alto en el portal, medio-alto en la API y medio en el servicio interno.
El portal tiene datos personales de los empleados (DNI, CUIL, sueldos), así que si
alguien entra tenemos un problema legal con la Ley 25.326 de datos personales. Si cae
la API se frenan los pedidos de los locales.

En el laboratorio ya aplicamos una solución temporal en el portal, después
actualizamos los tres servicios y comprobamos que siguen funcionando y que se puede
volver atrás en menos de 20 segundos. El problema es que en los registros hay señales
de que alguien pudo haber ejecutado comandos en el portal y en la API antes de la
actualización. Actualizar cierra la puerta, pero no saca a alguien que ya haya entrado.

---

## 2. Plan de acción priorizado

| Acción | Activo | Plazo | Dueño | Reversión |
|---|---|---|---|---|
| Desactivar en PHP la opción que usa el ataque (`session.upload_progress`) | Portal | Menos de 2 h | Guardia de sistemas | Volver a activarla y reiniciar |
| Aislar portal y API y guardar los registros antes de tocar nada | Portal y API | Menos de 2 h | Seguridad | No hace falta |
| Actualizar PHP a 8.3.36 | Portal | Menos de 24 h | Sistemas | Volver a la versión anterior guardada |
| Bloquear en el proxy los pedidos comprimidos con Brotli donde no se usen | API | Menos de 24 h | Redes | Sacar la regla |
| Actualizar Node.js a 22.23.4 | API | Menos de 72 h | Desarrollo | Volver a la versión anterior guardada |
| Cambiar las contraseñas que usan el portal y la API | Portal y API | Menos de 72 h | Seguridad | No aplica |
| Actualizar Brotli a 1.2.1 | Servicio interno | Menos de 7 días | Desarrollo | Volver a la versión anterior |
| Avisar a empleados y locales qué pasó y qué hicimos, sin detalles técnicos | Todos | Menos de 72 h, antes si se confirma que se vieron datos | Gerencia y Legales | No aplica |

Las tres fallas tienen la misma gravedad técnica (9.2 sobre 10), así que eso solo no
alcanza para decidir. Lo que define el orden es:

1. Si ya se está usando para atacar: solo la de PHP.
2. Si está en Internet: el portal y la API sí, el servicio interno no.
3. Qué tan importante es lo que guarda: el portal tiene los datos más sensibles.

La solución temporal va primero porque se hace en 5 minutos y se puede deshacer. La
actualización necesita una ventana y una prueba. El aviso a empleados y locales se
hace cuando sepamos si se vieron datos: muy pronto genera alarma sin información,
muy tarde genera desconfianza y problemas legales.

Si la falla de Node empieza a usarse en ataques reales, su actualización pasa a ser
inmediata. Si confirmamos que alguien entró, arrancamos el plan de incidente completo
y adelantamos el aviso.

---

## 3. Indicadores de compromiso

Confirmarían que alguien entró:

- Que el servidor web o la API ejecuten comandos del sistema. Es lo que aparece en el
  registro del 27/10: el portal ejecutando `id` y la API ejecutando `curl` hacia una
  IP externa.
- Conexiones desde el portal o la API hacia IPs desconocidas, como 198.51.100.7 y
  198.51.100.9 del registro.
- Archivos nuevos en el portal, usuarios nuevos o tareas programadas que nadie pidió.
- Que las contraseñas del portal se usen desde otro lugar.
- Que alguien entre al servidor de base de datos desde el portal o la API.

Lo descartarían:

- Que esos comandos sean de un script nuestro que esté documentado.
- Que el firewall muestre que no salieron conexiones desde esos servidores a esa
  hora. En el laboratorio la red no tiene salida, así que las descargas fallaron.
- Que las entradas por SSH a la base vengan de la máquina de administración y
  coincidan con alguien de guardia.

Con lo que tenemos hoy no podemos saber quién hizo cada cosa ni desde dónde, porque el
registro no guarda usuario ni IP y cubre pocos minutos. Tampoco si se llevaron datos.
Para eso hay que cruzarlo con los registros del proxy, del firewall y de la base de
datos.

---

## 4. Transferencia

Como caso distinto tomo CVE-2026-115560, el que propone la consigna. No encontré
información pública confiable sobre ese CVE, así que no pongo datos que no pude
comprobar. Lo que sí puedo hacer es aplicar los mismos pasos:

1. Ver qué programa y qué versiones afecta, en el aviso del fabricante y en NVD.
2. Revisar si lo tenemos, mirando la versión real en cada servidor y también si viene
   dentro de otro programa (como Brotli dentro de Node).
3. Ver si ya se usa en ataques reales (lista KEV de CISA, EPSS, avisos de CERT). Si
   está en KEV lo tratamos como PHP2Shell, en menos de 24 h. Si no, como Node2Shell,
   con una ventana programada.
4. Ver si está expuesto a Internet y si se puede atacar sin usuario. Si es así sube
   la prioridad; si es interno baja, salvo que ya sepamos que alguien entró.
5. Buscar si hay una forma de mitigarlo sin actualizar (una opción de configuración o
   una regla en el proxy) para aplicarla en las primeras horas.
6. Pensar si nuestras protecciones sirven. La red sin salida y los usuarios sin
   permisos ayudan contra la ejecución de comandos, pero si la falla solo deja leer
   datos ayudan menos, y ahí hay que priorizar la actualización y cambiar contraseñas.
7. Ver qué rastro deja el ataque para buscarlo en los registros desde la fecha en que
   se publicó.

---

## 5. Lecciones y procesos

- Inventario: necesitamos una lista actualizada de qué versión de PHP, Node y Python
  tiene cada servidor. En el laboratorio vimos que la versión de Brotli que muestra
  Node no cambia con el parche, así que mirar solo eso confunde.
- Cambios: antes de actualizar hay que confirmar que tenemos guardada la versión
  anterior. En el laboratorio volvimos atrás en 17 segundos porque estaba en la
  máquina.
- Detección: necesitamos registros con usuario, IP de origen y que se guarden al
  menos 30 días en otro lugar, no en el mismo servidor.
- Contención: la red sin salida y los servicios sin permisos de administrador
  hubieran frenado las descargas que vimos. Tendría que ser lo normal en todos los
  servicios.
- Roles: definir desde el principio quién hace inventario, quién aplica cambios,
  quién revisa los registros y quién comunica. La gerencia debería recibir un resumen
  cada 2 horas con lo que sabemos, lo que hicimos y lo que falta decidir.
