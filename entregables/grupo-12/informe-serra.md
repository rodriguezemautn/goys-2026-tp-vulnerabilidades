# Informe individual — Grupo 12

**Integrante:** Facundo Serra · **Fecha:** jueves 29/10/2026
**Destinatario:** gerente de operaciones / comité de crisis
**Organización:** Vidriería Spamer (ficticia). Tiene un portal web donde los clientes
piden presupuestos y suben medidas o planos, una API que usan los colocadores para
cargar pedidos, y un sistema interno de stock y facturación.

---

## 1. Situación y riesgo

A fines de octubre se conocieron dos fallas graves en programas sobre los que corren
nuestros sistemas. Con cualquiera de las dos, una persona de afuera puede ejecutar
órdenes en el servidor sin tener usuario ni contraseña.

| Sistema | Falla | ¿Se está usando en ataques? | ¿Está en Internet? | Riesgo |
|---|---|---|---|---|
| Portal de presupuestos (PHP) | PHP2Shell | Sí. CISA la agregó a su lista de fallas explotadas el 26/10 | Sí | **Alto** |
| API de colocadores (Node.js) | Node2Shell | No hay casos confirmados, solo demostraciones | Sí | **Medio-alto** |
| Stock y facturación (Python) | Misma familia que Node2Shell (librería Brotli) | No hay casos confirmados | No, es interno | **Medio** |

Qué nos juega cada uno:

- **Portal.** Guarda nombre, dirección y teléfono de los clientes, y planos de sus
  casas. Si alguien entra, es una filtración de datos personales (Ley 25.326) y además
  sabe cómo es por dentro la casa de cada cliente.
- **API.** Si se cae o la toman, los colocadores no reciben trabajos y se frenan las
  instalaciones del día.
- **Facturación.** No se llega desde Internet. Para atacarlo, alguien tiene que haber
  entrado antes por el portal o la API.

**Por qué no alcanza con "parchear todo":** el registro de actividad del 27/10
muestra al portal y a la API haciendo cosas que no hacen nunca (ver punto 3). Si eso
fue un ataque, la actualización evita que vuelva a pasar, pero no borra lo que el
intruso haya dejado adentro ni nos dice qué se llevó.

---

## 2. Plan de acción priorizado

| # | Acción | Sistema | Plazo | Dueño | Cómo se vuelve atrás |
|---|---|---|---|---|---|
| 1 | Apagar la función de PHP que usa el ataque (`upload_progress`) y **comprobar en el servidor funcionando** que quedó apagada | Portal | Hoy, menos de 2 h | Sistemas | Volver a prenderla y reiniciar el portal |
| 2 | Guardar copia de los registros y aislar portal y API si se confirma lo del punto 3 | Portal y API | Hoy, en paralelo con el 1 | Sistemas + Gerencia (decide cortar) | Volver a conectarlos a la red |
| 3 | Actualizar PHP a la versión corregida (8.3.36) | Portal | Menos de 24 h | Sistemas | Reinstalar 8.3.35 desde la copia guardada antes del cambio |
| 4 | Actualizar Node.js a la versión corregida (22.23.4). Hasta que se actualice, que el proxy deje pasar datos comprimidos con Brotli solo hacia la parte de la API que los necesita | API | Menos de 72 h, en ventana de mantenimiento | Sistemas | Reinstalar 22.23.3 desde la copia guardada |
| 5 | Actualizar la librería Brotli a 1.2.1 | Facturación | Próxima ventana, menos de 7 días | Sistemas | Volver a 1.0.9 |
| 6 | Cambiar contraseñas y claves que usan portal y API | Portal y API | Después del 2 | Sistemas | No aplica |
| 7 | Avisar a clientes y colocadores, sin dar detalles técnicos | Todos | Antes de 72 h si se confirma acceso a datos | Gerencia + Legales | No aplica |

**Por qué este orden.** Si miramos solo el puntaje oficial de gravedad, las tres
fallas empatan en 9.2 y no sabríamos por dónde empezar. Por eso usé tres preguntas: si ya se está
usando en ataques reales, si el sistema está en Internet y qué tan grave es para el
negocio que caiga. El portal cumple las tres, por eso va primero y con una medida
rápida antes del parche. La API está en Internet pero sin ataques confirmados, por
eso va en una ventana programada y no de urgencia. Facturación es interna y va
última.

**Qué cambiaría el orden:**

- Si aparecen ataques reales contra Node.js, la API pasa a menos de 24 h.
- Si se confirma que alguien ya estuvo en el portal o la API, el paso 2 pasa a ser
  apagar esos sistemas, no solo aislarlos.
- Si se confirma que alguien llegó a la red interna, facturación sube al mismo nivel
  que el portal.

**Por qué el paso 1 dice "comprobar en el servidor funcionando".** Cuando corrí el
laboratorio en mi computadora el 29/10, el cambio de configuración estaba guardado en
el archivo, pero **el servidor nunca lo leyó**. Una protección del sistema operativo
(SELinux) le impedía leer ese archivo, y el portal además devolvía "acceso
prohibido". Aun así, el panel mostraba los tres servicios como "sanos", porque ese
control solo revisa que el servidor esté prendido, no que funcione. Si nos hubiéramos
quedado con el archivo y el panel, habríamos informado una protección que no estaba
puesta. Las salidas están en
[serra-01](capturas/serra-01-arranque-inventario.txt),
[serra-05](capturas/serra-05-funcional-y-contencion-post-parche.txt) y
[serra-06](capturas/serra-06-selinux-montajes.txt).

---

## 3. Indicadores de compromiso

**Qué confirmaría que entraron:**

- Que el portal o la API abran una consola de comandos (`sh`) o programas de descarga
  (`curl`, `wget`), cosa que en su trabajo normal nunca hacen. El 27/10 el registro lo
  muestra tres veces: portal a las 09:42 y 09:44, API a las 09:43.
- Esos programas intentan conectarse a direcciones de Internet desconocidas (en el
  registro aparecen dos).
- Aparecen archivos nuevos en el servidor que nadie instaló.
- Consultas o descargas de la base de clientes fuera de lo normal.

**Qué lo descartaría:**

- Que en los registros desde el 21/10 no haya ningún programa raro lanzado por el
  portal o la API.
- Que los servidores no hayan intentado conectarse a direcciones desconocidas.
- Que las tres sesiones abiertas en `db01`, donde está la base de datos, tengan una
  explicación: un nombre de Sistemas, una tarea anotada para ese día y un origen que
  no sea ni el portal ni la API.

**Qué no podemos saber con lo que registramos hoy:**

- **Si se llevaron datos.** El registro anota qué programas se ejecutan, pero no qué
  información salió por la red.
- **Quién fue y desde dónde.** No queda anotado el usuario ni la dirección de origen.
- **Si las descargas funcionaron.** No queda anotado si un comando terminó bien. En el
  laboratorio el servidor no tiene salida a Internet y las descargas habrían fallado.
  En producción no sé si tenemos esa misma restricción.
- **Un ataque que no lance programas.** Si el atacante trabaja todo desde adentro de
  la API, no aparece ningún programa nuevo y nuestra alerta no lo ve.

Con lo que hay alcanza para decidir qué aislar, pero no para saber qué se perdió.

---

## 4. Transferencia: CVE-2026-115560

Según la guía del laboratorio, CVE-2026-115560 se corrige recién en el **próximo
bugfix regular de PHP**. Hasta entonces hay que mantener apagada la función
`upload_progress`, la misma de la medida 1. Más allá de ese dato de la guía, no tengo
detalles verificados de la falla (gravedad, si ya se ataca), así que los dejo como
preguntas abiertas y respondo con el mismo método que usé arriba:

1. **¿Lo tenemos?** Mirar la versión de PHP que corre de verdad en el portal, no la
   que dice la documentación. Con Node vimos que los números internos pueden engañar,
   así que el dato que cuenta es la versión del programa principal.
2. **¿Se está usando?** Revisar si está en la lista de CISA y qué probabilidad de
   explotación le da EPSS. Con ataques confirmados tendría la misma urgencia que
   PHP2Shell, un día como máximo. Sin ataques, entra en la actualización normal de PHP.
3. **¿Qué tenemos puesto mientras tanto?** La medida 1 ya cubre este caso. Lo
   importante es **comprobarla de nuevo** después de cada actualización, porque una
   versión nueva o un cambio de servidor puede volver a prenderla sin avisar. Esto es
   justo lo que me pasó en el laboratorio.
4. **¿Qué cambia en el plan?** Que la medida 1 deja de ser provisoria: pasa a ser una
   configuración fija del portal, con un control que revise todos los días que siga
   apagada.

---

## 5. Lecciones y procesos

- **Inventario.** La lista de piezas de la API no mencionaba Brotli, porque viene
  metido dentro de Node.js. Si el inventario solo mira lo que instalamos a mano, se
  pierde justo esto. Hay que registrar también lo que trae cada programa adentro.
- **Verificación de cambios.** Un cambio no está hecho cuando se guarda el archivo,
  sino cuando se comprueba en el servidor funcionando. Lo mismo vale para el "sano" del
  panel: hay que probar que el portal responda de verdad, no solo que esté prendido.
- **Reversión.** Un plan para deshacer el cambio sirve si la versión vieja está a
  mano. Antes de cada actualización hay que dejar una copia guardada y anotar dónde
  está, para no depender de bajarla de Internet en plena emergencia.
- **Detección.** Alertar cuando el portal, la API o facturación lanzan programas que
  no deberían, y guardar los registros en otro servidor para que un atacante no los
  pueda borrar.
- **Comunicación y roles.** Tener escrito de antemano quién decide apagar un sistema
  que factura, y un mensaje para clientes listo para adaptar.
