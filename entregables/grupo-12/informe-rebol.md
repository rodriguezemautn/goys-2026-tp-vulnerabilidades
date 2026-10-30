# Informe individual — Grupo 12

**Integrante:** Manuel Rebol · **Fecha:** jueves 29/10/2026
**Destinatario:** gerente de operaciones / comité de crisis
**Organización:** Supermercado SooS (ficticia). Tiene una tienda online con el programa
de puntos SooS Club, una API de pedidos y stock que usan las apps de delivery y las
cajas de las sucursales, y un servicio interno de reposición.

---

## 1. Situación y riesgo

En octubre se conocieron dos fallas graves en programas sobre los que corren nuestros
sistemas. Con cualquiera de las dos, alguien de afuera puede ejecutar órdenes en el
servidor sin usuario ni contraseña. Al 29/10 **las dos se están usando en ataques
reales**: CISA las agregó a su lista de fallas explotadas, la de PHP el 26/10 y la de
Node el 27/10.

| Sistema | Falla | ¿Se está usando en ataques? | ¿Está en Internet? | Riesgo |
|---|---|---|---|---|
| Tienda online y SooS Club (PHP) | PHP2Shell | Sí, desde el 26/10 | Sí | **Crítico** |
| API de pedidos y stock (Node.js) | Node2Shell | Sí, desde el 27/10 | Sí | **Alto** |
| Reposición (Python) | Misma librería que Node2Shell (Brotli) | No hay casos | No, es interno | **Medio** |

- **Tienda.** Guarda nombre, DNI, dirección e historial de compras de los socios. Si
  alguien entra es una filtración de datos personales (Ley 25.326).
- **API.** El ataque que circula contra Node falla en el último paso, pero cada intento
  tira la API. Aunque nadie entre, pueden frenar los pedidos de delivery en hora pico.
- **Reposición.** No se llega desde Internet. Para atacarlo hay que entrar antes por la
  tienda o la API.

Además, el registro del 27/10 muestra a la tienda y a la API ejecutando programas que
nunca ejecutan (punto 3). Si fue un ataque, actualizar evita que se repita, pero no saca
a quien ya entró.

---

## 2. Plan de acción priorizado

| # | Acción | Sistema | Plazo | Dueño | Cómo se vuelve atrás |
|---|---|---|---|---|---|
| 1 | Guardar copia de los registros en otro servidor antes de tocar nada | Tienda y API | Ya | Seguridad | No aplica |
| 2 | Apagar la función de PHP que usa el ataque (`upload_progress`) y comprobar en el servidor funcionando que quedó apagada | Tienda | Menos de 2 h | Sistemas | Volver a prenderla y reiniciar |
| 3 | Revisar los registros desde el 21/10 y decidir si se aíslan tienda y API | Tienda y API | Menos de 2 h | Seguridad + Gerencia (decide) | Volver a conectarlos |
| 4 | Que el proxy rechace datos comprimidos con Brotli donde la API no los usa | API | Menos de 4 h | Redes | Sacar la regla |
| 5 | Actualizar PHP a 8.3.36, guardando antes la versión actual | Tienda | Menos de 24 h | Sistemas | Volver a la versión guardada |
| 6 | Actualizar Node.js a 22.23.4, de madrugada | API | Menos de 24 h | Desarrollo | Volver a la versión guardada |
| 7 | Cambiar contraseñas y claves que usan tienda y API | Tienda y API | Menos de 72 h | Seguridad | No aplica |
| 8 | Actualizar Brotli a 1.2.1 | Reposición | Menos de 7 días | Desarrollo | Volver a 1.0.9 |
| 9 | Avisar a socios y apps de delivery, sin detalles técnicos | Todos | Antes de 72 h si hubo acceso a datos | Gerencia + Legales | No aplica |

**Por qué este orden.** Las tres fallas tienen la misma gravedad oficial (9.2), así que
eso no sirve para ordenar. Usé tres preguntas: si ya se está usando, si está en Internet
y cuánto le duele al negocio. La tienda cumple las tres y tiene una medida rápida que se
puede deshacer. La API en la matriz del grupo estaba a 72 h, pero ahora tiene ataques
confirmados y la paso a 24 h. Reposición es interna y va última. Guardar y revisar los
registros va antes del parche porque reiniciar puede borrar rastros.

**Por qué el paso 2 dice "comprobar en el servidor funcionando".** En la corrida de
Serra el cambio estaba en el archivo pero el servidor no lo leía, y el panel igual
mostraba todo "sano" ([serra-06](capturas/serra-06-selinux-montajes.txt)). En la de
Espamer sí quedó aplicado ([06](capturas/06-mitigacion-php.txt)).

**Qué cambiaría el orden:**

- Si se confirma que alguien entró, la tienda y la API se apagan, no solo se aíslan.
- Si no aparece nada raro desde el 21/10, no se aísla nada y se sigue con los parches.
- Si alguien llegó a la red interna, reposición sube al nivel de la tienda.

---

## 3. Indicadores de compromiso

En el registro del 27/10 encontramos, en menos de 3 minutos, a la tienda ejecutando `id`
y después `wget` hacia una dirección externa, a la API ejecutando `curl` hacia otra, y al
servicio interno ejecutando `uname -a`. Primero lo que está en Internet y después lo
interno, como alguien que entra y se mueve (detalle en [`deteccion.md`](deteccion.md)).

**Qué confirmaría que entraron:**

- Que la tienda, la API o reposición lancen `sh`, `bash`, `curl` o `wget`.
- Que esas descargas hayan funcionado (se ve en el firewall).
- Archivos nuevos en la tienda que nadie subió.
- Entradas al servidor de base de datos que vengan de la tienda o la API.
- Descargas grandes de la base de socios.

Las caídas repetidas de la API o los pedidos comprimidos con Brotli donde no se usan
indican que nos están probando, pero no que entraron.

**Qué lo descartaría:**

- Que en los registros desde el 21/10 no haya ningún programa raro lanzado por los
  servicios.
- Que el firewall muestre que no salió ninguna conexión. En el lab la red no tiene salida
  ([03](capturas/03-contencion.txt)); en producción hay que confirmarlo.
- Que las tres sesiones en `db01` sean de alguien de Sistemas, desde su máquina y con una
  tarea anotada. Las marcamos como dudosas porque así se ve un administrador trabajando.

**Qué no podemos saber con lo que registramos hoy:**

- Quién fue y desde dónde: no hay usuario ni dirección de origen.
- Si se llevaron datos: no hay registro de red.
- Si los comandos funcionaron: no queda anotado.
- Si el registro está completo: son 9 minutos y queda en el mismo servidor, así que quien
  llegue a administrador lo puede borrar.

---

## 4. Transferencia: Fragnesia (CVE-2026-46300)

Fragnesia es una falla del núcleo de Linux (el sistema operativo, no la aplicación) que
deja a un usuario sin permisos convertirse en administrador. No se ataca desde Internet:
el atacante ya tiene que estar adentro. CISA la agregó a su lista el 28/10 y ya se usó
junto con PHP2Shell para tomar servidores completos en menos de 15 minutos.

1. **¿La tenemos?** Hay que mirar la versión del núcleo de cada servidor. Los contenedores
   usan el núcleo de la máquina donde corren, así que actualizar las imágenes de PHP o
   Node no lo arregla. Es la misma trampa que Brotli adentro de Node.
2. **¿Se está usando?** Sí, está en la lista de CISA.
3. **¿Está expuesta?** No directamente, pero PHP2Shell le abre la puerta. Es urgente en
   los servidores de la tienda y la API, donde hay señales del 27/10.
4. **¿Qué cambia en el plan?**
   - El dueño es Infraestructura, no Desarrollo.
   - Mientras tanto se pueden bloquear tres módulos del núcleo, en menos de 24 h en los
     servidores de tienda y API. Pero dos de ellos los usa la VPN de las sucursales, así
     que en esos equipos no se bloquean y va directo el parche.
   - El parche exige reiniciar el servidor, lo que apaga todos sus contenedores. Va en
     ventana nocturna, antes del 31/10 en tienda y API, y en menos de 7 días en el resto.
   - Antes de reiniciar hay que revisar el servidor, porque el ataque deja cambios en
     memoria que el reinicio borra.
   - Correr los servicios sin permisos de administrador servía contra PHP2Shell, pero
     Fragnesia arranca justamente desde un usuario sin permisos. Si los contenedores del
     lab la frenan no lo sabemos, porque no ejecutamos ataques.

---

## 5. Lecciones y procesos

- **Inventario.** Registrar también el núcleo de cada servidor y lo que trae cada
  programa adentro, no solo lo que instalamos a mano.
- **Verificación.** Un cambio está hecho cuando se comprueba en el servidor funcionando.
  El "sano" del panel solo dice que está prendido.
- **Detección.** Mandar los registros a otro servidor, con usuario, origen y conexiones
  de red, y alertar cuando un servicio lanza una consola.
- **Seguimiento.** Alguien tiene que revisar todos los días la lista de CISA. Node entró
  el 27/10 y eso cambió nuestro orden.
- **Roles.** Tener escrito quién decide apagar la tienda online, que es venta perdida, y
  un aviso para socios listo para adaptar.
