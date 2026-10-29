# Informe individual — Grupo 11

**Integrante:** Lautaro Aubert (LauAubert) · **Fecha:** jueves 29/10/2026
**Destinatario:** gerente de operaciones / comité de crisis
**Organización asignada (ficticia):** Municipalidad de Villa Arrecife, 60.000
habitantes, con trámites y pago de tasas por Internet.

---

## 1. Situación y riesgo

El 21/10 salieron correcciones para dos fallas graves. Una está en PHP y la otra en
Brotli, un formato de compresión que usan Node.js y Python, entre otros. En la
municipalidad nos tocan en tres sistemas.

El más comprometido es el portal de trámites. Está hecho en PHP, lo tiene un hosting
contratado y cualquiera entra desde Internet. Ahí los vecinos piden turno para la
licencia, pagan tasas y suben copias de DNI, escrituras y planos, y el portal consulta
la base de contribuyentes que tenemos en el edificio municipal. La falla de PHP
(PHP2Shell) deja que un desconocido, sin loguearse, le dé órdenes al servidor. El
problema está en PHP mismo, no en nuestro código, y nuestra versión (8.3.35) es de las
afectadas. Ya se usa en ataques reales; CISA la sumó el 26/10 a su lista de fallas
explotadas. Quien tome el portal se lleva documentos de vecinos (protegidos por la Ley
25.326), puede tocar la página de pagos y tiene un camino hacia la base de
contribuyentes. Lo considero riesgo crítico. Para peor, el hosting nos dijo que
actualiza PHP recién el viernes 30/10.

La API de estacionamiento medido está en Node.js. La usan la app de los vecinos para
pagar y las terminales de los inspectores para hacer actas. La falla de Brotli
(Node2Shell) aparece cuando el programa descomprime datos armados por un atacante.
Nosotros no usamos Brotli a propósito (las terminales comprimen con gzip), pero en el
laboratorio comprobamos que el framework de la API lo descomprime por su cuenta, antes
de que los datos lleguen a nuestro código. Hasta el 27/10 no se habían visto ataques
reales, solo pruebas de laboratorio. Riesgo alto: la API cobra y tiene el acceso a la
pasarela de pagos.

El servicio de liquidación de tasas, en Python, está adentro de la red. Cada noche baja
del banco los archivos de cobranza y registra los pagos. Desde Internet no se llega,
pero la librería con la que baja esos archivos descomprime Brotli sola. Riesgo medio,
que pasa a alto si alguien ya entró por el portal o por la API.

---

## 2. Plan de acción priorizado

| # | Acción | Activo | Plazo | Dueño | Reversión |
|---|---|---|---|---|---|
| 1 | Desactivar en PHP la opción que aprovecha el ataque publicado (una línea de configuración que podemos cambiar sin el hosting) y comprobar que quedó desactivada | Portal | Hoy, antes de 2 h | Sistemas (guardia) | Volver a activarla, tarda un minuto |
| 2 | Pedirle al hosting por escrito los registros desde el 17/10, un filtro contra este ataque y el horario exacto del parche | Portal | Hoy, antes de 4 h | Sistemas y Asesoría Legal | No aplica |
| 3 | Dejar que el portal solo pueda leer la base de contribuyentes, no modificarla | Portal | Hoy | Sistemas | Devolverle los permisos |
| 4 | Rechazar los pedidos comprimidos con Brotli antes de que lleguen a la API | API | Hoy | Sistemas | Sacar el filtro |
| 5 | Bloquear la salida a Internet de la API y de liquidación, menos pasarela y banco | API y liquidación | Antes de 24 h | Sistemas | Sacar la regla del firewall |
| 6 | Actualizar PHP a 8.3.36 y hacer un turno y un pago de prueba | Portal | Viernes 30/10 | Hosting (verifica Sistemas) | Volver a la versión anterior solo si el portal no anda, y con la medida 1 puesta |
| 7 | Cambiar la contraseña con la que el portal entra a la base | Portal | Después del 6 | Sistemas | No aplica |
| 8 | Pasar Node.js a 22.23.4 y hacer un pago y un acta de prueba | API | Antes de 72 h, de noche | Desarrollo | Reinstalar la versión anterior, que queda guardada |
| 9 | Actualizar Brotli a 1.2.1 y procesar un día de cobranza de prueba | Liquidación | Ventana semanal, antes del próximo vencimiento | Desarrollo | Reinstalar la versión 1.0.9 |

El puntaje técnico es 9.2 para las dos fallas, así que no sirve para desempatar. Miré
si hay ataques en curso, si el sistema se ve desde Internet y cuánto nos perjudica que
caiga. El portal pierde en todo y arranca la lista. Como su parche no depende de
nosotros, las medidas 1 a 3 lo cubren hasta el viernes: la 1 frena el ataque que
circula, aunque la falla de fondo sigue, y la 3 limita lo que se puede robar si alguien
entra igual. La contraseña (7) la cambio después del parche, porque si hoy hay alguien
adentro también vería la nueva.

La API va segunda. Está en Internet y maneja plata, pero contra ella todavía no hay
ataques reales y la medida 4 casi no tiene costo, porque ningún cliente nuestro manda
Brotli. Liquidación cierra la lista porque no se la puede alcanzar desde Internet.

Mi duda es la medida 1. Si el hosting no nos deja cambiar esa configuración, o no
podemos comprobar que quedó aplicada, propongo poner el portal en mantenimiento hasta
el viernes y atender en ventanilla. Un día de atención presencial cuesta menos que un
portal abierto con una falla que ya se está atacando.

El orden cambiaría si Node2Shell entra en la lista de CISA o se publica un ataque: el
parche de la API se hace en el día. Y si los registros o las señales de la sección 3
muestran que alguien entró, el portal sale de línea, se reinstala desde una copia
limpia, se cambian todas las contraseñas que tenía guardadas y Asesoría Legal decide si
hay que avisar a la Agencia de Acceso a la Información Pública y a los vecinos. Ese
aviso lo redacta Prensa y no explica cómo funciona la falla.

---

## 3. Indicadores de compromiso

Si alguien entró, tendría que verse alguna de estas cosas:

- El portal, la API o liquidación ejecutando programas por su cuenta, como una consola
  o una descarga. En uso normal no lo hacen nunca. En el registro del laboratorio que
  analizamos en grupo aparece eso en tres servidores, con minutos de diferencia.
- Intentos de la API o de liquidación de conectarse a algo que no sea la pasarela o el
  banco. Con la medida 5 cada intento queda registrado.
- Archivos de programa nuevos entre los adjuntos que suben los vecinos, o una página de
  pago distinta de la que publicamos.
- El portal pidiéndole a la base de contribuyentes muchos más datos de lo normal.
- Accesos a la red interna hechos desde el portal o la API. Unit 42 describió ataques
  recientes, que podrían haber empezado por esta falla, en los que en dos horas fueron
  por contraseñas y por el control de los usuarios de la red.
- Vecinos con pagos que no aparecen o con links de pago que no reconocen.

Un intento no es lo mismo que una entrada. El ataque de PHP provoca errores por falta
de memoria, así que una seguidilla de esos errores en los registros del hosting quiere
decir que nos están probando. No demuestra que hayan entrado, pero si aparece adelanto
el parche y la revisión.

Me quedaría tranquilo si los registros desde el 17/10 (el primer intento conocido) no
muestran nada de la lista de arriba y si cada reinicio de la API coincide con un cambio
que hicimos nosotros.

Igual hay límites. Del portal solo sabemos lo que el hosting nos pase, y si guarda una
semana de registros ya perdimos el 17/10. En nuestros servidores, si los registros se
parecen a los del laboratorio, no dicen quién ejecutó cada cosa, desde dónde vino el
pedido ni si la descarga funcionó. Y un atacante podría bajar archivos con el mismo
Node.js sin dejar rastro en ese registro. Con lo que tenemos podemos encontrar señales,
pero no garantizar que esté limpio.

---

## 4. Transferencia: CVE-2024-3094 (puerta trasera en xz)

xz es otra librería de compresión, presente en casi cualquier Linux. En marzo de 2024
se descubrió que sus versiones 5.6.0 y 5.6.1 traían una puerta trasera, puesta por un
colaborador que llevaba dos años ganándose la confianza del proyecto. En algunas
distribuciones el servicio de SSH usa esa librería de rebote, y la puerta trasera le
permitía a su autor ejecutar comandos en el servidor sin loguearse. Puntaje 10 sobre
10. Se descubrió porque un ingeniero notó que SSH le tardaba medio segundo más, antes
de que llegara a las versiones estables de Debian y Ubuntu. No se conocen ataques
reales.

En el inventario se parece mucho a Brotli: una pieza de compresión que nadie eligió y
que llega a un servicio expuesto sin que nadie la pida. Preguntar si usamos xz no dice
mucho, porque casi siempre la respuesta es sí; hay que ver qué versión tiene cada
equipo. Los servidores del municipio usan versiones estables y no la recibieron.
Revisaría las notebooks de desarrollo, sobre todo las que usan versiones de prueba de
Linux.

Para priorizar, el 10 asusta pero no alcanza: no hay ataques conocidos y hace falta
tener SSH abierto a Internet con una versión afectada. Lo más probable es que el
municipio no tenga ningún equipo alcanzado, y entonces basta con verificar y dejarlo
por escrito. Si aparece uno, la respuesta es otra. Una puerta trasera la pone alguien a
propósito, así que no sabemos desde cuándo puede entrar y el equipo se trata como
comprometido: se vuelve a la versión 5.4, se reinstala desde una copia limpia y se
cambian sus claves de acceso. No hay configuración que la apague.

Lo que habría frenado este ataque sin saber nada de la falla es no tener SSH abierto a
Internet y entrar solo por VPN, igual que la medida 5 sirve contra cualquier falla y no
solo contra estas dos. Para buscar señales, en vez de la API ejecutando programas se
busca al servicio de SSH ejecutando comandos sin que nadie haya iniciado sesión. En
`deteccion.md` el grupo marcó un caso parecido como posible falso positivo: una sesión
SSH puede ser un administrador o un intruso, y para separarlos hace falta saber qué
usuario era y desde dónde entró, que es lo que el registro del laboratorio no trae.

---

## 5. Lecciones y procesos

- Hoy el hosting decide cuándo parchea. El próximo contrato tiene que fijar un plazo
  para fallas que ya se están explotando (24 horas), darnos acceso a los registros y
  permitirnos pedir cambios de configuración urgentes.
- Una lista de componentes por sistema, con su versión, incluidos los del hosting. A
  Brotli y a xz no los eligió nadie, y por eso nadie sabía que estaban.
- Las medidas 3 y 5 las estamos aplicando en plena crisis. Cuentas que solo leen y
  servidores sin salida a Internet tendrían que ser lo normal.
- Poder parchear de urgencia sin esperar una reunión: que la autorización para fallas
  explotadas en sistemas públicos ya esté dada, y que antes de cada cambio se guarde la
  versión anterior y se haya ensayado volver a ella.
- Registros guardados en un servidor del municipio, que digan quién ejecutó qué y desde
  dónde, y que duren por lo menos 30 días.
- Responsables definidos de antemano: quién puede ordenar sacar el portal de línea,
  quién habla con el hosting, quién con vecinos y periodistas y quién decide si se
  avisa al regulador. El aviso a los vecinos conviene tenerlo escrito: qué pasó, qué
  tienen que hacer y dónde hacer el trámite mientras tanto.
