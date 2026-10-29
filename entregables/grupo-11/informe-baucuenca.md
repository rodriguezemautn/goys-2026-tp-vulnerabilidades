# Informe individual — Grupo 11

**Integrante:** Juan Bautista Cuenca (baucuenca) · **Fecha:** jueves 29/10/2026
**Destinatario:** gerente de operaciones / comité de crisis
**Organización asignada (ficticia):** Cooperativa Eléctrica Costa Sur, distribuidora
de energía con 25.000 socios en tres localidades.

---

## 1. Situación y riesgo

La cooperativa tiene tres sistemas que usan las tecnologías afectadas por los avisos
del 21/10:

- La oficina virtual (PHP sobre Apache, publicada en Internet), donde los socios
  descargan facturas, pagan, cargan reclamos y adjuntan fotos y documentos.
- La API de lecturas (Node.js), que recibe comprimidas las lecturas de los medidores
  inteligentes y de la app de los lecturistas.
- El servicio de facturación (Python, solo en la red interna), que toma esas lecturas,
  calcula los consumos y genera las facturas del mes.

**Oficina virtual: riesgo crítico.** Con la falla de PHP (PHP2Shell), cualquiera puede
hacer que el servidor ejecute las órdenes que quiera, sin usuario ni contraseña.
Alcanza con que el servidor corra una versión de PHP sin corregir, y la nuestra es una
de ellas; actualizar la aplicación no cambia nada. Ya hay ataques reales y desde el
26/10 la agencia de ciberseguridad de EE. UU. (CISA) la tiene en su lista de fallas
explotadas. Están en juego los datos personales y bancarios de los socios (Ley 25.326)
y la posibilidad de que alguien use ese servidor para entrar a la red interna.

**API de lecturas: riesgo alto.** La falla de Brotli (Node2Shell) se activa cuando el
servidor descomprime datos que manda un tercero. En la prueba del grupo vimos que el
framework de la API descomprime esos datos antes de que corra nuestro código, así que
la API está alcanzada aunque nadie haya elegido usar Brotli. Por ahora solo hay
demostraciones en laboratorio, sin ataques reales confirmados. Quien la aprovechara
podría alterar lecturas, y con ellas las facturas de miles de socios.

**Servicio de facturación: riesgo medio.** Usa una versión afectada de la misma
librería y no recibe tráfico de Internet. Igual procesa datos que vienen de afuera,
porque las lecturas le llegan desde la API: si cae la API, es el siguiente objetivo.

En el registro de auditoría del laboratorio, que el grupo analizó, el servidor web, la
API y el servicio interno abren consolas y descargan archivos de direcciones externas
en el lapso de tres minutos. Lo tratamos como compromiso probable. El registro no
alcanza para confirmarlo ni para descartarlo.

---

## 2. Plan de acción priorizado

| # | Acción | Activo | Plazo | Dueño | Reversión |
|---|---|---|---|---|---|
| 1 | Apagar la función de PHP que usa el ataque conocido (`session.upload_progress.enabled = 0`) y reiniciar | Oficina virtual | Hoy, < 2 h | Infraestructura (guardia) | Volver el valor a `1` y reiniciar (1 min) |
| 2 | Cortar la salida a Internet de los tres servidores, salvo pasarela de pago y destinos conocidos | Todos | Hoy, < 4 h | Infraestructura | Quitar la regla del firewall |
| 3 | Guardar copia de los registros y buscar las señales de §3 desde el 17/10 | Todos | Hoy, en paralelo con 1 y 2 | Seguridad | No aplica (solo lectura) |
| 4 | Actualizar PHP a 8.3.36 | Oficina virtual | < 24 h, ventana nocturna | Infraestructura | Volver a la imagen anterior, guardada y etiquetada |
| 5 | Confirmar que los servidores corren sin permisos de administrador, con disco de solo lectura y límites de memoria y procesos | Todos | < 24 h | Infraestructura | Volver a la configuración anterior del contenedor |
| 6 | Rechazar en el borde datos comprimidos con Brotli que no vengan de medidores o de la app | API de lecturas | < 24 h | Infraestructura | Quitar la regla |
| 7 | Actualizar Node.js a 22.23.4 y probar la carga de un lote de lecturas de prueba | API de lecturas | < 72 h | Desarrollo | Volver a la imagen anterior |
| 8 | Actualizar Brotli a 1.2.1 y facturar un mes de prueba | Facturación | Ventana semanal, antes del cierre del mes | Desarrollo | Reinstalar la versión anterior |

Las dos fallas tienen la misma nota técnica (9.2 sobre 10), así que ordené por otros
criterios: si ya hay ataques reales, si el sistema está expuesto a Internet y qué
perdemos si cae. La oficina virtual está en rojo en los tres y va primero. La API está
expuesta y el negocio depende de ella, pero su falla todavía no se explota y el punto 6
reduce el riesgo a bajo costo mientras probamos el parche. La facturación queda última
porque desde afuera no se llega a ella.

Los puntos 2 y 5 son controles de compensación: la falla sigue ahí, pero el daño
posible es mucho menor. Van temprano porque ya los probamos en el laboratorio. Los tres
servicios quedaron sin salida a Internet, y la API corre con un usuario común y no
puede escribir en su disco. En un servidor así, quien entra no puede bajar
herramientas, sacar datos ni dejar guardada una puerta trasera.

El orden cambia en dos casos. Si Node2Shell entra en la lista de CISA, aparece un
ataque público o vemos señales en nuestros registros, el parche de la API pasa a
< 24 h. Si la búsqueda del punto 3 encuentra un servidor lanzando consolas, ya no
alcanza con parchear: ponemos la oficina virtual en mantenimiento, la reconstruimos
desde una imagen limpia y cambiamos las claves que ese servidor tenía guardadas.

Para dar por aplicado cada cambio miramos la versión que reporta el servidor, que los
tres servicios sigan funcionando y una prueba de punta a punta: un socio de prueba
entra y descarga su factura, y un lote de lecturas de prueba llega a facturación.

---

## 3. Indicadores de compromiso

Estas señales confirmarían un incidente:

- El servidor web o la API lanzando una consola o una descarga (`sh`, `bash`, `curl`,
  `wget`), algo que en uso normal nunca hacen. Es el patrón que encontramos en el
  registro del laboratorio.
- Intentos de conexión hacia afuera que el firewall del punto 2 bloquea y registra.
  Con la salida cerrada, cada intento es una alarma.
- Archivos nuevos en la carpeta de adjuntos de los reclamos, sobre todo con extensión
  `.php`.
- Reinicios inesperados de la API de lecturas justo después de recibir datos
  comprimidos. Un intento fallido contra Brotli suele tirar el proceso.
- Lecturas imposibles, como saltos de consumo o medidores en cero en bloque, que una
  falla de campo no explica.

Lo descartaríamos con confianza razonable si los registros desde el 17/10 (primer
intento conocido de PHP2Shell) no muestran procesos hijos ni conexiones salientes
raras, si cada reinicio coincide con un cambio aprobado, si los adjuntos son solo
imágenes y PDF y si las versiones corregidas quedaron verificadas.

Hay cosas que hoy no podemos saber. Si nuestros registros se parecen a los del
laboratorio, no dicen qué usuario corrió cada proceso, desde qué IP llegó el pedido ni
si una descarga funcionó, y duran pocos días. Con eso podemos afirmar que hay señales;
no podemos afirmar que no pasó nada. Y si el ataque fue anterior a la retención, no
queda rastro.

---

## 4. Transferencia: CVE-2023-4863 (libwebp)

libwebp es la librería que abre imágenes en formato WebP. En septiembre de 2023 se
publicó una falla en ella: una imagen armada a propósito provocaba una escritura fuera
de memoria al decodificarla y permitía ejecutar código. Se usó en ataques reales contra
iPhones, con imágenes que llegaban por mensaje sin que la víctima tocara nada. CISA la
agregó a su lista de fallas explotadas y se corrigió en libwebp 1.3.2. Primero se
publicó como una falla de Chrome; después se vio que estaba en la librería, que también
usan Firefox, Android, las aplicaciones de escritorio hechas con Electron y Pillow, la
librería de imágenes de Python.

El caso se parece a Brotli: un formato de datos que el servidor procesa solo, metido
dentro de otro software. Con el mismo marco:

- Para el inventario hay que buscar la librería en todo lo que procesa imágenes, use o
  no WebP a propósito. En la cooperativa miraría la oficina virtual, que recibe fotos en
  los reclamos y puede generar miniaturas; el servicio de facturación, si arma los PDF
  con Pillow, y la app de los lecturistas, que saca fotos del medidor.
- Para priorizar mandan otra vez la explotación real y la exposición. La oficina
  virtual procesa fotos que sube cualquiera y va primero. Las PC del personal, que solo
  abren imágenes al navegar, quedan cubiertas con la actualización normal del navegador.
- En el plan cambia la mitigación rápida: rechazar WebP en la carga de adjuntos, o
  convertir las imágenes en un proceso aparte y sin permisos, hasta actualizar la
  librería. La contención queda igual, porque sin salida a Internet y sin permiso de
  escritura el código del atacante tiene poco para hacer. La caza busca lo mismo que
  hoy: el proceso que maneja imágenes lanzando consolas o descargas.

---

## 5. Lecciones y procesos

- Necesitamos saber qué librerías trae cada servicio (Brotli, libwebp, OpenSSL) y en
  qué versión, con un inventario automático. La versión del producto principal no las
  muestra.
- Los servidores deberían salir sin acceso a Internet, sin permisos de administrador y
  con disco de solo lectura desde el primer día. Son los controles que siguen
  funcionando cuando el parche llega tarde, y hoy los pusimos recién en la crisis.
- Para fallas explotadas en sistemas expuestos a Internet hace falta una ventana de
  emergencia aprobada de antemano, con la versión anterior guardada y la vuelta atrás
  probada.
- Los registros tienen que guardar usuario, origen y resultado de cada proceso, durante
  al menos 30 días y en un lugar que un atacante no pueda borrar.
- Los roles se definen antes de la crisis: quién decide, quién cambia, quién busca
  señales y quién habla con los socios y con el ente regulador. Para esto último
  conviene tener un mensaje base aprobado que explique el impacto y los próximos pasos
  sin dar detalles útiles a un atacante.
