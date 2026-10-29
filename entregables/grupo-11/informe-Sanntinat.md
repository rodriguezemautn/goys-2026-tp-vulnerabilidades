# Informe individual — Grupo 11

**Integrante:** Santiago Natalichio Bestosini (Sanntinat) — legajo 32370 · **Fecha:** jueves 29/10/2026
**Destinatario:** gerente de operaciones / comité de crisis
**Organización asignada (ficticia):** RepuestosYa — tienda online de autopartes con
ventas en todo el país.

---

## 1. Situación y riesgo

RepuestosYa vende por una **tienda web en PHP** (catálogo, carrito, cuentas de clientes),
cobra a través de una **API de checkout en Node.js** que conversa con la pasarela de pagos
y calcula envíos con un **servicio interno en Python** que consulta a los correos.

El 21/10 se publicaron dos fallas graves que nos tocan a las tres piezas:

- **PHP2Shell (PHP):** permite tomar control del servidor de la tienda sin usuario ni
  contraseña, y no depende de cómo esté programada la tienda: alcanza con que corra
  sobre un PHP sin corregir. Ya hay ataques reales y desde el 26/10 CISA la tiene en su
  lista de fallas explotadas activamente. Nuestra tienda está publicada en Internet y
  usa una versión vulnerable. **Riesgo: crítico.** Con el control de la tienda, un
  atacante puede alterar el checkout para robar datos de tarjeta en el navegador del
  cliente, leer la base de clientes o dejarnos sin ventas.
- **Node2Shell (Brotli):** afecta a cualquier servicio que descomprima datos que manda
  un tercero. Nuestra API de checkout lo hace aunque nunca lo hayamos pedido, porque el
  framework que usamos descomprime por defecto los pedidos que llegan comprimidos.
  Por ahora solo se demostró en laboratorio, no hay ataques reales confirmados.
  **Riesgo: alto.** La API no guarda tarjetas, pero decide qué se cobra y a quién se
  despacha.
- **Servicio de envíos (Python):** usa la misma librería afectada. No recibe tráfico de
  Internet, pero sí descomprime las respuestas que le mandan los correos, así que un
  tercero puede hacerle llegar datos. **Riesgo: medio**, que sube si cae alguno de los
  otros dos, porque desde adentro sí se lo puede alcanzar.

---

## 2. Plan de acción priorizado

| # | Acción | Activo | Plazo | Dueño | Reversión |
|---|---|---|---|---|---|
| 1 | Mitigación provisoria en PHP (`session.upload_progress.enabled = 0`) + regla de WAF del proveedor para PHP2Shell | Tienda | Hoy, < 2 h | Infraestructura | Volver el valor a 1 y desactivar la regla |
| 2 | Revisar los archivos del checkout y los scripts que se sirven al navegador contra el repositorio; guardar copia de logs antes de tocar nada | Tienda | Hoy, en paralelo con 1 | Desarrollo + Seguridad | No aplica |
| 3 | Bloquear la salida a Internet de los servidores, salvo pasarela, correos y proveedores conocidos | Todos | Hoy | Infraestructura | Quitar la regla de firewall |
| 4 | Actualizar PHP a 8.3.36 | Tienda | < 24 h, ventana nocturna | Infraestructura | Volver a la imagen anterior |
| 5 | Rechazar en el borde los pedidos comprimidos con Brotli (la API no los necesita) | API de checkout | < 24 h | Infraestructura | Quitar la regla |
| 6 | Actualizar Node.js a 22.23.4 y probar una compra completa con la pasarela en sandbox | API de checkout | < 72 h | Desarrollo | Volver a la imagen anterior |
| 7 | Actualizar Brotli a 1.2.1 | Envíos | Ventana semanal | Desarrollo | Reinstalar la versión anterior |
| 8 | Avisar al proveedor de pagos y preparar mensaje a clientes; Legales revisa obligaciones por datos personales | Todos | Solo si el punto 2 o §3 dan positivo | Comercial + Legales | No aplica |

**Por qué este orden.** Las dos fallas tienen la misma nota técnica (9.2/10; el propio
Node.js la clasifica un escalón más abajo), así que la nota sola no decide. Decide la
combinación de **ataques reales**, **exposición** y **qué perdemos**: la tienda tiene las
tres en rojo. La API de checkout es crítica para el negocio, pero su falla todavía no se
explota y tiene una medida compensatoria simple (punto 5) mientras probamos el parche.
El bloqueo de salida (punto 3) va temprano porque corta la segunda etapa típica de
cualquiera de los dos ataques: descargar herramientas desde afuera.

No propongo apagar la tienda: el punto 1 reduce el riesgo en minutos y se revierte en
uno. El parche (punto 4) sí necesita ventana porque cambia la versión de PHP.

**Qué cambiaría la decisión:** si el punto 2 encuentra scripts del checkout modificados,
o aparecen procesos extraños en el servidor, pasamos de "parchear" a **sacar la tienda de
línea con página de mantenimiento** y reconstruirla desde una imagen limpia. Si se
confirman ataques reales de Node2Shell, la API sube al mismo nivel que la tienda y el
punto 6 pasa a hacerse hoy.

---

## 3. Indicadores de compromiso

**Confirmarían un incidente:**

- Cambios no autorizados en archivos JavaScript del checkout (comparando contra el
  repositorio y el último deploy).
- El servidor web o la API lanzando consolas o descargas (`sh`, `curl`, `wget`). En el
  análisis del grupo sobre el log de auditoría del laboratorio vimos justo ese patrón:
  comandos cortos como `id` y `uname` y descargas a IPs externas, en tres servidores en
  pocos minutos.
- Conexiones salientes a destinos que no son la pasarela, los correos o los proveedores
  (con el punto 3 aplicado, cada intento bloqueado queda registrado).
- Reinicios inesperados de la API o del servicio de envíos: un intento fallido contra
  Brotli suele tirar el proceso.
- Reclamos de clientes por cargos no reconocidos poco después de comprar.

**Lo descartarían:** archivos idénticos al repositorio, sin procesos hijos ni conexiones
salientes raras desde el 17/10 (primer intento conocido de PHP2Shell) y sin reinicios
que no podamos explicar con un deploy.

**Lo que no podemos saber hoy:** si nuestros registros son como los del laboratorio, no
guardan usuario ni IP de origen por proceso, no dicen si una descarga funcionó y
conservan pocos días. Si el ataque fue antes, puede que no quede rastro, y por eso el
punto 2 compara archivos y no depende solo de los logs.

---

## 4. Transferencia: CVE-2021-44228 (Log4Shell)

Log4Shell es la falla de diciembre de 2021 en **Log4j**, una librería de logs de Java
que usa muchísimo software. Si un atacante lograba que se registrara un texto especial
(en un usuario, un encabezado HTTP, un campo de búsqueda), Log4j lo interpretaba, se
conectaba a un servidor del atacante y terminaba ejecutando código. Nota 10/10,
explotación masiva a los pocos días y en la lista de CISA desde el principio.

Con el mismo marco:

- **Inventario:** igual que Brotli dentro de Node, Log4j casi siempre viene **escondido**
  dentro de otro producto (buscadores, ERPs, herramientas de terceros). No alcanza con
  mirar lo que desarrollamos: hay que buscar la librería en todo lo que corre Java. En
  RepuestosYa revisaría el buscador del catálogo y el ERP de stock, y le pediría a cada
  proveedor que confirme por escrito si lo usa.
- **Priorización:** explotación real más exposición mandan, como con PHP2Shell, así que
  iría primero. La diferencia es que el texto malicioso puede entrar por un sistema y
  explotar en otro: el nombre de un cliente que se carga en la tienda y después registra
  el ERP interno. Acá "interno" no quiere decir "no expuesto", y el ERP subiría de
  prioridad aunque no esté en Internet.
- **Plan:** como mitigación inmediata, sacar de la librería la parte que hace la
  conexión (la clase `JndiLookup`), porque el primer ajuste de configuración que se
  recomendó resultó no alcanzar. Después, parche a 2.17.1 o posterior. Y bloquear la
  salida a Internet de los servidores: sin salida, el servidor no puede ir a buscar la
  segunda parte del ataque. Es el mismo control del punto 3 de nuestro plan actual.

---

## 5. Lecciones y procesos

- **Saber qué librerías traen nuestros sistemas**, incluidas las de terceros, y no solo
  qué lenguaje usan. Brotli y Log4j muestran que el riesgo está muchas veces en algo que
  nadie eligió a propósito.
- **Ambiente de pruebas del checkout** con la pasarela en sandbox: sin él, cada parche
  se vuelve una apuesta y tiende a postergarse.
- **Salida a Internet cerrada por defecto** en los servidores, como regla permanente y no
  solo durante la crisis.
- **Integridad del front:** monitorear cambios en los scripts del checkout, que es lo
  primero que toca un atacante en una tienda.
- **Logs útiles y fuera del servidor:** guardar usuario, origen y resultado de cada
  proceso, por más tiempo, en un lugar que el atacante no pueda borrar.
- **Comunicación:** mensaje preparado para clientes y proveedor de pagos, aprobado por
  Legales, que se usa solo si hay indicios y no describe la falla en detalle.
