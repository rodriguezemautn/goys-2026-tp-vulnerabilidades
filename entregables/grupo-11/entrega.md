# Entregable — TP PHP2Shell / Node2Shell

**Grupo:** 11 · **Fork del grupo:** https://github.com/Sanntinat/goys-2026-tp-vulnerabilidades · **Rama:** `grupo-11`
**Fecha:** jueves 29/10/2026

| Integrante | Usuario de GitHub | Rol en el TP |
|---|---|---|
| Santiago | Sanntinat | Priorización y comunicación (comité) |
| Tomás | TomasMartin2004 | Mitigación, parche y reversión |
| Lautaro | Lauaubert | Inventario y exposición |
| Bautista | Baucuenca | Contención |

---

## 1. Inventario

| Activo | Versión | ¿Expuesto a Internet? | ¿Procesa contenido no confiable? | ¿Afectado? | Evidencia |
|--------|---------|:---------------------:|:--------------------------------:|:----------:|-----------|
| Portal PHP | PHP 8.3.35 | Sí (supuesto) | Sí: formularios y subida de archivos | Sí | [captura 01](capturas/01-arranque-inventario.png) |
| API Node.js | Node 22.23.3 | Sí (supuesto) | Sí: recibe datos comprimidos de los usuarios | Sí | [captura 01](capturas/01-arranque-inventario.png), [captura 04](capturas/04-node-bodyparser-br.png) |
| Servicio Python | Brotli 1.0.9 | No: es interno | Solo lo que le mandan los otros servicios | Sí, con menor riesgo | [captura 01](capturas/01-arranque-inventario.png) |

**Supuestos de exposición:** en el laboratorio nada está publicado hacia afuera y la red no tiene salida a Internet. Para decidir, supusimos cómo sería en la realidad: el portal y la API abiertos al público, y el servicio Python accesible solo desde adentro.

Un detalle que encontramos: la API no usa Brotli a propósito, pero Node lo trae incluido y descomprime los datos solo (captura 04). Por eso está afectada aunque en su código no aparezca.

---

## 2. Priorización y decisión

| Activo | CVSS | Explotación real | Exposición | Criticidad | Decisión y plazo |
|--------|:----:|:----------------:|:----------:|:----------:|------------------|
| Portal PHP | 9.2 | Sí, ya se está atacando (CISA KEV) | Alta | Alta | Mitigar ya y parchear en el día |
| API Node.js | 9.2 | No confirmada | Alta | Media | Parchear en 72 horas |
| Servicio Python | 9.2 | No confirmada | Baja | Media | Parchear en la próxima ventana normal |

**Justificación:** las tres fallas tienen la misma nota, así que la nota no alcanza para ordenar. El portal va primero porque es la única falla que ya se usa en ataques reales, está abierto a Internet y maneja datos personales. La API va segunda: también está expuesta, pero todavía no se vieron ataques. El servicio Python va último porque no se puede llegar a él desde afuera.

**Qué cambiaría la decisión:** si empezaran a atacar la falla de Node, la API pasaría a arreglarse en el día. Si viéramos señales de ataque en el servicio interno, subiría de prioridad, porque significaría que alguien ya entró.

---

## 3. Mitigación, parche y reversión

| Fecha | Activo | Cambio | Antes | Después | Reversión |
|------------|--------|--------|-------|---------|-----------|
| 29/10 | Portal PHP | Apagamos en la configuración de PHP la función que usa el ataque conocido (`upload_progress`) y reiniciamos | Activada (1) | Desactivada (0) — [captura 05](capturas/05-mitigacion-php.png) | Volver a activarla y reiniciar |
| 29/10 | Los tres | Instalamos las versiones corregidas | PHP 8.3.35 / Node 22.23.3 / Brotli 1.0.9 | PHP 8.3.36 / Node 22.23.4 / Brotli 1.2.1 — [captura 06](capturas/06-parche.png) | Volver a levantar las versiones anteriores, que siguen guardadas |

**Prueba funcional mínima:** después del parche comprobamos que los tres servicios responden y que el sistema los marca como sanos ([captura 07](capturas/07-prueba-funcional.png)).

**Reversión probada:** volvimos atrás los dos cambios y comprobamos que quedaron las versiones y la configuración originales ([captura 09](capturas/09-reversion.png)).

**Qué no se pudo probar:**

- Que el parche frene un ataque real, porque no usamos exploits.
- Que apagar la función de PHP corte todas las formas posibles del ataque; solo cubre la conocida.
- Cómo se comportaría con usuarios y tráfico real.

---

## 4. Detección y caza

Resumen. El análisis completo está en [`deteccion.md`](deteccion.md).

**Hipótesis:** si alguien atacó los servidores, vamos a ver al servidor web, a la API o al servicio interno abriendo una consola de comandos o descargando archivos, cosa que normalmente nunca hacen.

**Hallazgos en `audit.log`:**

| Línea / timestamp | Host | Padre → hijo | ¿Anómalo? | Por qué |
|-------------------|------|--------------|:---------:|---------|
| 09:42:17 | web01 | `apache2` → `sh -c id` | Sí | El servidor web abrió una consola y preguntó con qué usuario estaba |
| 09:43:03 | api01 | `node` → `sh -c curl ...` | Sí | La API descargó algo de una dirección externa |
| 09:44:22 | web01 | `apache2` → `wget ...` | Sí | Otra descarga desde el servidor web |
| 09:45:10 | svc01 | `python` → `sh -c uname -a` | Sí | El servicio interno abrió una consola, aunque no se puede llegar a él desde afuera |
| 09:42, 09:44, 09:49 | db01 | `sshd` → `bash` | No sabemos | Parece un administrador entrando, pero el log no dice quién |

**¿Hay compromiso?** Probablemente sí, pero no está confirmado: el log no dice quién lo hizo, desde dónde ni si las descargas funcionaron.

**Regla propuesta para Node.js:** avisar cuando la API abre una consola o un programa de descarga. Lo que se le escaparía: un atacante podría descargar archivos desde dentro de la propia API, sin abrir ningún programa aparte.

**Limitaciones del log:** no dice qué usuario hizo cada cosa ni desde qué dirección, cubre solo 9 minutos y la mayoría de las líneas son actividad normal.

---

## 5. Contención

| Control | Configuración | Evidencia | ¿Funciona? |
|---------|---------------|-----------|:----------:|
| Red sin salida | `internal: true` | Los tres servicios intentaron salir a Internet y no pudieron ([captura 08](capturas/08-contencion.png)) | Sí |
| Usuario sin privilegios | Cada servicio corre con un usuario común, no administrador | Captura 08 | Sí |
| Filesystem read-only | El disco es de solo lectura | Intentamos crear un archivo y no se pudo (captura 08) | Sí |
| Capabilities mínimas | Se quitaron los permisos especiales del sistema | Captura 08 | Sí |
| Límites de memoria/PIDs | Límite de memoria y de procesos | Captura 08 | Sí |
| Rechazo de Brotli innecesario | No está configurado en el laboratorio | — | No probado |

**Qué daño evita cada control:** sin salida a Internet, un atacante no puede descargar herramientas ni llevarse datos. Sin usuario administrador y sin permisos especiales, no puede tomar el control total. Con el disco de solo lectura, no puede dejar archivos para volver a entrar. Con los límites, no puede tirar el servidor saturándolo.

**Prueba de salida a Internet:** falló en los tres servicios, que es lo esperado.

**Lo que sigue pudiendo pasar:** si un atacante entra a un servicio, todavía puede comunicarse con los otros por la red interna. Separar esa red reduciría el riesgo.

---

## 6. Conclusión (5 líneas)

En las primeras dos horas haríamos primero la mitigación del portal, porque es rápida, se deshace en un minuto y frena el ataque que ya está circulando.
Revisaríamos qué versiones corren en cada servidor, no solo lo que dice la aplicación, porque la falla de Node venía incluida sin que lo supiéramos.
Mientras se aplica el parche, guardaríamos los registros y buscaríamos señales de ataque.
Antes de cambiar nada, dejaríamos listo cómo volver atrás.
Y separaríamos la red interna, porque la contención frena la salida a Internet pero no el paso entre servicios.

---

## 7. Checklist antes de entregar

- [x] El laboratorio arrancó y los 3 servicios quedaron `healthy`.
- [x] Inventario con evidencia.
- [x] Matriz con decisión y plazo.
- [x] Parche aplicado y verificado; reversión documentada.
- [x] Al menos 3 controles de contención probados.
- [x] `deteccion.md` completo.
- [x] `informe.md` individual completo (uno por integrante).
- [x] Sin claves, tokens ni placeholders.
- [x] Repo pusheado y PR abierto.
