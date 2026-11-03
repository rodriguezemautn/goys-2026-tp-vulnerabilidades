# Informe individual — Grupo 02

**Integrante:** Eliseche, Martín · **Fecha:** jueves 29/10/2026
**Destinatario:** gerente de operaciones / comité de crisis
**Caso asignado:** PHP2Shell (CVE-2026-109618 y CVE-2026-109619)

---

## 1. Situación y riesgo

PHP2Shell es un par de fallas en el núcleo de PHP que permiten ejecutar código en un
servidor **sin autenticación**. Tienen CVSS 9.2 y PHP publicó parches de emergencia el
21/10 (8.5.12, 8.4.27, 8.3.36 y 8.2.35). Los ataques ya se están viendo: según el
contexto del TP, el caso figura en el catálogo de vulnerabilidades explotadas de CISA
(KEV), y hay intentos registrados desde antes del parche.

**Qué nos afecta:** nuestro portal corre PHP 8.3.35 sobre Apache con `mod_php`, es
decir, justo antes del parche (8.3.36) y en la configuración más expuesta: la falla se
ejecuta antes de llegar a nuestra aplicación. Asumimos que en producción el portal está
publicado en Internet y que maneja subida de archivos y datos personales.

**Riesgo: alto.** Es el activo con explotación confirmada, el más expuesto y el que no
depende de cómo esté escrita nuestra aplicación.

## 2. Plan de acción priorizado

| Acción | Activo | Plazo | Dueño | Reversión |
|---|---|---|---|---|
| Mitigar: desactivar `session.upload_progress.enabled` y reiniciar PHP | Portal PHP | Inmediato (hecho el 29/10) | Responsable de cambios | Volver a `= 1` en `php.ini` y reiniciar el contenedor |
| Parchear PHP 8.3.35 → 8.3.36 | Portal PHP | Menos de 24 h (hecho el 29/10, 22:17 UTC) | Responsable de cambios | `docker compose --env-file versions.env up -d --build` sin las variables del parche |
| Caza retroactiva de procesos y logs de Apache desde el 17/10 | Portal PHP | 24 a 48 h | Responsable de detección | No aplica (solo lectura) |
| Guardar el parche en `versions.env` para que un reinicio no lo pierda | Portal PHP | Antes del próximo despliegue | Responsable de cambios | Revertir el cambio del archivo |

**Por qué este orden:** el CVSS no desempata, porque las dos vulnerabilidades del TP
tienen 9.2. Lo que ordena es la explotación real (PHP2Shell va primero), la exposición
del portal y que no necesita nada de la aplicación para ser explotable. La mitigación
va antes que el parche porque se aplica en minutos y reduce la superficie mientras se
prepara el cambio.

## 3. Indicadores de compromiso

**Confirmarían un compromiso:** un proceso `apache2` lanzando `sh`, `bash`, `curl`,
`wget` o `nc`, comandos de reconocimiento como `id` o `uname` desde el servidor web, y
descargas hacia IPs externas poco después.

**Lo descartarían:** ausencia de esos procesos hijos en toda la ventana que va desde
el 17/10, con telemetría de procesos activa durante ese período completo.

**Lo que no podemos saber hoy:** el log que analizamos es sintético y cubre unos 9
minutos. No tiene usuario, IP de origen, resultado de los comandos ni la petición que
los disparó. Nuestra conclusión es "compromiso probable, no confirmado" en el log de
ejemplo, y para nuestros propios servidores no tenemos telemetría histórica que permita
descartarlo.

## 4. Transferencia: CVE-2026-115560

**Qué es:** otra falla de PHP que podría permitir ejecutar código en el servidor. Es
independiente de PHP2Shell y los parches del 21/10 **no la corrigen**. PHP no publicará
un parche de emergencia: la corregirá en su próxima versión regular. Solo es explotable
si la aplicación cambia `session.serialize_handler` en tiempo de ejecución y tiene
activo `session.upload_progress`. No hay explotación reportada.

**Cómo la priorizaría con el mismo marco:**

- **Explotación real:** ninguna conocida, así que no es emergencia.
- **Exposición:** el mismo portal, pero el riesgo depende de una condición poco común.
- **Acción:** la mitigación que ya aplicamos (`upload_progress=0`) la cubre. Por eso la
  mantendríamos después del parche y la retiraríamos solo cuando salga la versión
  corregida.
- **Qué verificaría:** si nuestra aplicación llama a `ini_set()` sobre el
  `serialize_handler` antes de `session_start()`.
- **Qué cambiaría el plan:** que aparezca explotación real o una entrada en KEV.

## 5. Lecciones y procesos

Mi parte fue el inventario. Dos lecciones: Node trae Brotli dentro de su runtime, así
que no aparece en `npm ls` y un inventario por manifiesto lo habría pasado por alto; y
`php -v` mostró `(cli)`, que no es lo que atiende la web, así que confirmamos Apache con
la imagen y el árbol de procesos. Para la próxima: inventario automatizado que incluya
runtimes y configuración, mitigación inmediata en el activo con explotación confirmada,
y guardar los cambios de versión en el repositorio y no solo en la consola.
