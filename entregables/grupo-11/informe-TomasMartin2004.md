# Informe individual — Grupo 11

**Integrante:** Tomás (TomasMartin2004) · **Fecha:** jueves 29/10/2026
**Destinatario:** gerente de operaciones / comité de crisis
**Organización asignada (ficticia):** Mutual Salud Río — obra social regional con
40.000 afiliados.

---

## 1. Situación y riesgo

Mutual Salud Río tiene tres sistemas que comparten las tecnologías afectadas por los
avisos de esta semana:

- **Portal de afiliados** (PHP sobre Apache, publicado en Internet): login, descarga de
  credenciales y carga de órdenes médicas escaneadas.
- **API de turnos** (Node.js), que usan la app móvil y el portal.
- **Servicio interno de resultados de laboratorio** (Python), sin acceso desde Internet.

**Riesgo del portal: crítico.** La falla de PHP (PHP2Shell) permite que alguien sin
usuario ni contraseña ejecute órdenes en el servidor con solo enviarle un pedido
armado. No depende de que nuestra aplicación tenga errores: alcanza con que el servidor
use una versión de PHP sin corregir, y la nuestra está sin corregir. Ya hay ataques
reales confirmados y la agencia de ciberseguridad de EE. UU. (CISA) la incluyó en su
lista de fallas explotadas activamente. Para una obra social, el impacto es filtración
de datos de salud (datos sensibles según la Ley 25.326), interrupción de la atención y
obligación de notificar.

**Riesgo de la API de turnos: alto.** La falla de Brotli (Node2Shell) se activa al
descomprimir datos enviados por un tercero. En nuestras pruebas comprobamos que el
framework que usa la API descomprime esos datos **antes** de que corra nuestro código,
así que la API está alcanzada aunque nunca hayamos “usado Brotli” a propósito. Hoy no hay
ataques reales confirmados, pero sí demostraciones de control remoto en laboratorio.

**Riesgo del servicio de resultados: medio.** Usa una versión afectada de la misma
librería, pero no recibe tráfico de Internet. Su riesgo sube a alto si cae el portal o
la API, porque se vuelve el siguiente paso de un atacante que ya está adentro.

---

## 2. Plan de acción priorizado

| # | Acción | Activo | Plazo | Dueño | Reversión |
|---|---|---|---|---|---|
| 1 | Desactivar la función de PHP que usa el ataque conocido (`session.upload_progress`) y reiniciar | Portal | Hoy, < 2 h | Infraestructura (guardia) | Volver el valor a `1` y reiniciar (1 min) |
| 2 | Actualizar PHP a 8.3.36 en ventana de emergencia | Portal | < 24 h | Infraestructura | Volver a la imagen anterior, guardada y etiquetada |
| 3 | Buscar señales de compromiso del 17/10 en adelante (ver §3) | Portal y API | En paralelo con 1–2 | Seguridad | No aplica (solo lectura) |
| 4 | Rechazar en el balanceador pedidos comprimidos con Brotli que la API no necesita | API de turnos | < 24 h | Infraestructura | Quitar la regla del balanceador |
| 5 | Actualizar Node.js a 22.23.4 y volver a probar el alta de turnos | API de turnos | < 72 h | Desarrollo | Volver a la imagen anterior |
| 6 | Actualizar Brotli a 1.2.1 en el servicio de resultados | Resultados | Próxima ventana semanal | Desarrollo | Reinstalar la versión anterior |
| 7 | Rotar credenciales que el portal tenga en memoria o en disco si §3 da positivo | Portal | Inmediato si hay hallazgo | Seguridad | No aplica |

**Por qué este orden.** No ordenamos solo por gravedad técnica (las dos fallas tienen
la misma nota, 9.2/10). El portal va primero porque combina tres cosas: ataques reales
en curso, exposición directa a Internet y datos de salud. La API queda segunda porque
no hay ataques confirmados y existe una medida compensatoria barata (punto 4) que
reduce el riesgo mientras se prueba el parche. El servicio interno va al final porque
no es alcanzable desde afuera. **Qué cambiaría el orden:** si apareciera explotación
real de Node2Shell o si la caza del punto 3 encontrara algo en la API, el parche de
Node pasa a emergencia de < 24 h.

**Prueba de que quedó aplicado:** cada cambio se valida con la versión reportada por el
servidor y con una prueba funcional (login de un afiliado de prueba, alta y baja de un
turno de prueba) antes de cerrar la ventana.

---

## 3. Indicadores de compromiso

**Confirmarían un incidente:**

- El proceso del servidor web o de la API lanzando una consola o herramientas de
  descarga (`sh`, `bash`, `curl`, `wget`). En la caza del grupo sobre el log de auditoría
  aparecen exactamente estas señales en tres servidores en tres minutos.
- Conexiones salientes desde el portal o la API hacia IPs desconocidas.
- Archivos nuevos en carpetas temporales o en la web, o usuarios/claves SSH nuevos.
- Accesos al servicio de resultados desde el portal o la API fuera de lo habitual.

**Lo descartarían (con razonable confianza):** búsqueda limpia de procesos hijos y de
conexiones salientes desde el 17/10, versiones parcheadas verificadas y ausencia de
reinicios inesperados de los servicios.

**Lo que hoy no podemos saber:** nuestros registros no guardan el usuario ni la IP de
origen de cada proceso, ni si una descarga tuvo éxito. Con la telemetría actual podemos
decir “hay señales” pero no “no pasó nada”.

---

## 4. Transferencia: CVE-2024-4577 (PHP-CGI en Windows)

Es una falla de 2024 en PHP: en servidores **Windows** con PHP en modo **CGI** y ciertas
configuraciones de idioma, un atacante puede inyectar parámetros y ejecutar código sin
autenticación. Fue explotada masivamente y CISA la incluyó en su lista KEV.

Aplicando el mismo marco:

- **Inventario:** no alcanza con “¿usamos PHP?”. Hay que saber el sistema operativo, el
  modo de ejecución (CGI vs. módulo de Apache vs. FPM) y el idioma del sistema. Nuestro
  portal corre en Linux con módulo de Apache: **no afectado**. Habría que revisar
  equipos Windows con XAMPP en sucursales (un caso típico de “servidor olvidado”).
- **Priorización:** explotación real + KEV suben la prioridad, pero solo si hay un
  activo expuesto que cumpla las condiciones. Sin ese activo, la decisión correcta es
  verificar y documentar, no abrir una ventana de emergencia.
- **Qué cambia en el plan:** la mitigación pasa por la configuración del servidor web
  (reglas de reescritura) y por retirar PHP-CGI, y la caza mira procesos hijos de
  `php-cgi.exe` en lugar de `apache2`.

La lección es la misma: la versión sola no decide; decide versión + configuración +
exposición.

---

## 5. Lecciones y procesos

- **Inventario vivo:** tardamos en saber qué versión de PHP y de Node corría cada
  sistema y qué dependencias descomprimen datos. Necesitamos un inventario automático
  (SBOM) por servicio.
- **Ventana de emergencia pre-aprobada:** para fallas en KEV con exposición a Internet,
  el cambio debe poder hacerse en horas, con reversión probada, sin esperar al comité.
- **Telemetría de procesos y red** enviada a un colector externo, con usuario e IP de
  origen, y retención de al menos 30 días: hoy no podemos mirar hacia atrás hasta el 17/10.
- **Roles claros:** un responsable de comunicación con afiliados distinto del equipo
  que parchea, con un mensaje base preparado que explique impacto y próximos pasos sin
  dar detalles útiles a un atacante.
