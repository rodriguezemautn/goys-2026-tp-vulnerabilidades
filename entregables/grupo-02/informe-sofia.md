# Informe individual — Grupo 02

**Integrante:** Kalpin, Sofía · **Fecha:** jueves 29/10/2026
**Destinatario:** gerente de operaciones / comité de crisis
**Caso asignado:** IA agéntica: qué cambió en la velocidad del ataque y la defensa

---

## 1. Situación y riesgo

En octubre de 2026 hubo dos fallas críticas, PHP2Shell y Node2Shell, y ambas están en
el catálogo de vulnerabilidades explotadas de CISA (KEV). Lo que cambió respecto de
otros incidentes es el **tiempo**: según el contexto del TP, la inteligencia artificial
acortó tres etapas del ataque.

- **Descubrimiento:** tres equipos distintos (Calif, Wiz y OpenAI, con *Patch the
  Planet*) encontraron las mismas fallas en agosto de 2026 usando modelos de IA.
- **Armado del exploit:** los modelos ayudaron a adaptar las técnicas a versiones y
  configuraciones concretas. Un investigador (Artemis) vio una copia armada del
  código de prueba **30 minutos** después de que se publicó.
- **Después de entrar:** Unit 42 reportó comandos enviados en lotes, tareas cortas y
  saltos rápidos entre equipos. En 2 horas, el atacante obtuvo hashes de contraseñas
  y secretos de MFA, intentó un ataque de retransmisión NTLM contra Active Directory y
  trató de llegar a Domain Admin.

**Lo que NO está probado, y conviene decir con claridad a la gerencia:** que los
atacantes hayan usado IA para escribir el exploit. Además, Unit 42 no pudo confirmar
que el acceso inicial de ese caso haya sido PHP2Shell. La IA acortó los tiempos, pero
las decisiones siguen siendo humanas.

**Qué nos afecta:** nuestro portal PHP (8.3.35) y nuestra API Node (22.23.3) estaban
en versiones vulnerables. **Riesgo: alto**, y con menos margen de tiempo que antes,
porque la ventana entre la publicación de un parche y el primer ataque es más corta.

## 2. Plan de acción priorizado

| Acción | Activo | Plazo | Dueño | Reversión |
|---|---|---|---|---|
| Mitigar y parchear en horas, no en días, lo que ya tiene explotación confirmada (PHP primero, Node después) | Portal PHP y API Node | Menos de 24 h para PHP, menos de 72 h para Node | Responsable de cambios | `docker compose --env-file versions.env up -d --build` sin las variables del parche |
| Verificar que los controles de contención siguen funcionando si el perímetro cae: red sin salida, usuarios sin privilegios, sistema de archivos de solo lectura | Los 3 servicios | 24 h | Responsable de infraestructura | No aplica (solo verificación) |
| Detectar por comportamiento: comandos en lote, descargas desde el servidor y saltos entre equipos en pocos minutos | Servidores web y de aplicación | 48 h | Responsable de detección | No aplica |
| Preparar un mensaje claro para gerencia y clientes, sin detalles que ayuden a un atacante | Organización | Hoy | Responsable de comunicación | Rectificar el comunicado si cambia la evidencia |

**Por qué este orden:** si el atacante avanza en minutos, lo que más vale es acortar
nuestra propia ventana de exposición. Eso se logra con mitigación inmediata y parche
rápido, y con controles que sigan frenando el daño aunque el perímetro ya haya caído.
La detección va después porque confirma lo que pasó, pero no lo evita.

## 3. Indicadores de compromiso

**Confirmarían un incidente:** muchas órdenes cortas ejecutadas en lote desde un
servidor web o de aplicación; marcas como `==SHELLUSER==` o `==PASSWD==` en las líneas
de comandos (las describe Unit 42); procesos `apache2`, `node` o `python` que lanzan
`sh`, `curl` o `wget`; accesos a hashes o secretos; movimiento hacia otros equipos pocos
minutos después.

**Lo descartarían:** ausencia de esas señales en toda la ventana de revisión, que debe
empezar el 17/10 y no en la fecha del parche, porque hubo intentos antes de que
existiera el parche.

**Lo que no podemos saber:** el log del TP es sintético, de una sola fuente y de unos 9
minutos. No tiene usuario, IP de origen ni resultado de los comandos. Tampoco podemos
saber si un atacante usó IA, y no hace falta saberlo para decidir: el comportamiento
es el mismo.

## 4. Transferencia: Citrix Bleed (CVE-2023-4966)

**Qué fue:** una falla en los equipos NetScaler ADC y Gateway de Citrix que filtraba
información de memoria, incluyendo los **tokens de sesión** de usuarios ya autenticados.
Con ellos, un atacante entraba sin necesidad de contraseña ni de MFA. CVSS 9.4. Citrix
publicó los parches en octubre de 2023, pero la explotación ya se había registrado
desde agosto.

**Qué enseña para nuestro marco:**

- **Explotación real:** confirmada y previa al parche, así que es emergencia.
- **Parchear no alcanza:** los atacantes ya tenían sesiones robadas, que seguían
  válidas después de actualizar. Hay que **cerrar todas las sesiones activas** y revisar
  accesos anteriores al parche.
- **Cómo lo detectaría:** inicios de sesión desde IPs inusuales con sesiones que no
  pasaron por autenticación normal, y actividad fuera del horario habitual.
- **Qué comunicaría:** que la actualización es solo el primer paso y que hay que
  revocar credenciales y sesiones, sin dar detalles técnicos explotables.
- **Conexión con nuestro caso:** igual que con PHP2Shell, la ventana previa al parche
  importa, y por eso la caza retroactiva tiene que empezar antes de la fecha del
  parche.

## 5. Lecciones y procesos

Mi parte fue la priorización y la comunicación. Aprendimos que el CVSS no desempata:
las dos vulnerabilidades tienen 9.2 y lo que ordena es la explotación real y la
exposición. También que la matriz hay que revisarla cuando cambia la evidencia:
durante el taller, Node2Shell pasó a estar en KEV (27/10) y tuvimos que subir su
prioridad. Para la próxima vez: revisar las fuentes antes de cerrar la matriz, fijar
plazos más cortos para lo que tiene explotación confirmada, definir quién comunica qué y
a quién antes de que ocurra el incidente, y mantener un registro de cambios con hora,
estado anterior y reversión.
