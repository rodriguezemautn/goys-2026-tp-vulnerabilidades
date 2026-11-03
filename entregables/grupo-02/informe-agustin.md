# Informe individual — Grupo 02

**Integrante:** Gutierrez Mora, Agustín · **Fecha:** jueves 29/10/2026
**Destinatario:** gerente de operaciones / comité de crisis
**Caso asignado:** cadena PHP2Shell + Fragnesia (CVE-2026-46300)

---

## 1. Situación y riesgo

Parchear PHP no alcanza si el atacante puede llegar a administrador del servidor.
**Fragnesia** (CVE-2026-46300) es una falla del núcleo de Linux, en el componente de
red XFRM ESP-in-TCP, que permite a un usuario común escalar a root. Tiene CVSS 7.8,
afecta a kernels anteriores al 13/05/2026 y CISA la incorporó al KEV el 28/10.

**La cadena:** según el contexto del TP, una campaña documentada por la empresa Dream
usó un exploit propio de PHP2Shell, que entraba como el usuario `nobody`, y luego
Fragnesia para escribir `/etc/pam.d/su` con la opción `pam_permit.so`, lo que permite
pasar a root sin contraseña. La cadena completa tardó **menos de 15 minutos** y dejó
comprometidos 25 servidores en cuatro países, tres de ellos de un entorno afiliado al
gobierno de EE. UU. Después buscaron credenciales y recorrieron Active Directory.

**Una salvedad importante:** Dream no nombró al fabricante de los firewalls afectados.
Unit 42 confirmó por separado, el 29/10, ataques a interfaces de administración de
PAN-OS expuestas a Internet. Son dos afirmaciones distintas y no hay que mezclarlas.

**Qué nos afecta:** nuestros contenedores comparten el kernel del equipo anfitrión. El
de nuestro laboratorio es `6.18.33.2-microsoft-standard-WSL2`, compilado el 18/06/2026,
una fecha posterior al 13/05/2026. Eso **sugiere**, pero no prueba, que incluye la
corrección: no lo verificamos con el proveedor del kernel.

**Riesgo: alto**, porque convierte una ejecución de comandos en control total del
servidor.

## 2. Plan de acción priorizado

| Acción | Activo | Plazo | Dueño | Reversión |
|---|---|---|---|---|
| Confirmar la versión de kernel del anfitrión con su proveedor y actualizar si es anterior al 13/05/2026 | Servidores anfitriones | Menos de 24 h (KEV vence el 31/10) | Responsable de infraestructura | Reiniciar con el kernel anterior |
| Mitigar y parchear PHP (mitigación `upload_progress=0` + 8.3.36) | Portal PHP | Hecho el 29/10 | Responsable de cambios | Ver informe del caso PHP2Shell |
| Vigilar cambios en `/etc/pam.d/su` y sesiones nuevas de root | Servidores web | 24 a 48 h | Responsable de detección | No aplica |
| Reducir privilegios del proceso maestro de Apache (hoy corre como root) | Portal PHP | Planificado | Responsable de cambios | Volver a la configuración anterior del contenedor |

**Por qué este orden:** el kernel de un servidor comprometido por PHP es lo que separa
un incidente acotado de uno total, y el KEV de Fragnesia vence el 31/10.

## 3. Indicadores de compromiso

**Confirmarían la cadena:** un `apache2` que lanza `sh` o `curl`, seguido de **cambios
en `/etc/pam.d/su`** (en particular la línea `pam_permit.so`), sesiones de root que
nadie inició y movimientos hacia otros equipos poco después.

**Lo descartarían:** integridad intacta de los archivos de PAM y ausencia de procesos
hijos extraños en la ventana investigada.

**Lo que no podemos saber:** nuestro log del TP solo registra procesos padre e hijo. No
tiene eventos de **escritura de archivos** ni de autenticación, así que aunque la
cadena hubiera ocurrido, no habría dejado rastro en esa fuente. Esa es la limitación
más grave de nuestra detección.

## 4. Transferencia: xz-utils (CVE-2024-3094)

**Qué fue:** en marzo de 2024 se descubrió que las versiones 5.6.0 y 5.6.1 de la
librería de compresión xz traían una **puerta trasera** introducida en el código
fuente publicado, que afectaba al servicio SSH en algunas distribuciones. CVSS 10.0.
Se solucionó volviendo a la versión 5.4.x.

**Cómo lo priorizaría con el mismo marco:**

- **Inventario primero:** saber en qué servidores está esa librería y en qué versión.
- **Explotación real:** no hubo explotación masiva, pero el impacto potencial era
  máximo, así que se trató como emergencia en los equipos que la tenían.
- **Cómo lo detectaría:** la versión instalada es el indicador más directo. Además,
  comportamientos raros del servicio SSH, como mayor uso de CPU en las conexiones.
- **Lo que cambia respecto de nuestro caso:** acá no hay un proceso hijo anómalo que
  cazar, porque la amenaza viene dentro de un componente legítimo. Hay que detectarla
  por inventario y por la cadena de suministro.

## 5. Lecciones y procesos

Mi parte fue la detección. Del `audit.log` aprendimos tres cosas: el filtro de
`detectar.sh` solo muestra procesos hijos directos, así que no muestra los "nietos"
(por ejemplo `sh` → `curl`); una descarga con `wget` lanzada directamente por Apache no
tiene shell y una regla que busque solo shells no la ve; y los `sshd` → `bash` de
`db01` parecen sospechosos pero son lo que genera un login legítimo, por lo que los
dejamos como indeterminados. Para la próxima: sumar telemetría de escritura de archivos
y autenticación, y revisar la regla para que mire cadenas completas de procesos.
