# Informe individual — Grupo 02

**Integrante:** Bresciani, Isabella · **Fecha:** jueves 29/10/2026
**Destinatario:** gerente de operaciones / comité de crisis
**Caso asignado:** servicio Python con Brotli como punto de pivote interno

---

## 1. Situación y riesgo

Nuestro servicio Python es un servicio **interno**: no está publicado en Internet, pero
recibe cuerpos comprimidos con Brotli (`Content-Encoding: br`) que le envían otros
servicios. Usaba el paquete `brotli` 1.0.9, dentro del rango afectado por Node2Shell
(CVE-2026-111497, Brotli 1.0.3 a 1.2.0, corregido en 1.2.1).

**Qué significa el riesgo:** un atacante no llega directamente al servicio Python, pero
si logra entrar a un equipo que sí está expuesto (el portal PHP o la API Node), ese
servicio queda al alcance como **segundo salto**. Es el patrón del pivote: la red
interna parece protegida, pero deja de serlo cuando ya hay un punto comprometido.

**Un dato para no exagerar:** los reportes de explotación que figuran en el contexto
del TP son contra Node.js. No hay evidencia de explotación contra Python, aunque el CVE
afecta a la librería en cualquiera de sus usos.

**Riesgo: medio.** La exposición es baja, pero la librería es vulnerable y procesa
datos de otros servicios.

## 2. Plan de acción priorizado

| Acción | Activo | Plazo | Dueño | Reversión |
|---|---|---|---|---|
| Actualizar `brotli` 1.0.9 → 1.2.1 (hecho el 29/10, 22:17 UTC) | Servicio Python | En el mismo cambio o dentro de la semana | Responsable de cambios | `docker compose --env-file versions.env up -d --build` sin las variables del parche |
| Rechazar `Content-Encoding: br` si el servicio no lo necesita | Servicio Python | 72 h | Responsable de desarrollo | Quitar la validación del código |
| Verificar quién le envía datos y confirmar que nadie externo llega directo | Servicio Python | 72 h | Responsable de arquitectura | No aplica |
| Mantener la red sin salida a Internet | Red del laboratorio | Permanente | Responsable de infraestructura | No aplica |

**Por qué va tercero:** el portal PHP y la API Node están más expuestos y tienen
explotación confirmada. Python queda detrás por estar en la red interna, y sube de
prioridad si se descubre que recibe datos directamente de clientes externos.

## 3. Indicadores de compromiso

**Confirmarían un incidente:** un proceso `python` que lanza `sh`, `curl` o `wget`
(en nuestro log sintético, `python` → `sh -c uname -a` en `svc01` a las 09:45:10 es
una señal de reconocimiento); cuerpos `br` con tamaños o orígenes inusuales; caídas del
proceso.

**Lo descartarían:** ausencia de esos procesos hijos y de conexiones salientes en toda
la ventana de revisión.

**Lo que no podemos saber:** no tenemos registros de qué servicio le envía datos ni el
contenido de las peticiones, y el log es de una sola fuente.

## 4. Transferencia: regreSSHion (CVE-2024-6387)

**Qué fue:** una falla en el servidor SSH de OpenSSH (versiones 8.5p1 a 9.7p1, en Linux
con glibc) que permitía **ejecutar código como root sin autenticarse**, por una
condición de carrera en el manejo de señales. La descubrió Qualys y se divulgó en julio
de 2024. Se corrigió en OpenSSH 9.8p1. La explotación requería muchos intentos, del
orden de horas.

**Cómo lo priorizaría con el mismo marco:**

- **Exposición:** SSH suele estar expuesto, y el servicio corre como root. Es el caso
  opuesto a nuestro Python: alto impacto y alta exposición.
- **Explotación real:** difícil y lenta, pero con impacto máximo.
- **Mitigación mientras se parchea:** poner `LoginGraceTime 0`, con el costo de que
  facilita agotar conexiones, y limitar el acceso por firewall a IPs conocidas.
- **Cómo lo detectaría:** muchas conexiones que terminan con mensajes de
  "Timeout before authentication" en los registros de `sshd`.
- **Conexión con mi caso:** nuestros controles de contenedor (usuario sin privilegios,
  capabilities mínimas) están pensados justamente para que un servicio comprometido no
  sea root. regreSSHion muestra qué pasa cuando el servicio ya corre con ese privilegio.

## 5. Lecciones y procesos

Mi parte fue la contención. Probamos tres controles. La red interna sin salida funciona:
`curl`, Node y Python fallaron al conectarse a Internet en las tres pruebas. El sistema
de archivos de solo lectura también: un intento de crear un archivo en Node devolvió
`Read-only file system`. Las capabilities están eliminadas en Node (`CapEff` en cero).
Pero hay riesgo residual que declaramos: el proceso maestro de Apache en el portal PHP
corre como root y conserva capabilities como `SETUID` y `SETGID`, y el control de
rechazo de Brotli **no está aplicado**. Para la próxima: probar cada control en los tres
servicios y no solo en uno, y cerrar la entrada de datos que no hace falta.
