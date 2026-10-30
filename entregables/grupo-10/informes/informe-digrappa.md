# Informe individual — Grupo 10

**Integrante:** Di Grappa, Emiliano  
**Rol en el TP:** Detección  
**Fecha:** viernes 30/10/2026  
**Destinatario:** gerente de operaciones / comité de crisis   
**Organización Ficticia:** Red Hospitalaria Salud Integral  

---

## 1. Situación y Riesgo

Se detectó la publicación de alertas mundiales respecto a vulnerabilidades críticas de ejecución de comandos remotos:

- **PHP2Shell (CVE-2026-109618 / 109619):** Vulnerabilidad crítica en el runtime de PHP con ataques activos documentados en CISA KEV. Al afectar entornos Apache con mod_php, un atacante puede ejecutar comandos en el sistema hospitalario sin credenciales. El riesgo es **CRÍTICO**, pues compromete la confidencialidad de historias clínicas y la disponibilidad del sistema de turnos.
- **Node2Shell (CVE-2026-111497):** Falla en el descompresor Brotli que afecta a microservicios Node.js y Python. Si bien reviste severidad técnica 9.2, **no se ha detectado armamento activo en la red**, situándolo en un nivel de riesgo **MODERADO**.

---

## 2. Plan de Acción Priorizado

| Acción | Activo | Plazo | Dueño | Reversión |
|---|---|---|---|---|
| **1. Mitigación perimetral en PHP** | Servidor Web PHP | Inmediato (< 2 h) | Emiliano Di Grappa | Revertir directiva de subida en `php.ini` a su valor previo. |
| **2. Regla de detección EDR / auditd** | Servidores Node y PHP | Inmediato (< 3 h) | Emiliano Di Grappa | Deshabilitar regla de alerta en el recolector SIEM en caso de falso positivo. |
| **3. Parcheo de infraestructura PHP** | Portal Web | 24 h (horario nocturno) | Rodrigo Capre | Reinstalar imagen base de backup. |
| **4. Actualización de Node.js y Python** | Microservicios internos | 48 h | Rodrigo Capre | Desplegar contenedores con tags previos. |

**Justificación:**  
La respuesta prioriza la detección de ataques en curso y la mitigación de PHP sobre el portal expuesto. Node.js y Python reciben monitoreo continuo mientras se prepara la actualización sin alterar la operación hospitalaria.

---

## 3. Indicadores de Compromiso y Análisis Forense

A partir del análisis de telemetría de procesos sobre `audit.log`:

- **Hallazgos anómalos:** Se identificaron invocaciones sospechosas:
  - En `web01`, el proceso `apache2` engendra un shell `sh` que ejecuta `id` (reconocimiento de privilegios) y posteriormente un proceso `wget`.
  - En `api01`, el proceso `node` ejecuta `sh` y este lanza `curl`.
- **Evaluación de compromiso:** El estado es **INDETERMINADO CON INDICIOS SOSPECHOSOS**. Si bien las cadenas de procesos son típicas de explotación, las IPs registradas corresponden a rangos de prueba (RFC 5737) y los comandos no pudieron establecer conexiones de salida gracias a las políticas de red interna.
- **Falsos positivos analizados:** Sesiones administrativas legítimas por SSH (`sshd` → `bash`) o verificaciones de diagnóstico interno (`python` → `uname -a`).
- **Limitaciones del log:** Carencia de identificadores de usuario (UID/GID), ausencia de registros de red y falta de correlación con peticiones web.

---

## 4. Transferencia a un Caso Nuevo (CVE-2026-115560)

Ante una vulnerabilidad como **CVE-2026-115560**:
1. **Hipótesis de Caza:** Buscar procesos hijos anómalos generados a partir de peticiones de carga HTTP multipart.
2. **Priorización:** Sin explotación activa en KEV, se trata como incidente de severidad media gestionado por ciclo regular.
3. **Monitoreo:** Ajustar reglas de monitoreo para alertar si un proceso de aplicación genera archivos fuera de los directorios temporales asignados.

---

## 5. Lecciones y Procesos

1. **Monitoreo de comportamiento de procesos:** Implementar reglas de detección que alerten en tiempo real cuando un servidor web o API intente invocar utilidades de sistema (`sh`, `bash`, `curl`, `wget`).
2. **Mejora en la telemetría:** Exigir que los registros de auditoría incluyan contexto de usuario y puertos/conexiones de red para evitar investigaciones inconclusas.
3. **Defensa en profundidad:** Mantener entornos restringidos donde la red no tenga salida a Internet para anular los intentos de descarga de malware secundario.

