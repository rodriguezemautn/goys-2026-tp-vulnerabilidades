# Informe individual — Grupo 10

**Integrante:** Capre, Rodrigo  
**Rol en el TP:** Priorización y cambios/parche  
**Fecha:** viernes 30/10/2026  
**Destinatario:** Gerente de Operaciones / Comité de Crisis  
**Organización Ficticia:** Banco Metropolitano de Crédito S.A.  

---

## 1. Situación y Riesgo

Se ha notificado la divulgación de dos conjuntos de vulnerabilidades críticas que comprometen la plataforma tecnológica de la entidad:

- **PHP2Shell (CVE-2026-109618 / CVE-2026-109619):** Calificada con CVSS 9.2 y catalogada en CISA KEV con explotación activa en la naturaleza. Permite a un atacante ejecutar código arbitrario de manera remota al provocar fallas de memoria en el núcleo de PHP bajo Apache `mod_php`. El riesgo para el banco es **EXTREMO**: un compromiso en el portal puede derivar en la exfiltración de credenciales bancarias o alteración transaccional.
- **Node2Shell (CVE-2026-111497):** Desbordamiento de escritura fuera de límites en el módulo Brotli, presente en la API Node.js v22.23.3 y el servicio Python con brotli 1.0.9. Aunque cuenta con un CVSS de 9.2 y pruebas de concepto en laboratorios, **no se registra explotación maliciosa en producción**, lo cual permite estructurar una respuesta planificada.

---

## 2. Plan de Acción Priorizado

| Acción | Activo | Plazo | Dueño | Reversión |
|---|---|---|---|---|
| **1. Mitigación temporal PHP** | Portal PHP (`php-lab`) | Inmediato (< 2 h) | Rodrigo Capre | Reestablecer `session.upload_progress.enabled = 1` y reiniciar `php-lab`. |
| **2. Aplicación de parche PHP 8.3.36** | Portal PHP (`php-lab`) | 12 horas (ventana nocturna) | Rodrigo Capre | Revertir imagen a `php:8.3.35-apache` en `docker-compose.yml`. |
| **3. Actualización Node.js (v22.23.4) y Brotli Python (1.2.1)** | API Node y Servicio Python | 48 horas | Rodrigo Capre | Volver a tags anteriores fijados en `versions.env`. |
| **4. Validación y smoke tests** | Todos los servicios | Post-cambio inmediato | Rodrigo Capre | Rollback automático si falla el healthcheck en los primeros 5 minutos. |

**Criterios de gestión de cambios:**  
El orden de intervención prioriza el riesgo operativo real (presencia en CISA KEV) por encima de la severidad teórica. Cada modificación cuenta con prueba funcional mínima documentada y un camino de reversión probado que no insume más de 5 minutos de ejecución.

---

## 3. Indicadores de Compromiso

- **Evidencias de ataque activo:** Workers de Apache o procesos Node ejecutando binarios fuera de su estándar funcional (`sh`, `bash`, `wget`, `curl`), o intentos de conexión TCP no autorizados a nivel de socket.
- **Evidencias de normalidad / contención:** Estado de los servicios reportando código HTTP `200` y `healthy`, ausencia de subprocesos anómalos en el árbol de ejecución (`docker top`) y confirmación de que la red interna deniega el tráfico saliente.
- **Limitaciones de observabilidad:** Los registros disponibles en `audit.log` carecen de asociación con direcciones IP remotas de clientes, lo que impide determinar si una anomalía provino de una petición externa o de un comando local de mantenimiento.

---

## 4. Transferencia a un Caso Nuevo (CVE-2026-115560)

Frente a una vulnerabilidad alternativa como **CVE-2026-115560** (falla en el analizador de formularios de carga de PHP):
1. **Evaluación de Exposición:** Auditar el código fuente para constatar si las rutas expuestas al público aceptan subida de documentos.
2. **Priorización:** Al no contar con reportes de ataque masivo, se clasifica en el ciclo regular de mantenimiento mensual.
3. **Plan de Mitigación:** Si se requiriera acción inmediata, se deshabilita la directiva `file_uploads` en `php.ini` o se aplica filtrado de tipo de contenido en el WAF corporativo.

---

## 5. Lecciones y Procesos

1. **Protocolo formal de reversión:** Exigir que ningún cambio de seguridad se apruebe sin una prueba de rollback documentada y ensayada en pre-producción.
2. **Automatización de healthchecks:** Implementar validaciones funcionales post-despliegue que confirmen no solo que el contenedor está activo, sino que la lógica de negocio responde sin errores sintácticos.
3. **Aislamiento por defecto:** Mantener políticas de confinamiento en contenedores (`read_only`, capacidades mínimas de Linux y límites de memoria) para amortiguar el impacto de cualquier vulnerabilidad de día cero.

