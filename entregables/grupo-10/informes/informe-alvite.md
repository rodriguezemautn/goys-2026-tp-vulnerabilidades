# Informe individual — Grupo 10

**Integrante:** Alvite, Damián  
**Rol en el TP:** Contención  
**Fecha:** viernes 30/10/2026  
**Destinatario:** gerente de operaciones / comité de crisis  
**Organización Ficticia:** Aseguradora del Plata S.A.  

---

## 1. Situación y Riesgo

Se evaluó el impacto de la divulgación de las vulnerabilidades críticas de octubre de 2026 sobre nuestros activos:

- **PHP2Shell (CVE-2026-109618 / CVE-2026-109619):** Severidad 9.2 con explotación activa en Internet (incluida en CISA KEV). Al correr sobre Apache con mod_php, permite RCE directo sin autenticación previa. Riesgo **CRÍTICO** para el sistema de pólizas expuesto a clientes.
- **Node2Shell (CVE-2026-111497):** Falla out-of-bounds write en la descompresión Brotli. Severidad 9.2, pero **sin reportes de ataques reales en producción**. El riesgo es **CONTROLABLE** mediante medidas de aislamiento de red y límites de sistema.

---

## 2. Plan de Acción Priorizado

| Acción | Activo | Plazo | Dueño | Reversión |
|---|---|---|---|---|
| **1. Mitigación perimetral en PHP** | Portal PHP (`php-lab`) | Inmediato (< 2 h) | Damián Alvite | Restaurar directiva en `php.ini` y reiniciar contenedor. |
| **2. Confinamiento y contención estricta** | Todos los contenedores | Inmediato (< 4 h) | Damián Alvite | Relajar temporalmente directivas de compose en caso de incompatibilidad. |
| **3. Parcheo del motor PHP** | Portal PHP | 24 h (ventana nocturna) | Rodrigo Capre | Volver a la imagen anterior en registry. |
| **4. Actualización de Node.js y Python** | Servicios de soporte | 48 h | Rodrigo Capre | Restaurar variables de versión en `.env`. |

**Justificación:**  
La prioridad número uno es aplicar barreras de contención que neutralicen el vector de ataque antes del despliegue del parche definitivo. Esto permite ganar tiempo operativo sin exponer la continuidad del negocio.

---

## 3. Indicadores de Compromiso y Eficacia de la Contención

- **Verificación de controles defensivos:**
  - **Red sin salida (`internal: true`):** Las pruebas arrojaron `SIN SALIDA` en los tres servicios, garantizando que un eventual RCE no pueda conectarse a un C2 externo ni descargar código malicioso.
  - **Filesystem Read-Only:** El sistema de archivos raíz de solo lectura bloqueó intentos de escritura (`Read-only file system`), impidiendo la instalación de web shells persistentes.
  - **Usuario sin privilegios y Capabilities mínimas:** `node-lab` corre con usuario `node` y `py-lab` con `nobody`; ambos con `cap_drop: ALL`, impidiendo la manipulación de recursos del kernel o escalamiento de privilegios.
- **Limitaciones de la telemetría:** El log sintético de auditoría no muestra si una acción anómala fue contenida por las restricciones del sistema operativo, requiriendo verificación manual sobre el estado del contenedor.

---

## 4. Transferencia a un Caso Nuevo (CVE-2026-115560)

Frente a una falla de subida de archivos como **CVE-2026-115560**:
1. **Contención Arquitectural:** Verificar que los directorios donde se almacenan temporales de subida (`/tmp`) tengan montado un volumen en memoria (`tmpfs`) con flags `noexec` y `nosuid`, garantizando que ningún archivo subido pueda ejecutarse directamente.
2. **Priorización:** Sin explotación confirmada, se programa la mitigación en el próximo ciclo de despliegue.
3. **Validación:** Comprobar que las funcionalidades de emisión de pólizas que no requieren adjuntos operen con normalidad.

---

## 5. Lecciones y Procesos

1. **Defensa en profundidad por diseño:** La infraestructura debe nacer aislada (redes internas sin salida, contenedores inmutables de solo lectura) de modo que la seguridad no dependa únicamente de la velocidad con que se apliquen los parches.
2. **Monitoreo de recursos:** Mantener límites estrictos de memoria y procesos (`mem_limit`, `pids_limit`) para evitar que fallas de corrupción de memoria afecten la estabilidad global del host.
3. **Planes de contingencia documentados:** Mantener procedimientos de reversión estandarizados y probados para cada componente de infraestructura.

