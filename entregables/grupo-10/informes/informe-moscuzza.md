# Informe individual — Grupo 10

**Integrante:** Moscuzza, Vicente  
**Rol en el TP:** Inventario y Exposición  
**Fecha:** viernes 30/10/2026  
**Destinatario:** Gerente de Operaciones / Comité de Crisis  
**Organización Ficticia:** Logística y Envíos Federal S.A.  

---

## 1. Situación y Riesgo

Durante el mes de octubre de 2026 se publicaron avisos oficiales sobre vulnerabilidades críticas que impactan directamente sobre nuestros componentes de software:

- **PHP2Shell (CVE-2026-109618 y CVE-2026-109619):** Fallas críticas en el núcleo de PHP relacionadas con la gestión de memoria (errores Out-of-Memory y reutilización de estado global corrupto). En nuestro caso, el portal web corre bajo **Apache con mod_php (SAPI apache2handler)** sobre PHP 8.3.35. Esta combinación es la de mayor exposición conocida: permite ejecución remota de código (RCE) sin autenticación antes de que la propia lógica de la aplicación tome el control. Se encuentra listada en **CISA KEV** con ataques activos en Internet.
- **Node2Shell / HTTP2Shell (CVE-2026-111497):** Desbordamiento de escritura fuera de límites en el descompresor Brotli (versiones 1.0.3 a 1.2.0), que afecta tanto a nuestra API en Node.js 22.23.3 como al servicio de reportes en Python 3.11 con brotli 1.0.9. Al 27/10 no presenta explotación confirmada en el mundo real, aunque el RCE fue probado en entornos de laboratorio.

**Nivel de riesgo institucional:** **Crítico e inminente en el portal PHP**, debido a la exposición a Internet y la explotación real activa; **Medio-Alto en los servicios Node y Python**, dado que son dependencias internas y requieren procesamiento específico de payloads comprimidos sin exploit público masivo.

---

## 2. Plan de Acción Priorizado

| Acción | Activo | Plazo | Dueño | Reversión |
|---|---|---|---|---|
| **1. Mitigación en configuración PHP** | Portal Web PHP (`php-lab`) | Inmediato (< 2 horas) | Vicente Moscuzza (Ops) | Deshacer el cambio en `php.ini` (`session.upload_progress.enabled = 1`) y reiniciar Apache. |
| **2. Restricción perimetral de Brotli** | API Node (`node-lab`) y Svc Python (`py-lab`) | < 4 horas | Vicente Moscuzza (Redes) | Reactivar la aceptación de cabeceras `Content-Encoding: br` en el balanceador. |
| **3. Parcheo del runtime PHP** | Portal Web PHP (`php-lab`) | 24 horas (ventana programada) | Rodrigo Capre (Infraestructura) | Volver a la imagen base previa `php:8.3.35-apache` en el compose. |
| **4. Actualización de Node.js y Python Brotli** | API Node y Svc Python | 48 horas | Rodrigo Capre (DevOps) | Reconstruir contenedores apuntando a versiones previas (Node 22.23.3 y brotli 1.0.9). |

**Justificación del orden:**  
No nos basamos exclusivamente en el puntaje CVSS (ambos son 9.2). Se prioriza PHP porque está presente en el catálogo CISA KEV con ataques reales detectados y corre sobre mod_php. Node.js y Python se ubican después porque no existe exploit activo en la red y es factible mitigar la superficie de ataque a nivel de proxy mientras se planifica el cambio.

---

## 3. Indicadores de Compromiso

- **Señales que confirmarían compromiso:** Presencia en logs de auditoría de procesos hijos anómalos bajo los servidores web (`apache2` o `node` lanzando `/bin/sh`, `/bin/bash`, `curl`, `wget` o `id`), generación de conexiones hacia IPs desconocidas o creación de binarios ejecutables en rutas temporales.
- **Señales que descartarían compromiso:** Ausencia de procesos no autorizados en el árbol de ejecución de los contenedores, integridad total del filesystem de solo lectura y verificación de que la red interna bloqueó cualquier intento de salida.
- **Limitaciones de la telemetría actual:** El archivo `audit.log` relevado no incluye el usuario (UID) que ejecutó los procesos, no captura la IP de origen que envió las solicitudes HTTP ni cuenta con el contexto de las peticiones en los logs de acceso de los servicios.

---

## 4. Transferencia a un Caso Nuevo (CVE-2026-115560)

Ante la aparición de una nueva vulnerabilidad como **CVE-2026-115560** (vulnerabilidad en la carga de archivos multipart en PHP):
1. **Inventario y Exposición:** Se verificaría si el portal expone endpoints de subida (`file_uploads = On`) accesibles por usuarios no autenticados. Si el servicio no utiliza subida de archivos, se mitiga inmediatamente desactivando la directiva en `php.ini`.
2. **Priorización:** Si no figura en KEV, se gestiona mediante el ciclo habitual de parches sin parada de emergencia.
3. **Contención:** Si el parche no está disponible, se implementa una regla en el proxy reverso que descarte peticiones `multipart/form-data` dirigidas a rutas críticas.

---

## 5. Lecciones y Procesos

1. **Gestión de dependencias:** Implementar un inventario continuo de software (SBOM) que alerte de inmediato sobre dependencias embebidas en los runtimes (como Brotli dentro de Node.js).
2. **Contención preventiva:** Establecer como estándar corporativo que los contenedores corran con filesystem `read-only`, sin capacidades innecesarias (`cap_drop: ALL`) y sin salida a Internet por defecto.
3. **Capacidad de auditoría:** Reconfigurar el subsistema de auditoría del sistema operativo para registrar el UID/GID de cada proceso e integrar los logs de red del proxy reverso.

