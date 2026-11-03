# Informe individual — Grupo 02

**Integrante:** Petosa Ayala, Franco · **Fecha:** jueves 29/10/2026
**Destinatario:** gerente de operaciones / comité de crisis
**Caso asignado:** Node2Shell / HTTP2Shell (CVE-2026-111497)

---

## 1. Situación y riesgo

Node2Shell es una falla de escritura fuera de límites en el decodificador **Brotli**, la
librería que descomprime datos. Afecta a Brotli 1.0.3 a 1.2.0 y, por eso, a Node.js,
Bun, Python, .NET, Envoy e Istio. Está corregida en Brotli 1.0.10, 1.1.1 y 1.2.1, y en
Node 22.23.4, 24.22.1 y 26.12.1.

**Estado de la amenaza:** CISA la incorporó al catálogo de vulnerabilidades explotadas
(KEV) el 27/10. Sin embargo, el exploit público visto en la práctica falla en su última
etapa: en las pruebas que figuran en el contexto del TP no logró abrir ninguna
consola en 50 intentos, aunque otro equipo sí consiguió ejecutar código en cuatro
configuraciones de laboratorio. Además, los intentos fallidos igual **tumban el
proceso**, lo que ya es una caída del servicio sin autenticación. KEV confirma
explotación activa, no un compromiso masivo exitoso.

**Qué nos afecta:** nuestra API Node 22.23.3 decodifica cuerpos `Content-Encoding: br`
(`POST /decode`), y nuestro servicio Python usa la misma librería (1.0.9). Asumimos la
API publicada en Internet.

**Riesgo: medio-alto.** La explotación es real pero poco confiable, y el efecto más
probable hoy es una caída del servicio.

## 2. Plan de acción priorizado

| Acción | Activo | Plazo | Dueño | Reversión |
|---|---|---|---|---|
| Rechazar `Content-Encoding: br` en el proxy mientras se parchea (si no se necesita) | API Node | Inmediato | Responsable de red/proxy | Quitar la regla del proxy |
| Parchear Node 22.23.3 → 22.23.4 | API Node | Menos de 72 h (hecho el 29/10, 22:17 UTC) | Responsable de cambios | `docker compose --env-file versions.env up -d --build` sin las variables del parche |
| Actualizar brotli de Python 1.0.9 → 1.2.1 | Servicio Python | En el mismo cambio o dentro de la semana | Responsable de cambios | Ídem |
| Vigilar caídas inesperadas del proceso Node | API Node | Continuo | Responsable de detección | No aplica |

**Por qué este orden:** el portal PHP va primero porque su explotación es confiable y
no depende de la aplicación. La API Node va segunda: está en KEV, pero requiere que la
aplicación decodifique Brotli. Python va tercero por estar solo en la red interna.

## 3. Indicadores de compromiso

**Confirmarían un incidente:** un proceso `node` que lanza `sh`, `curl` o `wget`;
reinicios o caídas repetidas del proceso sin causa clara (señal de intentos fallidos);
peticiones con `Content-Encoding: br` desde orígenes desconocidos en los registros del
proxy.

**Lo descartarían:** ninguna de las señales anteriores en el período desde el 26/10
(primera actividad maliciosa registrada), con telemetría de procesos activa.

**Lo que no podemos saber:** el log del TP es sintético y no incluye registros de red ni
del proxy, así que no podemos mirar peticiones.

## 4. Transferencia: Log4Shell (CVE-2021-44228)

**Qué fue:** una falla en la librería de registros Log4j 2 (versiones 2.0-beta9 a
2.14.1) que permitía ejecutar código al registrar un texto con `${jndi:...}`. CVSS 10.0.
Se divulgó en diciembre de 2021 y se corrigió en 2.15.0, con arreglos posteriores en
2.16.0 y 2.17.0.

**Por qué se parece a Node2Shell:** en ambos casos la librería vulnerable era una
**dependencia oculta**, que muchas aplicaciones usaban sin saberlo.

**Cómo lo priorizaría con el mismo marco:**

- **Explotación real:** masiva desde el primer día, así que es emergencia.
- **Primer paso:** inventariar dónde está Log4j, incluyendo las dependencias de las
  dependencias, porque el manifiesto de la aplicación no alcanza.
- **Mitigación mientras se parchea:** desactivar las búsquedas JNDI o quitar esa clase
  de la librería, y bloquear conexiones salientes desde los servidores.
- **Cómo lo detectaría:** cadenas `${jndi:` en los registros y conexiones salientes
  inesperadas (LDAP, RMI) desde servidores de aplicación.

## 5. Lecciones y procesos

Mi parte fue el parche. Aplicamos las tres actualizaciones con `parchear.sh`, pero el
primer intento falló por un error de certificado de la red al construir la imagen de
Node, y el segundo por un timeout; lo dejamos documentado y el tercero funcionó. Dos
lecciones concretas: después del parche el texto de versión de Brotli en Node sigue
diciendo 1.1.0, porque la corrección va dentro del runtime, así que hay que mirar la
versión de Node y no la de la librería; y el parche se aplicó con variables de entorno
sin guardarlo en `versions.env`, por lo que un reinicio común podría volver a las
versiones vulnerables. Para la próxima vez: persistir el cambio de versión en el
repositorio y probar la conectividad antes de abrir la ventana de cambio.
