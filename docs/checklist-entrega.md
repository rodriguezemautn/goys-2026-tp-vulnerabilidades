# Checklist de entrega — TP de vulnerabilidades

Marcá cada ítem antes de abrir el PR.

## Repo y proceso

- [x] El grupo tiene **un solo fork** del repo base (no uno por integrante).
- [x] El dueño del fork agregó al resto como **colaboradores** y todos aceptaron.
- [x] Cloné el **fork del grupo** y creé/uso la rama `grupo-XX`.
- [x] Copié `entregables/plantilla.md` a `entregables/grupo-XX/entrega.md`.
- [x] Todos los integrantes aparecen con nombre, usuario de GitHub y rol.
- [x] Cada integrante tiene al menos un commit con su usuario de GitHub.
- [x] Los commits son convencionales y por aporte.
- [x] El repo no contiene claves, tokens, `.env` ni `secret.yml`.

## Laboratorio

- [x] `./scripts/arrancar-2h.sh` levanta los 3 servicios `healthy`.
- [x] `./scripts/inventario.sh` muestra las versiones reales.
- [x] `./scripts/parchear.sh` aplica las versiones corregidas.
- [x] La prueba funcional mínima pasa después del parche.
- [x] `./scripts/verificar-contencion.sh` muestra `SIN SALIDA` en los 3 servicios.
- [x] El laboratorio quedó apagado (`docker compose down -v`).

## Entregables

- [x] `entrega.md` con inventario, matriz, cambios, contención y conclusión.
- [x] `deteccion.md` con hipótesis, hallazgos, regla y limitaciones.
- [x] `informe.md` individual, 2–3 páginas.
- [x] Capturas o salidas referenciadas (si usaste `capturas/`).
- [x] No hay texto “pendiente”, “TODO” o placeholders.
- [x] Las tablas están completas y se entienden sin abrir el lab.

## Evidencia

- [x] Cada afirmación técnica tiene un comando, una salida o una captura.
- [x] Se distingue “probado” de “planeado”.
- [x] Se declara lo que no se pudo probar y por qué.
- [x] El change log incluye reversión.

## Entrega

- [x] `git push origin grupo-XX` al fork del grupo.
- [x] PR abierto desde el fork del grupo a
      `rodriguezemautn/goys-2026-tp-vulnerabilidades:main`.
- [x] Título del PR: `[Grupo XX] Entrega TP vulnerabilidades`.
- [x] Enlace del PR (o del fork del grupo) pegado en el aula virtual.
- [ ] Entregado **antes de salir del aula del jueves 29/10**.
