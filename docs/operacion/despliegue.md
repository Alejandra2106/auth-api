# Despliegue de auth-api

- Flyway solo migra el esquema `auth`, y únicamente en un arranque con `AUTH_FLYWAY_MIGRAR_AL_ARRANCAR=true`
  (con `SPRING_FLYWAY_USER` y `SPRING_FLYWAY_PASSWORD` del propietario). Sin esa variable, Flyway solo valida:
  con migraciones pendientes la aplicación no arranca y no aplica nada (`config/FlywayArranqueConfig`). Antes de
  migrar una base con datos: respaldo verificado, revisión del plan y autorización.
- Roles: propietario del esquema (solo migraciones) y rol de ejecución con SELECT, INSERT y UPDATE sobre
  `usuario` y `token_renovacion` y SELECT sobre el historial de Flyway. En una base nueva los crea
  `roles-auth-api.sql`. En `motor_scoring` ya existían (`auth_migrator` y `auth_api`); el 2026-10-19 se dio a
  `auth_api` SELECT sobre el historial de Flyway y se le retiró DELETE (registro en
  `scoring-api/docs/operacion/despliegue-v10-v11.md`).
- Primer administrador y restablecimiento de contraseña: README, perfiles `bootstrap-admin` y `reset-admin`.
