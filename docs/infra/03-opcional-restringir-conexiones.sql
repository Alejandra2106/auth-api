-- OPCIONAL, CON RIESGO: impedir que roles ajenos se conecten a motor_scoring y motor_scoring_it.
-- Por defecto PUBLIC tiene CONNECT en toda base. Sin este paso, auth_api_it podría CONECTARSE a esas
-- bases, aunque no puede leer ni escribir sus tablas (no tiene privilegios sobre ellas y, desde
-- PostgreSQL 15, tampoco puede crear objetos en "public").
-- RIESGO: cualquier rol que hoy se conecte gracias a PUBLIC perderá el acceso. Antes de ejecutarlo,
-- sustituir <ROL_SCORING_API> por el rol real de scoring-api (DB_USERNAME) y añadir cualquier otro
-- rol legítimo identificado en 00-verificacion-solo-lectura.sql (columna datacl).
-- NO EJECUTAR sin autorización explícita.
\set ON_ERROR_STOP on
\connect postgres

BEGIN;
REVOKE CONNECT ON DATABASE motor_scoring FROM PUBLIC;
GRANT CONNECT ON DATABASE motor_scoring TO <ROL_SCORING_API>, auth_api;

REVOKE CONNECT ON DATABASE motor_scoring_it FROM PUBLIC;
GRANT CONNECT ON DATABASE motor_scoring_it TO <ROL_SCORING_API>;
COMMIT;
