-- PARTE A: rol "auth_api" y esquema "auth" en la base compartida motor_scoring.
-- NO EJECUTAR sin autorización explícita y sin revisar antes 00-verificacion-solo-lectura.sql.
-- Ejecutar de forma interactiva con psql (\password pide la contraseña sin mostrarla ni guardarla
-- en el historial). El script no contiene contraseñas.
-- No modifica ningún objeto existente: solo crea un rol nuevo y un esquema nuevo.
\set ON_ERROR_STOP on

\connect postgres
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auth_api') THEN
        RAISE EXCEPTION 'El rol auth_api ya existe: revisar antes de continuar';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'motor_scoring') THEN
        RAISE EXCEPTION 'No existe la base motor_scoring';
    END IF;
END $$;

-- Rol de aplicación sin privilegios administrativos
CREATE ROLE auth_api LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
\password auth_api

\connect motor_scoring
DO $$
BEGIN
    IF current_database() <> 'motor_scoring' THEN
        RAISE EXCEPTION 'Conectado a una base inesperada: %', current_database();
    END IF;
    IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'auth') THEN
        RAISE EXCEPTION 'El esquema auth ya existe: revisar antes de continuar';
    END IF;
END $$;

BEGIN;
GRANT CONNECT ON DATABASE motor_scoring TO auth_api;
-- auth_api es propietario SOLO de "auth": Flyway de auth-api crea ahí sus tablas y su historial
CREATE SCHEMA auth AUTHORIZATION auth_api;
ALTER ROLE auth_api IN DATABASE motor_scoring SET search_path = auth;
-- Ningún GRANT sobre "public": auth_api no puede leer ni escribir datos de scoring-api.
COMMIT;

-- Comprobación posterior (solo lectura)
SELECT nspname, pg_get_userbyid(nspowner) AS propietario FROM pg_namespace WHERE nspname = 'auth';
SELECT has_schema_privilege('auth_api', 'public', 'CREATE') AS puede_crear_en_public,
       has_schema_privilege('auth_api', 'auth', 'CREATE')   AS puede_crear_en_auth;
