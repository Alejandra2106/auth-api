-- PARTE B: base de pruebas de integración exclusiva de auth-api, con un rol propio.
-- NO EJECUTAR sin autorización explícita. Ejecutar de forma interactiva con psql (\password).
-- Solo crea objetos nuevos; no toca motor_scoring ni motor_scoring_it.
\set ON_ERROR_STOP on

\connect postgres
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auth_api_it') THEN
        RAISE EXCEPTION 'El rol auth_api_it ya existe: revisar antes de continuar';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_database WHERE datname = 'motor_scoring_auth_it') THEN
        RAISE EXCEPTION 'La base motor_scoring_auth_it ya existe: revisar antes de continuar';
    END IF;
END $$;

CREATE ROLE auth_api_it LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
\password auth_api_it

-- El nombre termina en _it: la protección de las IT de auth-api lo exige
CREATE DATABASE motor_scoring_auth_it TEMPLATE template0;
-- Solo auth_api_it (y el propietario) pueden conectarse a la base de pruebas
REVOKE CONNECT, TEMPORARY ON DATABASE motor_scoring_auth_it FROM PUBLIC;
GRANT CONNECT ON DATABASE motor_scoring_auth_it TO auth_api_it;

\connect motor_scoring_auth_it
DO $$
BEGIN
    IF current_database() <> 'motor_scoring_auth_it' THEN
        RAISE EXCEPTION 'Conectado a una base inesperada: %', current_database();
    END IF;
END $$;

BEGIN;
-- En esta base nueva nadie más necesita "public"
REVOKE ALL ON SCHEMA public FROM PUBLIC;
-- Permisos mínimos para Flyway y las pruebas: propiedad del esquema "auth" (crear tablas, índices,
-- restricciones, historial de Flyway y operar sobre sus propias filas). Nada más.
CREATE SCHEMA auth AUTHORIZATION auth_api_it;
ALTER ROLE auth_api_it IN DATABASE motor_scoring_auth_it SET search_path = auth;
COMMIT;

-- Comprobación posterior (solo lectura)
SELECT has_database_privilege('auth_api_it', 'motor_scoring_auth_it', 'CONNECT') AS conecta_a_pruebas,
       has_database_privilege('auth_api_it', 'motor_scoring', 'CONNECT')         AS conecta_a_motor,
       has_database_privilege('auth_api_it', 'motor_scoring_it', 'CONNECT')      AS conecta_a_it_hu11;
