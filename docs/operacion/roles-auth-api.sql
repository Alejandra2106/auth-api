-- auth-api: propietario del esquema auth sin privilegios de superusuario y rol de ejecución.
-- Hoy auth-api y su Flyway usan un rol superusuario. Este script:
--   1. crea el rol propietario (LOGIN, sin contraseña en este archivo; solo para migraciones) y le transfiere
--      el esquema y los objetos que pertenezcan a quien ejecuta el script;
--   2. crea el rol de ejecución con SELECT, INSERT y UPDATE sobre usuario y token_renovacion (sin DELETE ni
--      TRUNCATE) y SELECT sobre el historial de Flyway (la aplicación solo valida las migraciones).
-- No modifica datos. Requiere respaldo verificado y autorización (scoring-api/docs/operacion/despliegue-v10-v11.md).
--
-- Uso: psql -h <host> -U <administrador> -d motor_scoring -v rol_propietario=<rol> -v rol_app=<rol> --        -f roles-auth-api.sql
--   y después, de forma interactiva: \password <rol de ejecución> (y del propietario, si va a migrar)
-- Variables opcionales: esquema (por defecto auth) y base_esperada (por defecto motor_scoring).

\set ON_ERROR_STOP on

\if :{?rol_propietario}
\else
    \echo 'Falta -v rol_propietario=<rol propietario de auth-api>'
    \quit
\endif
\if :{?rol_app}
\else
    \echo 'Falta -v rol_app=<rol de ejecución de auth-api>'
    \quit
\endif
\if :{?esquema}
\else
    \set esquema auth
\endif
\if :{?base_esperada}
\else
    \set base_esperada motor_scoring
\endif

SELECT current_database() = :'base_esperada' AS base_correcta \gset
\if :base_correcta
\else
    \echo 'Conectado a una base distinta de la esperada; no se hace nada'
    \quit
\endif

BEGIN;

CREATE ROLE :"rol_propietario" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
COMMENT ON ROLE :"rol_propietario" IS 'auth-api: propietario del esquema auth; solo para migraciones';
CREATE ROLE :"rol_app" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
COMMENT ON ROLE :"rol_app" IS 'auth-api: rol de ejecución, sin propiedad de las tablas';
GRANT CONNECT ON DATABASE :"base_esperada" TO :"rol_propietario", :"rol_app";

ALTER SCHEMA :"esquema" OWNER TO :"rol_propietario";

SELECT set_config('despliegue.esquema', :'esquema', true), set_config('despliegue.propietario', :'rol_propietario', true);

DO $$
DECLARE
    v_esquema     text := current_setting('despliegue.esquema');
    v_propietario text := current_setting('despliegue.propietario');
    r             record;
BEGIN
    -- Tablas y vistas (sus índices y secuencias de identidad cambian con ellas)
    FOR r IN
        SELECT format('%I.%I', n.nspname, c.relname) AS nombre, c.relkind
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = v_esquema
          AND c.relkind IN ('r', 'p', 'v', 'm')
          AND c.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
          AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = c.oid AND d.deptype = 'e')
    LOOP
        EXECUTE format('ALTER %s %s OWNER TO %I',
            CASE r.relkind WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW' ELSE 'TABLE' END,
            r.nombre, v_propietario);
    END LOOP;
    -- Secuencias independientes (no ligadas a una columna)
    FOR r IN
        SELECT format('%I.%I', n.nspname, c.relname) AS nombre
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = v_esquema AND c.relkind = 'S'
          AND c.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
          AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = c.oid AND d.deptype IN ('a', 'i', 'e'))
    LOOP
        EXECUTE format('ALTER SEQUENCE %s OWNER TO %I', r.nombre, v_propietario);
    END LOOP;
    -- Funciones (incluidas las de triggers y las SECURITY DEFINER)
    FOR r IN
        SELECT p.oid::regprocedure AS firma
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = v_esquema
          AND p.proowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
          AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.deptype = 'e')
    LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO %I', r.firma, v_propietario);
    END LOOP;
END;
$$;

GRANT USAGE ON SCHEMA :"esquema" TO :"rol_app";
GRANT SELECT, INSERT, UPDATE ON :"esquema".usuario, :"esquema".token_renovacion TO :"rol_app";
GRANT SELECT ON :"esquema".flyway_schema_history TO :"rol_app";
GRANT USAGE ON ALL SEQUENCES IN SCHEMA :"esquema" TO :"rol_app";

COMMIT;

SELECT c.relname AS objeto, pg_get_userbyid(c.relowner) AS propietario
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = :'esquema' AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
ORDER BY 1;
SELECT table_name, string_agg(privilege_type, ', ' ORDER BY privilege_type) AS privilegios
FROM information_schema.role_table_grants
WHERE grantee = :'rol_app' AND table_schema = :'esquema'
GROUP BY table_name ORDER BY table_name;
