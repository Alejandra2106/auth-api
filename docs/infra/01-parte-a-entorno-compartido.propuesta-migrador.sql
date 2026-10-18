-- PROPUESTA (no sustituye a 01-parte-a-entorno-compartido.sql). NO EJECUTAR sin autorización explícita
-- de cada fase.
--
-- Diseño: separación de privilegios en la base compartida motor_scoring.
--   auth_migrator  LOGIN. Propietario del esquema "auth" y de todo lo que crea Flyway en él
--                  (tablas, índices, auth.flyway_schema_history). Lo usa solo Flyway.
--   auth_api       LOGIN. Usuario de ejecución: USAGE sobre "auth" (sin CREATE) y DML explícito y
--                  mínimo sobre las tablas operativas. Ningún privilegio sobre flyway_schema_history.
-- Ninguno de los dos recibe privilegios en "public" ni sobre los objetos de scoring-api. No se
-- revoca nada de PUBLIC ni se modifica ningún objeto existente.
--
-- Uso: una fase por ejecución, conectado como postgres, por ejemplo
--   psql -h 127.0.0.1 -p 5432 -U postgres -d postgres -v fase=A1 -f 01-parte-a-entorno-compartido.propuesta-migrador.sql
-- Fases:
--   previo    solo lectura  instancia: roles inexistentes, autenticación y registro de sentencias
--   A1        escritura     crea los roles auth_migrator y auth_api (sin contraseña)
--   A2, A3    interactivas  NO están en este archivo: en una sesión psql interactiva como postgres
--                           ejecutar \password auth_migrator   y, por separado,   \password auth_api
--                           (contraseñas distintas; psql calcula SCRAM en el cliente y no guarda la
--                           contraseña en el historial)
--   verif-A   solo lectura  atributos, contraseñas SCRAM presentes y membresías
--   B1        escritura     motor_scoring: CONNECT, esquema auth (propietario auth_migrator),
--                           USAGE para auth_api y search_path por base
--   verif-B1  solo lectura  privilegios efectivos tras B1
--   B2        externa       NO está en este archivo: primera ejecución de Flyway de auth-api con las
--                           credenciales de auth_migrator (autorización separada, ver documentación)
--   B3        escritura     permisos de ejecución de auth_api sobre las tablas creadas por V1
--   verif-B3  solo lectura  matriz final de privilegios en "auth"
--
-- Recuperación (sin borrados automáticos):
--   * Cada fase de escritura es una única transacción: si falla, no queda nada aplicado.
--   * Rol sin contraseña tras A1: no puede autenticarse por SCRAM; repetir \password.
--   * Neutralizar un rol sin eliminarlo:            ALTER ROLE <rol> NOLOGIN;
--   * Deshacer B1 sin eliminar el esquema (vacío):  ALTER ROLE <rol> IN DATABASE motor_scoring RESET search_path;
--                                                   REVOKE CONNECT ON DATABASE motor_scoring FROM <rol>;
--   * Deshacer B3:                                  REVOKE ALL ON ALL TABLES IN SCHEMA auth FROM auth_api;
--   Cualquier DROP requiere una autorización específica.

\set ON_ERROR_STOP on
\encoding UTF8

\if :{?fase}
\else
    \echo 'Indique la fase con -v fase=<previo|A1|verif-A|B1|verif-B1|B3|verif-B3>'
    \quit
\endif

SELECT :'fase' IN ('previo', 'A1', 'verif-A', 'B1', 'verif-B1', 'B3', 'verif-B3') AS fase_valida,
       :'fase' = 'previo'   AS fase_previo,
       :'fase' = 'A1'       AS fase_a1,
       :'fase' = 'verif-A'  AS fase_verif_a,
       :'fase' = 'B1'       AS fase_b1,
       :'fase' = 'verif-B1' AS fase_verif_b1,
       :'fase' = 'B3'       AS fase_b3,
       :'fase' = 'verif-B3' AS fase_verif_b3 \gset

\if :fase_valida
\else
    DO $$ BEGIN RAISE EXCEPTION 'Fase no reconocida'; END $$;
\endif

-- ---------------------------------------------------------------------------------------------
\if :fase_previo
\connect postgres
BEGIN READ ONLY;
-- Debe devolver cero filas
SELECT rolname FROM pg_roles WHERE rolname IN ('auth_migrator', 'auth_api');
-- password_encryption debe ser scram-sha-256; log_statement no debe ser ddl ni all
SELECT name, setting FROM pg_settings
WHERE name IN ('password_encryption', 'log_statement', 'log_min_duration_statement') ORDER BY name;
-- Ninguna regla host/hostssl/hostnossl con trust o password para las conexiones locales
SELECT rule_number, type, database, user_name, address, auth_method
FROM pg_hba_file_rules WHERE error IS NULL ORDER BY rule_number;
-- Debe existir motor_scoring
SELECT datname, pg_get_userbyid(datdba) AS propietario, datacl FROM pg_database WHERE datname = 'motor_scoring';
ROLLBACK;
\endif

-- ---------------------------------------------------------------------------------------------
\if :fase_a1
\connect postgres
BEGIN;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('auth_migrator', 'auth_api')) THEN
        RAISE EXCEPTION 'auth_migrator o auth_api ya existen: revisar antes de continuar';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'motor_scoring') THEN
        RAISE EXCEPTION 'No existe la base motor_scoring';
    END IF;
END $$;
CREATE ROLE auth_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE auth_api      LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
COMMIT;
\endif

-- ---------------------------------------------------------------------------------------------
\if :fase_verif_a
\connect postgres
BEGIN READ ONLY;
SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin,
       rolreplication, rolbypassrls, rolconnlimit, rolvaliduntil
FROM pg_roles WHERE rolname IN ('auth_migrator', 'auth_api') ORDER BY rolname;
-- No muestra el verificador: solo si existe y si es SCRAM
SELECT rolname,
       rolpassword IS NOT NULL                          AS tiene_password,
       coalesce(rolpassword LIKE 'SCRAM-SHA-256$%', false) AS es_scram
FROM pg_authid WHERE rolname IN ('auth_migrator', 'auth_api') ORDER BY rolname;
-- Debe devolver cero filas
SELECT g.rolname AS grupo, m.rolname AS miembro
FROM pg_auth_members am
JOIN pg_roles g ON g.oid = am.roleid
JOIN pg_roles m ON m.oid = am.member
WHERE g.rolname IN ('auth_migrator', 'auth_api') OR m.rolname IN ('auth_migrator', 'auth_api');
ROLLBACK;
\endif

-- ---------------------------------------------------------------------------------------------
\if :fase_b1
\connect motor_scoring
BEGIN;
DO $$
BEGIN
    IF current_database() <> 'motor_scoring' THEN
        RAISE EXCEPTION 'Conectado a una base inesperada: %', current_database();
    END IF;
    IF (SELECT count(*) FROM pg_roles
        WHERE rolname IN ('auth_migrator', 'auth_api')
          AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole
          AND NOT rolreplication AND NOT rolbypassrls) <> 2 THEN
        RAISE EXCEPTION 'auth_migrator y auth_api deben existir con los atributos de la fase A1';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'auth') THEN
        RAISE EXCEPTION 'El esquema auth ya existe: revisar antes de continuar';
    END IF;
END $$;
-- Explícito e independiente de PUBLIC (no se modifica lo que PUBLIC tiene hoy)
GRANT CONNECT ON DATABASE motor_scoring TO auth_migrator, auth_api;
-- El rol de migraciones es el propietario: Flyway crea aquí sus tablas y su historial
CREATE SCHEMA auth AUTHORIZATION auth_migrator;
-- El rol de ejecución solo puede resolver nombres en "auth"; no puede crear objetos
GRANT USAGE ON SCHEMA auth TO auth_api;
ALTER ROLE auth_migrator IN DATABASE motor_scoring SET search_path = auth;
ALTER ROLE auth_api      IN DATABASE motor_scoring SET search_path = auth;
-- Sin ALTER DEFAULT PRIVILEGES: Flyway crea auth.flyway_schema_history en su primera ejecución y
-- cualquier privilegio por defecto sobre tablas de auth_migrator se le aplicaría también.
-- Ningún GRANT sobre "public".
COMMIT;
\endif

-- ---------------------------------------------------------------------------------------------
\if :fase_verif_b1
\connect motor_scoring
BEGIN READ ONLY;
SELECT nspname, pg_get_userbyid(nspowner) AS propietario, nspacl FROM pg_namespace WHERE nspname IN ('auth', 'public');
-- Esperado: auth_migrator USAGE+CREATE en auth; auth_api solo USAGE en auth; ninguno CREATE en public
SELECT r.rolname, n.nspname,
       has_schema_privilege(r.oid, n.oid, 'USAGE')  AS usage,
       has_schema_privilege(r.oid, n.oid, 'CREATE') AS crear
FROM pg_namespace n CROSS JOIN pg_roles r
WHERE n.nspname IN ('auth', 'public') AND r.rolname IN ('auth_migrator', 'auth_api')
ORDER BY r.rolname, n.nspname;
-- Esperado: cero filas (ningún privilegio sobre tablas, vistas o secuencias de public)
SELECT r.rolname, c.relname, c.relkind
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN pg_roles r
WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
  AND r.rolname IN ('auth_migrator', 'auth_api')
  AND (has_table_privilege(r.oid, c.oid, 'SELECT') OR has_table_privilege(r.oid, c.oid, 'INSERT')
       OR has_table_privilege(r.oid, c.oid, 'UPDATE') OR has_table_privilege(r.oid, c.oid, 'DELETE')
       OR has_table_privilege(r.oid, c.oid, 'TRUNCATE') OR has_table_privilege(r.oid, c.oid, 'REFERENCES')
       OR has_table_privilege(r.oid, c.oid, 'TRIGGER'))
UNION ALL
SELECT r.rolname, c.relname, c.relkind
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN pg_roles r
WHERE n.nspname = 'public' AND c.relkind = 'S'
  AND r.rolname IN ('auth_migrator', 'auth_api')
  AND (has_sequence_privilege(r.oid, c.oid, 'USAGE') OR has_sequence_privilege(r.oid, c.oid, 'SELECT')
       OR has_sequence_privilege(r.oid, c.oid, 'UPDATE'));
SELECT coalesce(r.rolname, '(todos)') AS rol, coalesce(d.datname, '(todas)') AS base, s.setconfig
FROM pg_db_role_setting s
LEFT JOIN pg_roles r ON r.oid = s.setrole
LEFT JOIN pg_database d ON d.oid = s.setdatabase
WHERE r.rolname IN ('auth_migrator', 'auth_api');
-- Esperado: cero filas
SELECT pg_get_userbyid(defaclrole) AS rol, defaclnamespace::regnamespace AS esquema, defaclobjtype, defaclacl
FROM pg_default_acl;
ROLLBACK;
\endif

-- ---------------------------------------------------------------------------------------------
\if :fase_b3
\connect motor_scoring
BEGIN;
DO $$
BEGIN
    IF current_database() <> 'motor_scoring' THEN
        RAISE EXCEPTION 'Conectado a una base inesperada: %', current_database();
    END IF;
    -- B2 debe haber terminado: historial y tablas de V1 creados por auth_migrator
    IF (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'auth' AND c.relkind = 'r'
          AND c.relname IN ('flyway_schema_history', 'usuario', 'token_renovacion')
          AND c.relowner = 'auth_migrator'::regrole) <> 3 THEN
        RAISE EXCEPTION 'Faltan tablas de V1 o del historial de Flyway propiedad de auth_migrator en auth';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
               WHERE n.nspname = 'auth' AND c.relowner <> 'auth_migrator'::regrole) THEN
        RAISE EXCEPTION 'Hay objetos en auth que no pertenecen a auth_migrator';
    END IF;
    IF EXISTS (SELECT 1 FROM auth.flyway_schema_history WHERE NOT success) THEN
        RAISE EXCEPTION 'El historial de Flyway contiene migraciones fallidas';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_default_acl) THEN
        RAISE EXCEPTION 'Existen privilegios por defecto no previstos: revisar antes de continuar';
    END IF;
END $$;
-- Concede el propietario, para que quede registrado como otorgante
SET LOCAL ROLE auth_migrator;
-- usuario: altas (merge con UUID asignado = SELECT + INSERT) y consultas; el código no actualiza ni borra
GRANT SELECT, INSERT ON auth.usuario TO auth_api;
-- token_renovacion: altas, consulta con FOR UPDATE y marcado de uso/revocación (únicas columnas que
-- actualiza el código). FOR UPDATE exige UPDATE sobre al menos una columna. Sin DELETE.
GRANT SELECT, INSERT ON auth.token_renovacion TO auth_api;
GRANT UPDATE (usado_en, revocado_en) ON auth.token_renovacion TO auth_api;
-- Ningún privilegio sobre auth.flyway_schema_history
RESET ROLE;
COMMIT;
\endif

-- ---------------------------------------------------------------------------------------------
\if :fase_verif_b3
\connect motor_scoring
BEGIN READ ONLY;
-- Esperado: usuario SELECT+INSERT; token_renovacion SELECT+INSERT; flyway_schema_history todo false
SELECT c.relname,
       has_table_privilege('auth_api', c.oid, 'SELECT')     AS sel,
       has_table_privilege('auth_api', c.oid, 'INSERT')     AS ins,
       has_table_privilege('auth_api', c.oid, 'UPDATE')     AS upd_tabla,
       has_table_privilege('auth_api', c.oid, 'DELETE')     AS del,
       has_table_privilege('auth_api', c.oid, 'TRUNCATE')   AS trn,
       has_table_privilege('auth_api', c.oid, 'REFERENCES') AS ref,
       has_table_privilege('auth_api', c.oid, 'TRIGGER')    AS trg,
       pg_get_userbyid(c.relowner)                          AS propietario
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'auth' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
ORDER BY c.relname;
-- Esperado: UPDATE solo en token_renovacion.usado_en y token_renovacion.revocado_en
SELECT c.relname, a.attname
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'auth' AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
  AND has_column_privilege('auth_api', c.oid, a.attnum, 'UPDATE')
ORDER BY c.relname, a.attname;
-- Esperado: false
SELECT has_schema_privilege('auth_api', 'auth', 'CREATE') AS auth_api_crea_en_auth;
ROLLBACK;
\endif
