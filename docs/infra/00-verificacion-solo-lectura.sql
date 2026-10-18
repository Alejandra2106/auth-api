-- Verificación previa, SOLO LECTURA. No crea ni modifica nada.
-- Ejecutar con psql conectado a la base "postgres" de la instancia de destino.
\set ON_ERROR_STOP on

-- 1. Instancia, versión y usuario con el que se ejecutarán los scripts
SELECT version(), current_user, inet_server_addr(), inet_server_port();

-- 2. El usuario actual debe poder crear roles y bases (o ser superusuario)
SELECT rolname, rolsuper, rolcreaterole, rolcreatedb
FROM pg_roles WHERE rolname = current_user;

-- 3. Bases relevantes: deben existir motor_scoring y motor_scoring_it; motor_scoring_auth_it NO debe existir
SELECT datname, pg_get_userbyid(datdba) AS propietario, datacl
FROM pg_database
WHERE datname IN ('motor_scoring', 'motor_scoring_it', 'motor_scoring_auth_it')
ORDER BY datname;

-- 4. Los roles nuevos NO deben existir todavía
SELECT rolname FROM pg_roles WHERE rolname IN ('auth_api', 'auth_api_it');

-- 5. Dentro de motor_scoring: el esquema "auth" NO debe existir; "public" y su historial de Flyway no se tocan
\connect motor_scoring
SELECT current_database();
SELECT nspname, pg_get_userbyid(nspowner) AS propietario, nspacl
FROM pg_namespace WHERE nspname IN ('public', 'auth', 'consulta') ORDER BY nspname;
SELECT version, description, success
FROM public.flyway_schema_history ORDER BY installed_rank;

-- 6. Ningún privilegio sobre tablas de "public" debe estar concedido a PUBLIC
--    (si aparece alguno, auth_api lo heredaría; revisar antes de continuar)
SELECT table_name, privilege_type
FROM information_schema.role_table_grants
WHERE table_schema = 'public' AND grantee = 'PUBLIC';
