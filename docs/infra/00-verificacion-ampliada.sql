
\set ON_ERROR_STOP on

-- Q1. Configuracion de contrasenas
SHOW password_encryption;

-- Q2. Privilegios de PUBLIC sobre las bases de datos
SELECT
    d.datname,
    d.datacl,
    COALESCE(
        bool_or(a.privilege_type = 'CONNECT'),
        false
    ) AS public_connect,
    COALESCE(
        bool_or(a.privilege_type = 'TEMPORARY'),
        false
    ) AS public_temp
FROM pg_database d
LEFT JOIN LATERAL aclexplode(
    COALESCE(d.datacl, acldefault('d', d.datdba))
) a ON a.grantee = 0
WHERE d.datname IN (
    'postgres',
    'motor_scoring',
    'motor_scoring_it',
    'motor_scoring_auth_it'
)
GROUP BY d.datname, d.datacl
ORDER BY d.datname;
-- Q3. Roles existentes
SELECT
    rolname,
    rolsuper,
    rolcanlogin,
    rolinherit,
    rolcreaterole,
    rolcreatedb,
    rolbypassrls
FROM pg_roles
WHERE rolname !~ '^pg_'
ORDER BY rolname;

-- Q4. Membresias entre roles
SELECT
    granted.rolname AS rol_concedido,
    member.rolname AS miembro,
    am.inherit_option,
    am.set_option,
    am.admin_option
FROM pg_auth_members am
JOIN pg_roles granted ON granted.oid = am.roleid
JOIN pg_roles member ON member.oid = am.member
WHERE member.rolname !~ '^pg_'
ORDER BY member.rolname, granted.rolname;

-- Q5-Q7. Inspeccionar motor_scoring
\connect motor_scoring

SELECT current_database();

-- Q5a. Permisos de PUBLIC sobre el esquema public
SELECT
    n.nspname,
    COALESCE(
        bool_or(a.privilege_type = 'USAGE'),
        false
    ) AS public_usage,
    COALESCE(
        bool_or(a.privilege_type = 'CREATE'),
        false
    ) AS public_create
FROM pg_namespace n
LEFT JOIN LATERAL aclexplode(
    COALESCE(n.nspacl, acldefault('n', n.nspowner))
) a ON a.grantee = 0
WHERE n.nspname = 'public'
GROUP BY n.nspname;

-- Q5b. Funciones en public
SELECT
    p.oid::regprocedure AS funcion,
    p.proacl
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public'
ORDER BY 1;

-- Q6. Permisos por defecto personalizados
SELECT
    defaclrole::regrole AS propietario,
    defaclnamespace::regnamespace AS esquema,
    defaclobjtype AS tipo_objeto,
    defaclacl AS privilegios
FROM pg_default_acl
ORDER BY 1, 2, 3;

-- Q7. Tablas, vistas y secuencias de public
SELECT
    c.relname,
    c.relkind,
    c.relowner::regrole AS propietario,
    c.relacl
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
ORDER BY c.relname;

-- Inspeccionar motor_scoring_it
\connect motor_scoring_it

SELECT current_database();

-- Q5a. Permisos de PUBLIC sobre el esquema public
SELECT
    has_schema_privilege('public', 'public', 'USAGE') AS public_usage,
    has_schema_privilege('public', 'public', 'CREATE') AS public_create;

-- Q5b. Funciones en public
SELECT
    p.oid::regprocedure AS funcion,
    p.proacl
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public'
ORDER BY 1;

-- Q6. Permisos por defecto personalizados
SELECT
    defaclrole::regrole AS propietario,
    defaclnamespace::regnamespace AS esquema,
    defaclobjtype AS tipo_objeto,
    defaclacl AS privilegios
FROM pg_default_acl
ORDER BY 1, 2, 3;

-- Q7. Tablas, vistas y secuencias de public
SELECT
    c.relname,
    c.relkind,
    c.relowner::regrole AS propietario,
    c.relacl
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
ORDER BY c.relname;
