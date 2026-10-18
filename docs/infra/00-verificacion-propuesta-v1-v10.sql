-- PROPUESTA. Diagnóstico de SOLO LECTURA (V1-V10). No crea, altera ni elimina objetos.
-- Cada bloque se ejecuta dentro de BEGIN READ ONLY ... ROLLBACK; los \connect quedan fuera de las
-- transacciones. NO EJECUTAR sin autorización explícita.
-- Uso (como postgres; V2 y V9b requieren superusuario):
--   psql -h 127.0.0.1 -p 5432 -U postgres -d postgres -f 00-verificacion-propuesta-v1-v10.sql

\set ON_ERROR_STOP on
\encoding UTF8

-- =============================================================================================
-- BLOQUE I. Instancia
-- =============================================================================================
\connect postgres
BEGIN READ ONLY;
SELECT current_database() AS base, current_user AS usuario, version() AS version_servidor;

-- V1 Atributos de los roles
SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin,
       rolreplication, rolbypassrls, rolconnlimit, rolvaliduntil
FROM pg_roles
WHERE rolname IN ('auth_migrator', 'auth_api', 'postgres')
ORDER BY rolname;

-- V2 Contraseña presente y en formato SCRAM, sin mostrar el verificador (requiere superusuario)
SELECT rolname,
       rolpassword IS NOT NULL                             AS tiene_password,
       coalesce(rolpassword LIKE 'SCRAM-SHA-256$%', false) AS es_scram
FROM pg_authid
WHERE rolname IN ('auth_migrator', 'auth_api')
ORDER BY rolname;

-- V3 Membresías en ambas direcciones
SELECT g.rolname                   AS grupo,
       m.rolname                   AS miembro,
       am.admin_option,
       am.inherit_option,
       am.set_option,
       pg_get_userbyid(am.grantor) AS otorgante
FROM pg_auth_members am
JOIN pg_roles g ON g.oid = am.roleid
JOIN pg_roles m ON m.oid = am.member
WHERE g.rolname IN ('auth_migrator', 'auth_api')
   OR m.rolname IN ('auth_migrator', 'auth_api')
ORDER BY grupo, miembro;

-- V4 Privilegios efectivos sobre las bases
SELECT r.rolname,
       d.datname,
       pg_get_userbyid(d.datdba)                         AS propietario,
       d.datacl,
       has_database_privilege(r.oid, d.oid, 'CONNECT')   AS conecta,
       has_database_privilege(r.oid, d.oid, 'TEMPORARY') AS temporal,
       has_database_privilege(r.oid, d.oid, 'CREATE')    AS crea_esquemas
FROM pg_database d
CROSS JOIN pg_roles r
WHERE NOT d.datistemplate
  AND r.rolname IN ('auth_migrator', 'auth_api')
ORDER BY r.rolname, d.datname;

-- V5 Configuración por rol y base
SELECT coalesce(r.rolname, '(todos)') AS rol,
       coalesce(d.datname, '(todas)') AS base,
       s.setconfig
FROM pg_db_role_setting s
LEFT JOIN pg_roles r    ON r.oid = s.setrole
LEFT JOIN pg_database d ON d.oid = s.setdatabase
ORDER BY rol, base;

-- V9a Parámetros de autenticación y registro
SELECT name, setting
FROM pg_settings
WHERE name IN ('password_encryption', 'log_statement',
               'log_min_duration_statement', 'log_connections')
ORDER BY name;

-- V9b Reglas activas de pg_hba (requiere superusuario)
SELECT rule_number, type, database, user_name, address, netmask, auth_method
FROM pg_hba_file_rules
WHERE error IS NULL
ORDER BY rule_number;

-- V9c Sesiones de cliente por usuario y base
SELECT usename, datname, application_name, client_addr, count(*) AS sesiones
FROM pg_stat_activity
WHERE backend_type = 'client backend'
GROUP BY usename, datname, application_name, client_addr
ORDER BY usename, datname;

-- V10 Objetos que dependen de cada rol (propiedad, ACL, políticas), en cualquier base.
-- La descripción solo se resuelve para objetos compartidos o de la base actual.
SELECT coalesce(d.datname, '(compartido)') AS base,
       pg_get_userbyid(s.refobjid)         AS rol,
       s.classid::regclass                 AS catalogo,
       s.objid,
       s.deptype,
       CASE WHEN s.dbid IN (0, (SELECT oid FROM pg_database
                                WHERE datname = current_database()))
            THEN pg_describe_object(s.classid, s.objid, s.objsubid)
       END                                 AS objeto
FROM pg_shdepend s
LEFT JOIN pg_database d ON d.oid = s.dbid
WHERE s.refclassid = 'pg_authid'::regclass
  AND s.refobjid IN (SELECT oid FROM pg_roles
                     WHERE rolname IN ('auth_migrator', 'auth_api'))
ORDER BY base, rol;

ROLLBACK;


-- =============================================================================================
-- BLOQUE II. Base motor_scoring
-- =============================================================================================
\connect motor_scoring
BEGIN READ ONLY;
SELECT current_database() AS base, current_user AS usuario;

-- V6 Esquemas: propietario, ACL y privilegios efectivos
SELECT n.nspname,
       pg_get_userbyid(n.nspowner)                  AS propietario,
       n.nspacl,
       r.rolname,
       has_schema_privilege(r.oid, n.oid, 'USAGE')  AS uso,
       has_schema_privilege(r.oid, n.oid, 'CREATE') AS crear
FROM pg_namespace n
CROSS JOIN pg_roles r
WHERE n.nspname !~ '^pg_'
  AND n.nspname <> 'information_schema'
  AND r.rolname IN ('auth_migrator', 'auth_api')
ORDER BY n.nspname, r.rolname;

-- V7a Tablas, vistas y tablas foráneas: privilegios efectivos de tabla
SELECT n.nspname,
       c.relname,
       c.relkind,
       r.rolname,
       has_table_privilege(r.oid, c.oid, 'SELECT')     AS sel,
       has_table_privilege(r.oid, c.oid, 'INSERT')     AS ins,
       has_table_privilege(r.oid, c.oid, 'UPDATE')     AS upd,
       has_table_privilege(r.oid, c.oid, 'DELETE')     AS del,
       has_table_privilege(r.oid, c.oid, 'TRUNCATE')   AS trn,
       has_table_privilege(r.oid, c.oid, 'REFERENCES') AS ref,
       has_table_privilege(r.oid, c.oid, 'TRIGGER')    AS trg
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN pg_roles r
WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
  AND n.nspname !~ '^pg_'
  AND n.nspname <> 'information_schema'
  AND r.rolname IN ('auth_migrator', 'auth_api')
ORDER BY n.nspname, c.relname, r.rolname;

-- V7b Secuencias (incluidas las de columnas IDENTITY)
SELECT n.nspname,
       c.relname,
       r.rolname,
       has_sequence_privilege(r.oid, c.oid, 'USAGE')  AS uso,
       has_sequence_privilege(r.oid, c.oid, 'SELECT') AS sel,
       has_sequence_privilege(r.oid, c.oid, 'UPDATE') AS upd
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN pg_roles r
WHERE c.relkind = 'S'
  AND n.nspname !~ '^pg_'
  AND n.nspname <> 'information_schema'
  AND r.rolname IN ('auth_migrator', 'auth_api')
ORDER BY n.nspname, c.relname, r.rolname;

-- V7c Privilegios por columna concedidos explícitamente
SELECT n.nspname, c.relname, a.attname, a.attacl
FROM pg_attribute a
JOIN pg_class c     ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE a.attacl IS NOT NULL
  AND a.attnum > 0
  AND NOT a.attisdropped
ORDER BY n.nspname, c.relname, a.attname;

-- V7d Inventario de propietarios de los objetos de usuario
SELECT n.nspname,
       c.relname,
       c.relkind,
       pg_get_userbyid(c.relowner) AS propietario,
       c.relacl
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname !~ '^pg_'
  AND n.nspname <> 'information_schema'
ORDER BY n.nspname, c.relkind, c.relname;

-- V8a Funciones y procedimientos en public y auth
SELECT p.oid::regprocedure         AS funcion,
       pg_get_userbyid(p.proowner) AS propietario,
       p.proacl,
       p.prosecdef                 AS security_definer
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname IN ('public', 'auth')
ORDER BY funcion;

-- V8b Extensiones
SELECT extname,
       extnamespace::regnamespace AS esquema,
       pg_get_userbyid(extowner)  AS propietario
FROM pg_extension
ORDER BY extname;

-- V8c Privilegios por defecto (se esperan cero filas)
SELECT pg_get_userbyid(defaclrole)   AS rol,
       defaclnamespace::regnamespace AS esquema,
       defaclobjtype,
       defaclacl
FROM pg_default_acl
ORDER BY rol;

ROLLBACK;

-- =============================================================================================
-- BLOQUE III. Base motor_scoring_it (idéntico al bloque II salvo la conexión)
-- =============================================================================================
\connect motor_scoring
BEGIN READ ONLY;
SELECT current_database() AS base, current_user AS usuario;

-- V6 Esquemas: propietario, ACL y privilegios efectivos
SELECT n.nspname,
       pg_get_userbyid(n.nspowner)                  AS propietario,
       n.nspacl,
       r.rolname,
       has_schema_privilege(r.oid, n.oid, 'USAGE')  AS uso,
       has_schema_privilege(r.oid, n.oid, 'CREATE') AS crear
FROM pg_namespace n
CROSS JOIN pg_roles r
WHERE n.nspname !~ '^pg_'
  AND n.nspname <> 'information_schema'
  AND r.rolname IN ('auth_migrator', 'auth_api')
ORDER BY n.nspname, r.rolname;

-- V7a Tablas, vistas y tablas foráneas: privilegios efectivos de tabla
SELECT n.nspname,
       c.relname,
       c.relkind,
       r.rolname,
       has_table_privilege(r.oid, c.oid, 'SELECT')     AS sel,
       has_table_privilege(r.oid, c.oid, 'INSERT')     AS ins,
       has_table_privilege(r.oid, c.oid, 'UPDATE')     AS upd,
       has_table_privilege(r.oid, c.oid, 'DELETE')     AS del,
       has_table_privilege(r.oid, c.oid, 'TRUNCATE')   AS trn,
       has_table_privilege(r.oid, c.oid, 'REFERENCES') AS ref,
       has_table_privilege(r.oid, c.oid, 'TRIGGER')    AS trg
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN pg_roles r
WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
  AND n.nspname !~ '^pg_'
  AND n.nspname <> 'information_schema'
  AND r.rolname IN ('auth_migrator', 'auth_api')
ORDER BY n.nspname, c.relname, r.rolname;

-- V7b Secuencias (incluidas las de columnas IDENTITY)
SELECT n.nspname,
       c.relname,
       r.rolname,
       has_sequence_privilege(r.oid, c.oid, 'USAGE')  AS uso,
       has_sequence_privilege(r.oid, c.oid, 'SELECT') AS sel,
       has_sequence_privilege(r.oid, c.oid, 'UPDATE') AS upd
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN pg_roles r
WHERE c.relkind = 'S'
  AND n.nspname !~ '^pg_'
  AND n.nspname <> 'information_schema'
  AND r.rolname IN ('auth_migrator', 'auth_api')
ORDER BY n.nspname, c.relname, r.rolname;

-- V7c Privilegios por columna concedidos explícitamente
SELECT n.nspname, c.relname, a.attname, a.attacl
FROM pg_attribute a
JOIN pg_class c     ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE a.attacl IS NOT NULL
  AND a.attnum > 0
  AND NOT a.attisdropped
ORDER BY n.nspname, c.relname, a.attname;

-- V7d Inventario de propietarios de los objetos de usuario
SELECT n.nspname,
       c.relname,
       c.relkind,
       pg_get_userbyid(c.relowner) AS propietario,
       c.relacl
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname !~ '^pg_'
  AND n.nspname <> 'information_schema'
ORDER BY n.nspname, c.relkind, c.relname;

-- V8a Funciones y procedimientos en public y auth
SELECT p.oid::regprocedure         AS funcion,
       pg_get_userbyid(p.proowner) AS propietario,
       p.proacl,
       p.prosecdef                 AS security_definer
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname IN ('public', 'auth')
ORDER BY funcion;

-- V8b Extensiones
SELECT extname,
       extnamespace::regnamespace AS esquema,
       pg_get_userbyid(extowner)  AS propietario
FROM pg_extension
ORDER BY extname;

-- V8c Privilegios por defecto (se esperan cero filas)
SELECT pg_get_userbyid(defaclrole)   AS rol,
       defaclnamespace::regnamespace AS esquema,
       defaclobjtype,
       defaclacl
FROM pg_default_acl
ORDER BY rol;

ROLLBACK;
