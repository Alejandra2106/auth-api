-- Esquema "auth" (propiedad de auth-api). Flyway lo usa como esquema por defecto, por lo que las
-- tablas se crean sin prefijo. No referencia tablas de otros esquemas.

CREATE TABLE usuario (
    id_usuario UUID PRIMARY KEY,
    correo VARCHAR(254) NOT NULL,
    -- "{algoritmo}" + hash (PBKDF2-HMAC-SHA256 ocupa 104 caracteres); margen para futuros algoritmos
    hash_contrasena VARCHAR(255) NOT NULL,
    rol VARCHAR(30) NOT NULL,
    habilitado BOOLEAN NOT NULL DEFAULT TRUE,
    fecha_creacion TIMESTAMP WITH TIME ZONE NOT NULL,
    creado_por UUID NULL,
    origen_creacion VARCHAR(20) NOT NULL,
    -- HU08 CA03: unicidad sobre el correo normalizado, también bajo concurrencia
    CONSTRAINT uq_usuario_correo UNIQUE (correo),
    CONSTRAINT ck_usuario_correo_normalizado CHECK (correo = lower(btrim(correo))),
    -- HU08 CA06
    CONSTRAINT ck_usuario_rol CHECK (rol IN ('ADMINISTRADOR_RIESGO', 'ANALISTA_CREDITO')),
    CONSTRAINT ck_usuario_origen CHECK (origen_creacion IN ('INICIALIZACION', 'API')),
    -- HU08 CA11 y CA13: las altas por API registran su autor; la inicialización no tiene autor
    CONSTRAINT ck_usuario_autor CHECK (
        (origen_creacion = 'API' AND creado_por IS NOT NULL)
        OR (origen_creacion = 'INICIALIZACION' AND creado_por IS NULL)),
    CONSTRAINT fk_usuario_creado_por FOREIGN KEY (creado_por) REFERENCES usuario (id_usuario)
);

CREATE TABLE token_renovacion (
    id_token UUID PRIMARY KEY,
    id_usuario UUID NOT NULL,
    familia UUID NOT NULL,
    -- HU09 CA07: solo el hash SHA-256 (64 caracteres hexadecimales), nunca el token en claro
    hash_token VARCHAR(64) NOT NULL,
    emitido_en TIMESTAMP WITH TIME ZONE NOT NULL,
    expira_en TIMESTAMP WITH TIME ZONE NOT NULL,
    usado_en TIMESTAMP WITH TIME ZONE NULL,
    revocado_en TIMESTAMP WITH TIME ZONE NULL,
    CONSTRAINT uq_token_renovacion_hash UNIQUE (hash_token),
    CONSTRAINT ck_token_renovacion_hash CHECK (hash_token ~ '^[0-9a-f]{64}$'),
    -- HU09 CA06: vigencia máxima de siete días
    CONSTRAINT ck_token_renovacion_vigencia CHECK (
        expira_en > emitido_en AND expira_en <= emitido_en + INTERVAL '7 days'),
    CONSTRAINT fk_token_renovacion_usuario FOREIGN KEY (id_usuario) REFERENCES usuario (id_usuario)
);

CREATE INDEX ix_token_renovacion_familia ON token_renovacion (familia);
CREATE INDEX ix_token_renovacion_usuario ON token_renovacion (id_usuario);
