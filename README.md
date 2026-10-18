# auth-api

Aplicación Spring Boot independiente para la gestión de usuarios y roles (HU08) y la autenticación con
sesiones (HU09) del Motor de Scoring de Riesgo Crediticio. Emite los JWT que validan localmente
`scoring-api` y `evaluation-query-api` (HU10).

- Java 21, Spring Boot 4.1.1, Maven Wrapper (Maven 3.9.16).
- Monolito modular con Package by Feature y Ports & Adapters: `usuarios` (HU08) y `sesiones` (HU09),
  más `config` y `shared`.
- Persistencia en la base PostgreSQL compartida, **solo en el esquema `auth`** (Flyway propio,
  historial en `auth.flyway_schema_history`).

## Endpoints y permisos

| Método y ruta | Acceso | Respuestas |
|---|---|---|
| `POST /api/v1/auth/login` | Público | 200 `{accessToken, tokenType, expiresIn}` + cookie de renovación; 400; 401 `CREDENCIALES_INVALIDAS` |
| `POST /api/v1/auth/refresh` | Cookie de renovación + `Origin` permitido | 200 (cookie rotada); 401 `SESION_INVALIDA`; 403 `ORIGEN_NO_PERMITIDO` |
| `POST /api/v1/auth/logout` | Cookie de renovación + `Origin` permitido | 204 (cookie eliminada); 403 `ORIGEN_NO_PERMITIDO` |
| `POST /api/v1/usuarios` | `ADMINISTRADOR_RIESGO` | 201 `{idUsuario, correo, rol, fechaCreacion}`; 400; 401; 403; 409 `CORREO_DUPLICADO` |
| `GET /actuator/health` | Público (sin detalles) | 200 |
| Cualquier otra ruta | Denegada | 401 / 403 |

Los errores usan el formato común `{errorCode, message, details, traceId}` y todas las respuestas llevan
`X-Trace-Id`.

## Contrato JWT (común a las tres API)

- Algoritmo **RS256**, cabecera con `kid`. Se rechaza cualquier otro algoritmo y los tokens sin firma.
- Claims: `iss`, `aud`, `sub` (UUID del usuario), `role` (`ADMINISTRADOR_RIESGO` o `ANALISTA_CREDITO`),
  `iat`, `exp` (15 minutos) y `jti`. No incluye correo ni otros datos personales.
- Cada API valida localmente firma, algoritmo, emisor, audiencia propia y vigencia (60 s de tolerancia de
  reloj), sin llamar a `auth-api`. Un cambio de rol o una deshabilitación se refleja en la siguiente
  renovación, como máximo en 15 minutos (HU10 CA10).

## Contraseñas

- Mínimo 12 caracteres (HU08 CA04), sin máximo ni truncamiento.
- PBKDF2-HMAC-SHA256 con sal aleatoria de 16 bytes por contraseña, hash de 256 bits y 600 000
  iteraciones (calibrables con `AUTH_PBKDF2_ITERATIONS`, sin bajar de la recomendación vigente de OWASP).
- El hash se guarda con el prefijo del algoritmo (`{pbkdf2}...`) mediante `DelegatingPasswordEncoder`,
  para que un cambio futuro de algoritmo conviva con los hashes existentes.

## Sesiones

- Token de renovación aleatorio de 256 bits, entregado **solo** en la cookie `refresh_token`
  (`HttpOnly`, `Secure` salvo en el perfil `dev`, `SameSite` configurable, `Path=/api/v1/auth`).
  En la base solo se guarda su hash SHA-256.
- **Vigencia (HU09 CA06):** cada token de renovación vale como máximo 7 días desde su emisión. Una
  renovación válida emite otro token con sus propios 7 días, por lo que la sesión puede prolongarse
  mientras se renueve correctamente; no hay un límite absoluto desde el inicio de sesión.
- Cada renovación rota el token dentro de una transacción con la fila bloqueada. Un token ya rotado no
  genera otra sesión y su reutilización revoca toda la familia (HU09 CA08–CA10). La renovación vuelve a
  leer el usuario: si está deshabilitado se rechaza.
- **Renovaciones simultáneas:** si dos peticiones renuevan con el mismo token, la segunda se trata como
  reutilización y revoca la familia, de modo que ambas pestañas pierden la sesión. **El frontend debe
  coordinar las renovaciones** (una sola renovación en curso por navegador, compartiendo el resultado
  entre pestañas) para evitar peticiones simultáneas.
- CSRF: `refresh` y `logout` exigen un `Origin` incluido en `AUTH_ALLOWED_ORIGINS` (CORS por sí solo no
  protege frente a formularios de otros sitios).

## Variables de entorno

| Variable | Descripción |
|---|---|
| `AUTH_DB_URL` | `postgresql://host:puerto/base` (la misma base que las otras API) |
| `AUTH_DB_USERNAME`, `AUTH_DB_PASSWORD` | Usuario PostgreSQL de `auth-api` (propietario del esquema `auth`) |
| `AUTH_JWT_PRIVATE_KEY_LOCATION` | Ubicación de la clave privada PKCS#8, p. ej. `file:/secretos/jwt-privada.pem` |
| `AUTH_JWT_PUBLIC_KEY_LOCATION` | Ubicación de la clave pública X.509 |
| `AUTH_JWT_KEY_ID` | Identificador de la clave (`kid`), p. ej. `clave-2026-10` |
| `AUTH_JWT_ISSUER` | Emisor (por defecto `auth-api`) |
| `AUTH_JWT_AUDIENCES` | Audiencias (por defecto `auth-api,scoring-api,evaluation-query-api`) |
| `AUTH_ALLOWED_ORIGINS` | Orígenes del frontend, separados por coma |
| `AUTH_COOKIE_SECURE`, `AUTH_COOKIE_SAME_SITE` | Atributos de la cookie (por defecto `true` y `Strict`) |
| `AUTH_PBKDF2_ITERATIONS` | Iteraciones de PBKDF2-HMAC-SHA256 (por defecto 600 000) |
| `AUTH_API_PORT` | Puerto HTTP (por defecto 8081) |

## Claves RS256

Las claves **nunca** se guardan en el repositorio (`.gitignore` excluye `*.pem`). Generación:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt-privada.pem
openssl pkey -in jwt-privada.pem -pubout -out jwt-publica.pem
```

- La clave privada solo se instala en `auth-api`; `scoring-api` y `evaluation-query-api` reciben solo la
  pública.
- Rotación: generar un par nuevo con otro `AUTH_JWT_KEY_ID`, instalar la nueva clave pública en las API
  consumidoras, cambiar las claves de `auth-api` y retirar la clave pública anterior **después de 15
  minutos más la tolerancia de reloj**, para no rechazar tokens ya emitidos con ella.

## Primer administrador (HU08 CA13)

Procedimiento controlado, sin endpoint público ni credenciales por defecto. La contraseña se lee de un
archivo, no de argumentos ni variables, y no se registra en los logs. Si ya existe un administrador, el
procedimiento termina con error sin cambiar nada (la comprobación está serializada con un bloqueo de
PostgreSQL).

```powershell
$env:AUTH_BOOTSTRAP_ADMIN_CORREO = 'admin@ejemplo.com'
$env:AUTH_BOOTSTRAP_ADMIN_CONTRASENA_ARCHIVO = 'C:\secretos\admin.txt'   # archivo con permisos restringidos
.\mvnw.cmd spring-boot:run "-Dspring-boot.run.profiles=bootstrap-admin"
```

Después, eliminar el archivo de la contraseña.

### Restablecer la contraseña de un administrador existente

Procedimiento offline que actualiza solo el hash del administrador indicado y revoca sus sesiones de
renovación existentes. La cuenta debe existir y tener el rol `ADMINISTRADOR_RIESGO`; se aplica la
política actual de contraseña y el codificador PBKDF2 configurado para esta ejecución. Los JWT de
acceso ya emitidos pueden seguir vigentes hasta 15 minutos. La contraseña se lee de un archivo, no
de argumentos ni variables de entorno.

```powershell
$env:AUTH_ADMIN_RESET_CORREO = 'admin@ejemplo.com'
$env:AUTH_ADMIN_RESET_CONTRASENA_ARCHIVO = 'C:\secretos\nueva-contrasena.txt'   # permisos restringidos
.\mvnw.cmd spring-boot:run "-Dspring-boot.run.profiles=reset-admin"
```

Confirma el mensaje de éxito y elimina el archivo de contraseña después. Este procedimiento necesita
la misma configuración de base de datos y claves JWT que la aplicación. Si no se encuentra la cuenta
o no tiene rol de administrador, no se modifica ningún usuario. No cambies `hash_contrasena`
directamente en SQL.

## Ejecución y pruebas

```powershell
.\mvnw.cmd test                                   # pruebas unitarias y de controladores (H2, sin PostgreSQL)
.\mvnw.cmd spring-boot:run "-Dspring-boot.run.profiles=dev"
```

El esquema `auth` debe existir antes de arrancar contra PostgreSQL (Flyway no lo crea).
