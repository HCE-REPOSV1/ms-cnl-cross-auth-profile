# ms-cnl-cross-auth-profile

> MS Canal — Auth Profile generado por **Jarvis Platform** — 10/6/2026

Microservicio de autenticación JWT con integración al sistema MAC (Módulo de Autenticación Centralizado).

## Endpoints

Todas las rutas reales van con el prefijo de versión del API Gateway: `/api/v1/auth/...`
(este servicio internamente solo declara el sub-path `/auth/...`, ver `app.setGlobalPrefix`/`enableVersioning` en `main.ts`).

| Método | Ruta | Protección | Descripción |
|--------|------|------------|-------------|
| POST | `/auth/login` | Público | Login contra MAC. Emite `access_token` (cookie httpOnly + body) y `refresh_token` (cookie httpOnly **only**, nunca en el body) |
| POST | `/auth/refresh` | Cookie `refresh_token` | Renueva `access_token` a partir de la cookie `refresh_token` y **rota ambos** tokens (emite uno nuevo de cada). No revalida contra MAC: si la sesión MAC ya expiró, `/auth/accesos` y `/auth/cambiar-contrasena` seguirán fallando hasta un login real |
| POST | `/auth/validate` | Público | Valida un JWT (`access_token`) — usado internamente por el API Gateway |
| GET  | `/auth/health` | Público | Health check |
| GET  | `/auth/me` | JWT (cookie o Bearer) | Datos del usuario autenticado, solo desde el payload del JWT (sin llamar a MAC) |
| GET  | `/auth/accesos` | JWT (cookie o Bearer) | Árbol de módulos y permisos del usuario en MAC. Si MAC indica que su token venció (sin refresh propio), limpia ambas cookies para forzar un login nuevo |
| POST | `/auth/logout` | JWT (cookie o Bearer) | Cierra sesión en MAC y elimina ambas cookies (`access_token` + `refresh_token`) |
| POST | `/auth/cambiar-contrasena` | JWT (cookie o Bearer) | Cambio de contraseña vía MAC. Mismo comportamiento que `/auth/accesos` si el token de MAC venció |

> Swagger disponible en `/api/docs` cuando `NODE_ENV != production`.

### Uso típico desde el browser (cookies)

```text
1. POST /api/v1/auth/login           → Set-Cookie: access_token (4h) + refresh_token (7d)
2. GET  /api/v1/auth/me / /accesos   → el browser manda las cookies automáticamente
3. Cuando access_token vence (4h):
   POST /api/v1/auth/refresh         → Set-Cookie: nuevos access_token + refresh_token
4. Si MAC rechaza el token (no tiene refresh propio):
   /auth/accesos devuelve 401 y limpia las cookies → el front debe redirigir a login
```

`access_token` también se devuelve en el body de `/auth/login` y `/auth/refresh` para los
casos donde un gateway interno lo necesita como `Authorization: Bearer <token>` explícito
(ver `gateway.service.ts` de los API Gateways). `refresh_token` **nunca** aparece en ningún
body de respuesta — solo existe como cookie httpOnly, para que JS del browser no pueda leerlo.

## JWT Payload

```json
{
  "sub":             "uuid-del-usuario",
  "username":        "JPEREZ",
  "roles":           ["12"],
  "email":           "juan@empresa.com",
  "sessionId":       "uuid-de-sesion",
  "idUsuario":       "123",
  "nombres":         "Juan",
  "apellidoPaterno": "Pérez",
  "apellidoMaterno": "García",
  "nombreCompleto":  "Juan Pérez García",
  "nombrePerfil":    "Médico Emergencia",
  "numeroDocumento": "12345678",
  "sucursales":      [{ "idSede": "1", "descripcion": "Sede Central" }],
  "iat": 1234567890,
  "exp": 1234571490
}
```

> **mac_token** nunca se incluye en el JWT — se almacena en caché server-side
> (`MacTokenCacheService`) con TTL equivalente a `JWT_EXPIRES_IN`.
> La clave de caché es `sessionId`.

`refresh_token` lleva el mismo payload que `access_token` más `"type": "refresh"`, y se firma
con un secret **distinto** (`JWT_REFRESH_SECRET`) y vida más larga (`JWT_REFRESH_EXPIRES_IN`,
default `7d`). Así un `access_token` filtrado no sirve para pedir un refresh, y viceversa —
la verificación con el secret equivocado falla antes incluso de mirar el campo `type`.

## Variables de entorno

| Variable | Requerida | Default | Descripción |
|----------|:---------:|---------|-------------|
| `PORT` | — | `10701` | Puerto HTTP |
| `NODE_ENV` | — | `development` | Entorno (`development` / `production`) |
| `COOKIE_SECURE` | — | `false` | `true` en producción (HTTPS obligatorio para la cookie) |
| `JWT_SECRET` | ✓ | — | Secreto de firma de `access_token` (mínimo 32 chars) |
| `JWT_EXPIRES_IN` | — | `4h` | Duración de `access_token` (`4h`, `1d`, etc.) |
| `JWT_REFRESH_SECRET` | ✓ | — | Secreto de firma de `refresh_token` — debe ser **distinto** de `JWT_SECRET` |
| `JWT_REFRESH_EXPIRES_IN` | — | `7d` | Duración de `refresh_token` |
| `EXTERNAL_AUTH_BASE_URL` | ✓ | — | URL base del servicio MAC sin barra final |
| `EXTERNAL_AUTH_SISTEMA` | — | `25` | Código de sistema registrado en MAC |
| `EXTERNAL_AUTH_TIMEOUT_MS` | — | `5000` | Timeout en ms para llamadas al MAC |
| `SSL_VERIFY` | — | `true` | `false` acepta certificados autofirmados del MAC |
| `CRYPTO_KEY` | ✓ | — | Clave AES-256-CBC — exactamente **32 caracteres** UTF-8 |
| `CRYPTO_IV` | ✓ | — | IV AES-256-CBC — exactamente **16 caracteres** UTF-8 |
| `KAFKA_BROKER` | — | `localhost:9092` | Broker(s) Kafka (coma-separados) |
| `KAFKA_TOPIC` | — | `platform.logs` | Topic donde se publican eventos de auditoría |

> `CRYPTO_KEY` y `CRYPTO_IV` deben coincidir exactamente con los valores
> configurados en el sistema HCE .NET (`Criptography.Encrypt()`).

## Integración con MAC

El servicio delega autenticación y accesos al sistema MAC:

| Operación | Endpoint MAC |
|-----------|-------------|
| Autenticar usuario | `POST /autenticar` |
| Obtener árbol de accesos | `POST /obtenerAccesos` |
| Cerrar sesión | `POST /cerrarSesion` |
| Cambiar contraseña | `POST /cambioContrasena` |

### Manejo de errores MAC

**Importante:** MAC señaliza éxito/error con su propio `codigo` dentro del body JSON, **no**
con el status HTTP — confirmado contra el servidor real (`desarrollo2.sanfelipe.com`): una
firma de token inválida devuelve HTTP 400 con `{"codigo":99,...}`, mientras que un código de
negocio "normal" (ej. credenciales inválidas en `/autenticar`) puede venir con HTTP
400/401/403 indistintamente. El status HTTP varía y no es confiable por sí solo — siempre
hay que mirar el `codigo` del body cuando MAC responde.

#### `POST /autenticar` (login)

| Código MAC | Significado | HTTP que devuelve este servicio |
|-----------|-------------|---------------|
| 0 | Éxito | 201 |
| 1/2/3 | Parámetro de configuración vacío (`codigoSistema`/usuario/contraseña) | 400 |
| 5 | Usuario no encontrado en AD | 401 |
| 6 | Usuario y/o contraseña incorrecta | 401 |
| 7 | Usuario bloqueado en AD | 403 |
| 8 | Éxito, requiere cambio de contraseña | 201 (`requirePasswordChange: true`) |
| 9 | Usuario deshabilitado en AD | 403 |
| 99 | Error interno MAC | 503 |

#### `POST /obtenerAccesos`, `/cerrarSesion`, `/cambioContrasena` (rutas con bearer del macToken cacheado)

| Código MAC | Significado | HTTP que devuelve este servicio |
|-----------|-------------|---------------|
| 0 | Éxito | 200/201 |
| 3 (solo `/obtenerAccesos`, documentado) | **Token de MAC caducado** | 401 — además borra el `macCache` y limpia ambas cookies (`access_token`+`refresh_token`); MAC no tiene refresh propio, así que esto siempre implica login nuevo |
| Cualquier otro código ≠ 0 | Error de negocio específico del endpoint (ver docs de MAC) | 400, con `{codigo, mensaje}` tal cual los devuelve MAC |
| (sin body / 404) | Endpoint no encontrado o mal configurado en este ambiente | 503 |

> `cambioContrasena` y `cerrarSesion` no tienen documentado un código específico de "token
> caducado" — solo `obtenerAccesos` lo declara explícitamente (código 3). Si en el futuro se
> confirma un código equivalente para esos dos, agregarlo al arreglo `expiredCodes` que recibe
> `ExternalAuthDao.mapMacBodyError()` para esa llamada.

## Cómo ejecutar

### Local sin Docker

```bash
npm install
# Copiar .env.example a .env y completar EXTERNAL_AUTH_BASE_URL, JWT_SECRET, CRYPTO_KEY, CRYPTO_IV
npm run start:dev
```

Swagger disponible en `http://localhost:10701/api/docs` (solo fuera de producción).

### Local con Docker

Usa `docker-compose.dev.yml`, que lee el `.env` local:

```bash
docker compose -f docker-compose.dev.yml build
docker compose -f docker-compose.dev.yml up -d

# O build + up en un solo comando:
docker compose -f docker-compose.dev.yml up -d --build

# Para bajar:
docker compose -f docker-compose.dev.yml down
```

### Producción (con Vault)

El `docker-compose.yml` lee los secretos directamente de Vault al arrancar. **No se necesita `.env`.**

**Requisito:** Vault corriendo (ver [HCE-vault-config](../HCE-vault-config/README.md)).

#### Paso 1 — Obtener el token

El archivo `HCE-vault-config/.env` tiene la línea:
```
TOKEN_AUTH_SERVICE=hvs.CAESIDsn...
```
Copia ese valor.

#### Paso 2 — Crear `.env.docker` con el token

Este archivo tiene **una sola línea** con el token de bootstrap. No contiene secretos de la app — esos vienen del vault.

**PowerShell (Windows):**
```powershell
"VAULT_TOKEN=hvs.CAESIDsn..." | Out-File -Encoding utf8 .env.docker
```

**Bash / Linux / Mac:**
```bash
echo "VAULT_TOKEN=hvs.CAESIDsn..." > .env.docker
```

> `.env.docker` está en `.gitignore` — nunca se commitea.  
> Si el init regenera los tokens, actualizar este archivo con el nuevo valor de `TOKEN_AUTH_SERVICE`.

#### Paso 3 — Levantar

```bash
docker compose down
docker compose build
docker compose up -d
```

Funciona igual en PowerShell, CMD y bash — sin exportar nada.

Al arrancar, `entrypoint.sh` se conecta al Vault con ese token, descarga todos los secretos
(`JWT_SECRET`, `CRYPTO_KEY`, `EXTERNAL_AUTH_BASE_URL`, etc.) y los inyecta como variables de
entorno en el contenedor. La aplicación no sabe que existe Vault.

Con GitHub Actions el token se pasa automáticamente desde GitHub Secrets (`VAULT_TOKEN`).

---

## Scripts disponibles

```bash
npm run start:dev   # desarrollo con hot-reload
npm run build       # compilar TypeScript
npm run start:prod  # ejecutar build
npm run test        # tests unitarios
npm run test:cov    # cobertura
```
