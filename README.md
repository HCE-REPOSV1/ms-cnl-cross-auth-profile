# aa-pruebas-auth

> Auth Service generado por **Jarvis Platform** — 2/4/2026

Microservicio de autenticación JWT con integración al sistema MAC (Módulo de Autenticación Centralizado).

## Endpoints

| Método | Ruta | Protección | Descripción |
|--------|------|------------|-------------|
| POST | `/auth/login` | Público | Login — retorna JWT en cookie httpOnly y en body |
| POST | `/auth/validate` | Público | Valida un JWT — usado internamente por el API Gateway |
| GET  | `/auth/health` | Público | Health check |
| GET  | `/auth/me` | JWT (cookie) | Datos del usuario autenticado desde el JWT |
| GET  | `/auth/accesos` | JWT (cookie) | Árbol de módulos y permisos del usuario en MAC |
| POST | `/auth/logout` | JWT (cookie) | Cierra sesión en MAC y elimina la cookie |
| POST | `/auth/cambiar-contrasena` | JWT (cookie) | Cambio de contraseña vía MAC |

> Swagger disponible en `/api/docs` cuando `NODE_ENV != production`.

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

## Variables de entorno

| Variable | Requerida | Default | Descripción |
|----------|:---------:|---------|-------------|
| `PORT` | — | `10101` | Puerto HTTP |
| `NODE_ENV` | — | `development` | Entorno (`development` / `production`) |
| `COOKIE_SECURE` | — | `false` | `true` en producción (HTTPS obligatorio para la cookie) |
| `JWT_SECRET` | ✓ | — | Secreto de firma JWT (mínimo 32 chars) |
| `JWT_EXPIRES_IN` | — | `4h` | Duración del token (`4h`, `1d`, etc.) |
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

| Código MAC | Significado | HTTP devuelto |
|-----------|-------------|---------------|
| 0 | Éxito | 200 |
| 5 | Usuario no encontrado en AD | 401 |
| 6 | Usuario y/o contraseña incorrecta | 401 |
| 7 | Usuario bloqueado en AD | 403 |
| 8 | Éxito, requiere cambio de contraseña | 200 |
| 9 | Usuario deshabilitado en AD | 403 |
| 99 | Error interno MAC | 503 |

## Cómo ejecutar

### Local sin Docker

```bash
npm install
# Copiar .env.example a .env y completar EXTERNAL_AUTH_BASE_URL, JWT_SECRET, CRYPTO_KEY, CRYPTO_IV
npm run start:dev
```

Swagger disponible en `http://localhost:10402/api/docs` (solo fuera de producción).

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
