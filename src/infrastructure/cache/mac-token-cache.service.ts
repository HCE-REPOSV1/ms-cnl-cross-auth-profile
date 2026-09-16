import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { REDIS_CLIENT, RedisLike } from './redis-client.provider';

interface CacheEntry {
  macToken: string;
  perfil:   string;
  username: string;
}

const SESSION_PREFIX      = 'authprofile:session:';
const USER_SESSION_PREFIX = 'authprofile:user-session:';

/**
 * Almacena el mac_token externo en Redis, indexado por sessionId — server-side, el JWT
 * nunca carga el mac_token, solo viaja el sessionId para buscar aca (ver AuthUseCase).
 *
 * Migrado de un Map en memoria a Redis (2026-09-15) para escalar mas alla de una sola
 * instancia de este servicio: a medida que crece el nuevo sistema HCE va a haber multiples
 * logins concurrentes, potencialmente contra replicas distintas detras de un load balancer
 * -- un Map de proceso no puede detectar que un username ya tiene sesion activa si esa
 * sesion se creo en OTRA instancia.
 *
 * Ademas del cache sessionId -> {macToken, perfil} de siempre, mantiene un INDICE
 * SECUNDARIO username -> sessionId (HU01 "Multiples sesiones abiertas"): permite que
 * AuthUseCase.login() detecte una sesion activa existente del mismo usuario ANTES de
 * emitir un JWT nuevo, y ofrecer forzar el cierre de esa sesion anterior.
 */
@Injectable()
export class MacTokenCacheService {
  private readonly ttlSeconds: number;

  constructor(
    @Inject(REDIS_CLIENT) private readonly redis: RedisLike,
    cfg: ConfigService,
  ) {
    const raw = cfg.get<string>('JWT_EXPIRES_IN', '4h');
    const match = raw.match(/^(\d+)(s|m|h|d)$/);
    const multSeconds: Record<string, number> = { s: 1, m: 60, h: 3_600, d: 86_400 };
    this.ttlSeconds = match ? Number(match[1]) * (multSeconds[match[2]] ?? 3_600) : 4 * 3_600;
  }

  private userKey(username: string): string {
    return USER_SESSION_PREFIX + username.toUpperCase();
  }

  /**
   * Escribe la entrada de sesion Y el indice username->sessionId con el mismo TTL, SIN
   * chequear si ya habia una sesion activa — usar solo en el camino "forzado" (forceLogout,
   * despues de closeUserSession) o cuando el caller ya garantizo por otro medio que no hay
   * carrera posible. Para el camino normal de login usar trySetActiveSession().
   */
  async set(sessionId: string, macToken: string, perfil: string, username: string): Promise<void> {
    const entry: CacheEntry = { macToken, perfil, username };
    await this.redis.set(SESSION_PREFIX + sessionId, JSON.stringify(entry), 'EX', this.ttlSeconds);
    await this.redis.set(this.userKey(username), sessionId, 'EX', this.ttlSeconds);
  }

  /**
   * Camino NO forzado de login (HU01 "Multiples sesiones abiertas"): reserva el indice
   * username->sessionId de forma ATOMICA (SET ... NX) antes de escribir la entrada de
   * sesion, para cerrar la ventana de carrera entre getActiveSessionForUser() y set()
   * cuando dos requests de login del mismo usuario llegan casi simultaneas (doble clic,
   * retry de red) — sin esto, ambas podrian pasar el chequeo previo y crear dos sesiones
   * "no forzadas" a la vez, rompiendo la garantia que promete la HU.
   *
   * Devuelve false sin escribir nada si el indice ya existia (sesion activa detectada) —
   * el caller debe tratarlo igual que si getActiveSessionForUser() hubiera encontrado una.
   *
   * Orden deliberado (user-session con NX primero, session:{sessionId} despues): si el
   * proceso crashea entre ambas escrituras, el fallo cae del lado PERMISIVO (sessionId
   * sin indice — se autolimpia solo por TTL) en vez del lado que rompe el invariante de
   * sesion unica.
   */
  async trySetActiveSession(sessionId: string, macToken: string, perfil: string, username: string): Promise<boolean> {
    const reserved = await this.redis.set(this.userKey(username), sessionId, 'EX', this.ttlSeconds, 'NX');
    if (reserved !== 'OK') return false;

    const entry: CacheEntry = { macToken, perfil, username };
    await this.redis.set(SESSION_PREFIX + sessionId, JSON.stringify(entry), 'EX', this.ttlSeconds);
    return true;
  }

  async get(sessionId: string): Promise<{ macToken: string; perfil: string } | null> {
    const raw = await this.redis.get(SESSION_PREFIX + sessionId);
    if (!raw) return null;
    const entry: CacheEntry = JSON.parse(raw);
    return { macToken: entry.macToken, perfil: entry.perfil };
  }

  /** Elimina la entrada de sesion y, si existe, su entrada en el indice username->sessionId. */
  async delete(sessionId: string): Promise<void> {
    const raw = await this.redis.get(SESSION_PREFIX + sessionId);
    await this.redis.del(SESSION_PREFIX + sessionId);
    if (raw) {
      const entry: CacheEntry = JSON.parse(raw);
      await this.redis.del(this.userKey(entry.username));
    }
  }

  /**
   * Extiende el TTL de la entrada de sesion y de su indice username->sessionId — llamado
   * desde AuthUseCase.refreshAccessToken() en CADA /auth/refresh exitoso.
   *
   * Laguna que esto cierra: el TTL se fijaba UNA sola vez en el login (set/
   * trySetActiveSession) y nunca se tocaba de nuevo — una sesion mantenida viva a punta de
   * refresh (hasta 7d via JWT_REFRESH_EXPIRES_IN) perdia su entrada en macCache a las
   * JWT_EXPIRES_IN horas igual (ej. 4h), sin importar que el usuario siguiera activo. Efecto
   * doble: getAccesos/cambiarContrasena empezaban a fallar a mitad de sesion, Y el indice de
   * sesion unica (HU01) desaparecia, permitiendo un segundo login sin el 409 aunque la
   * sesion original siguiera "viva" del lado del JWT.
   *
   * No-op silencioso si la entrada ya no existe (sesion MAC ya vencida/limpiada por otro
   * camino, ej. delete() tras MacTokenExpiredException) — el refresh del JWT sigue
   * funcionando iguel, pero accesos/cambiarContrasena seguiran fallando hasta un login
   * nuevo, exactamente como ya esta documentado para ese caso.
   */
  async touch(sessionId: string): Promise<void> {
    const raw = await this.redis.get(SESSION_PREFIX + sessionId);
    if (!raw) return;
    const entry: CacheEntry = JSON.parse(raw);
    await this.redis.set(SESSION_PREFIX + sessionId, raw, 'EX', this.ttlSeconds);
    await this.redis.set(this.userKey(entry.username), sessionId, 'EX', this.ttlSeconds);
  }

  /**
   * HU01 "Multiples sesiones abiertas": ¿este username ya tiene una sesion activa? Se
   * llama ANTES de crear una sesion nueva en AuthUseCase.login().
   */
  async getActiveSessionForUser(username: string): Promise<string | null> {
    return this.redis.get(this.userKey(username));
  }

  /**
   * Cierra la sesion activa previa de un username (flujo "Cerrar Sesión" de HU01, cuando
   * el usuario confirma que quiere desalojar su otra sesion). Devuelve el macToken/
   * sessionId de la sesion cerrada para que el caller pueda invalidarla tambien contra MAC
   * (POST /cerrarSesion) — null si no habia ninguna sesion activa para ese username.
   */
  async closeUserSession(username: string): Promise<{ macToken: string; sessionId: string } | null> {
    const sessionId = await this.redis.get(this.userKey(username));
    if (!sessionId) return null;

    const raw = await this.redis.get(SESSION_PREFIX + sessionId);
    await this.redis.del(SESSION_PREFIX + sessionId);
    await this.redis.del(this.userKey(username));

    return { macToken: raw ? (JSON.parse(raw) as CacheEntry).macToken : '', sessionId };
  }
}
