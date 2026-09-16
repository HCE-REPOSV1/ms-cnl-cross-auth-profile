import { Injectable, UnauthorizedException, HttpException, Inject, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { randomUUID } from 'crypto';
import { AUTH_DAO, IAuthDao, MAC_DAO, IMacAuthDao } from '../../domain/repositories/auth-dao.interface';
import { MacTokenCacheService } from '../../infrastructure/cache/mac-token-cache.service';
import { KafkaLoggerService } from '../../logger/kafka-logger.service';
import { MacTokenExpiredException } from '../../domain/exceptions/mac-token-expired.exception';
import { ActiveSessionExistsException } from '../../domain/exceptions/active-session-exists.exception';

@Injectable()
export class AuthUseCase {
  private readonly logger = new Logger(AuthUseCase.name);

  constructor(
    private readonly jwt:         JwtService,
    private readonly config:      ConfigService,
    @Inject(AUTH_DAO) private readonly authDao:   IAuthDao,
    @Inject(MAC_DAO)  private readonly macDao:    IMacAuthDao,
    private readonly macCache:    MacTokenCacheService,
    private readonly kafkaLogger: KafkaLoggerService,
  ) {}

  async login(
    username: string,
    password: string,
    context?: { ip?: string; userAgent?: string; traceId?: string },
    forceLogout = false,
  ) {
    const attemptTraceId = context?.traceId ?? randomUUID();

    try {
      const user = await this.authDao.validateUser(username, password);
      if (!user) {
        await this.kafkaLogger.log({
          eventType: 'LOGIN_FAILED', level: 'WARN', traceId: attemptTraceId,
          username, action: 'LOGIN', outcome: 'FAILED', payload: { reason: 'INVALID_CREDENTIALS' },
          ipAddress: context?.ip, userAgent: context?.userAgent,
        });
        throw new UnauthorizedException('Credenciales inválidas');
      }

      const sessionId            = randomUUID();
      const requirePasswordChange = user.requirePasswordChange ?? false;

      // mac_token almacenado en caché server-side — nunca en el JWT
      if (user.macToken) {
        await this.enforceSingleSession(sessionId, user, forceLogout, attemptTraceId, context);
      }

      const payload = {
        sub:             user.userId,
        username:        user.username,
        roles:           user.roles,
        email:           user.email,
        sessionId,
        idUsuario:       user.idUsuario       ?? '',
        nombres:         user.nombres         ?? '',
        apellidoPaterno: user.apellidoPaterno ?? '',
        apellidoMaterno: user.apellidoMaterno ?? '',
        nombreCompleto:  user.nombreCompleto  ?? '',
        nombrePerfil:    user.nombrePerfil    ?? '',
        numeroDocumento: user.numeroDocumento ?? '',
        sucursales:      user.sucursales      ?? [],
      };

      const accessToken  = this.jwt.sign(payload);
      const refreshToken = this.signRefreshToken(payload);

      await this.kafkaLogger.log({
        eventType: 'LOGIN_SUCCESS', level: 'INFO', traceId: attemptTraceId,
        userId: user.userId, username: user.username, sessionId,
        action: 'LOGIN', outcome: 'SUCCESS',
        ipAddress: context?.ip, userAgent: context?.userAgent,
      });

      return {
        success: true,
        message: requirePasswordChange ? 'Login exitoso, se requiere cambio de contraseña' : 'Login exitoso',
        data: {
          user:                 { userId: user.userId, username: user.username, roles: user.roles, email: user.email, sucursales: user.sucursales ?? [] },
          access_token:         accessToken,
          // refresh_token solo viaja como cookie httpOnly (ver AuthController.setCookies) —
          // se incluye aquí para que el controller la lea, pero nunca debe llegar al body de la respuesta.
          refresh_token:        refreshToken,
          expires_in:           this.config.get<string>('JWT_EXPIRES_IN', '4h'),
          token_type:           'Bearer',
          session_id:           sessionId,
          requirePasswordChange,
        },
      };
    } catch (err) {
      // ExternalAuthDao.mapUser() lanza HttpException directamente para casos de
      // negocio (usuario no existe, credenciales inválidas, bloqueado, deshabilitado)
      // en vez de retornar null — por eso el logging debe hacerse aquí, no en el
      // branch `if (!user)` de arriba (que en la práctica nunca se alcanza).
      if (err instanceof HttpException) {
        const status         = err.getStatus();
        const blocked        = status === 403;
        const activeSession  = err instanceof ActiveSessionExistsException;
        const reason         = (err.getResponse() as any)?.mensaje ?? err.message;
        await this.kafkaLogger.log({
          eventType: activeSession ? 'LOGIN_BLOCKED_ACTIVE_SESSION' : blocked ? 'LOGIN_BLOCKED' : 'LOGIN_FAILED',
          level: 'WARN', traceId: attemptTraceId,
          username, action: 'LOGIN', outcome: activeSession ? 'ACTIVE_SESSION' : blocked ? 'BLOCKED' : 'FAILED',
          payload: { reason },
          ipAddress: context?.ip, userAgent: context?.userAgent,
        });
        throw err;
      }
      await this.kafkaLogger.log({
        eventType: 'LOGIN_FAILED', level: 'ERROR', traceId: attemptTraceId,
        username, action: 'LOGIN', outcome: 'ERROR', payload: { reason: (err as any)?.message },
        ipAddress: context?.ip, userAgent: context?.userAgent,
      });
      throw err;
    }
  }

  /**
   * HU01 "Multiples sesiones abiertas". Dos caminos:
   *
   * - forceLogout=false (default, primer intento de login): reserva el indice
   *   username->sessionId de forma atomica (trySetActiveSession, SET NX) — si ya habia una
   *   sesion activa, lanza ActiveSessionExistsException (409) SIN tocar nada mas. El front
   *   muestra el mensaje de la HU con las opciones "Cerrar Sesión"/"Cancelar".
   * - forceLogout=true (el usuario ya confirmo "Cerrar Sesión"): cierra la sesion activa
   *   anterior — best-effort contra MAC (POST /cerrarSesion con el mac_token viejo) y en el
   *   cache local — y recien ahi escribe la sesion nueva sin chequeo (ya no hay carrera que
   *   proteger, el usuario pidio explicitamente desalojar).
   *
   * Fallos de Redis (cache no disponible) NO tumban el login — se loguean como WARN via
   * Kafka (visibles en auditoria) y se deja pasar sin chequeo de sesion unica, a proposito:
   * un problema de infraestructura no debe convertirse en un login bloqueado, pero tampoco
   * debe ser un bypass silencioso de una regla de negocio explicita del cliente.
   */
  private async enforceSingleSession(
    sessionId: string,
    user: { username: string; macToken?: string; perfil?: string },
    forceLogout: boolean,
    traceId: string,
    context?: { ip?: string; userAgent?: string },
  ): Promise<void> {
    if (!user.macToken) return;

    try {
      if (forceLogout) {
        const previous = await this.macCache.closeUserSession(user.username);
        if (previous?.macToken) {
          try {
            await this.macDao.cerrarSesion(previous.macToken, user.username);
          } catch (macErr: any) {
            // Best-effort: si MAC ya invalido ese token por su cuenta (ej. expiro), no
            // debe bloquear el login nuevo — solo se deja rastro en auditoria.
            await this.kafkaLogger.log({
              eventType: 'LOGIN_FORCE_CLOSE_MAC_ERROR', level: 'WARN', traceId,
              username: user.username, action: 'LOGIN', outcome: 'MAC_ERROR',
              payload: { reason: macErr?.message },
              ipAddress: context?.ip, userAgent: context?.userAgent,
            });
          }
        }
        await this.macCache.set(sessionId, user.macToken, user.perfil ?? '', user.username);
        return;
      }

      const reserved = await this.macCache.trySetActiveSession(sessionId, user.macToken, user.perfil ?? '', user.username);
      if (!reserved) throw new ActiveSessionExistsException();
    } catch (err) {
      if (err instanceof ActiveSessionExistsException) throw err;
      // Fallo real de Redis (conexion, timeout, etc.) — degradar con gracia, no tumbar el login.
      this.logger.warn(`MacTokenCacheService no disponible durante login de '${user.username}' — se omite el chequeo de sesión única: ${(err as any)?.message}`);
      await this.kafkaLogger.log({
        eventType: 'LOGIN_SESSION_CACHE_UNAVAILABLE', level: 'WARN', traceId,
        username: user.username, action: 'LOGIN', outcome: 'DEGRADED',
        payload: { reason: (err as any)?.message },
        ipAddress: context?.ip, userAgent: context?.userAgent,
      });
    }
  }

  /** Recibe el payload ya verificado por JwtAuthGuard */
  getMe(user: any) {
    return {
      success: true,
      data: {
        userId:          user.sub,
        username:        user.username,
        email:           user.email,
        roles:           user.roles,
        idUsuario:       user.idUsuario,
        nombres:         user.nombres,
        apellidoPaterno: user.apellidoPaterno,
        apellidoMaterno: user.apellidoMaterno,
        nombreCompleto:  user.nombreCompleto,
        nombrePerfil:    user.nombrePerfil,
        numeroDocumento: user.numeroDocumento,
        sucursales:      user.sucursales ?? [],
        sessionId:       user.sessionId,
      },
    };
  }

  /** Recibe el payload ya verificado por JwtAuthGuard */
  async getAccesos(user: any) {
    const cached = await this.macCache.get(user.sessionId);
    if (!cached) throw new UnauthorizedException('Sesión MAC no encontrada o expirada');
    try {
      const raw      = await this.macDao.getAccesos(cached.macToken, cached.perfil);
      const opciones = raw?.data?.opciones ?? [];
      return {
        success: true,
        data: {
          opciones,
          permisos: this.flattenOpciones(opciones),
        },
      };
    } catch (err) {
      if (err instanceof MacTokenExpiredException) await this.macCache.delete(user.sessionId);
      throw err;
    }
  }

  /**
   * Firma un JWT de refresh, vida más larga y secret propio (JWT_REFRESH_SECRET)
   * — así un access_token filtrado no sirve para pedir refresh, y viceversa.
   */
  private signRefreshToken(payload: Record<string, any>): string {
    return this.jwt.sign(
      { ...payload, type: 'refresh' },
      {
        secret:    this.config.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: this.config.get<string>('JWT_REFRESH_EXPIRES_IN', '7d') as any,
      },
    );
  }

  /**
   * Reemite access_token + refresh_token (rotación) a partir de un refresh_token válido.
   *
   * Gate de sesión (cierra la laguna "TTL de Redis fijo desde el login, nunca se extendía
   * con refresh"): la vigencia de la sesión HCE queda atada a que la entrada en macCache
   * siga viva — esa entrada es la ÚNICA fuente de verdad de "sesión HCE activa" (a MAC no
   * le importa si hay N sesiones simultáneas del mismo usuario, la exclusividad de HU01 es
   * una garantía que vive enteramente de este lado). Si ya se detectó que el mac_token
   * venció (getAccesos → MacTokenExpiredException → macCache.delete()) o el TTL natural
   * expiró sin que nadie lo extendiera, el refresh se RECHAZA — fuerza un login nuevo en
   * vez de permitir una sesión HCE indefinidamente renovable sobre una sesión MAC ya
   * muerta. Si la entrada SÍ existe, se extiende su TTL (touch) junto con el JWT: una
   * sesión en uso activo se mantiene viva completa mientras se la siga refrescando.
   */
  async refreshAccessToken(refreshToken: string) {
    let decoded: any;
    try {
      decoded = this.jwt.verify(refreshToken, { secret: this.config.get<string>('JWT_REFRESH_SECRET') });
    } catch {
      throw new UnauthorizedException('Refresh token inválido o expirado');
    }
    if (decoded?.type !== 'refresh') throw new UnauthorizedException('Token no es de tipo refresh');

    const { type, iat, exp, ...payload } = decoded;

    if (payload.sessionId) {
      await this.enforceSessionStillAlive(payload.sessionId);
    }

    const accessToken     = this.jwt.sign(payload);
    const newRefreshToken = this.signRefreshToken(payload);

    return {
      success: true,
      message: 'Token renovado',
      data: {
        access_token:  accessToken,
        refresh_token: newRefreshToken,
        expires_in:    this.config.get<string>('JWT_EXPIRES_IN', '4h'),
        token_type:    'Bearer',
        session_id:    payload.sessionId,
      },
    };
  }

  /**
   * Gate de refresh (ver doc de refreshAccessToken). Un fallo de INFRAESTRUCTURA de Redis
   * (no "la key no existe", sino que Redis no responde) se degrada con gracia igual que en
   * login — no tumba el refresh por un problema ajeno a la sesión del usuario.
   */
  private async enforceSessionStillAlive(sessionId: string): Promise<void> {
    let cached: { macToken: string; perfil: string } | null;
    try {
      cached = await this.macCache.get(sessionId);
    } catch (err: any) {
      this.logger.warn(`MacTokenCacheService no disponible durante refresh de sessionId='${sessionId}' — se omite el chequeo de sesión, se permite el refresh igual: ${err?.message}`);
      return;
    }
    if (!cached) throw new UnauthorizedException('Sesión expirada, vuelve a iniciar sesión');

    try {
      await this.macCache.touch(sessionId);
    } catch (err: any) {
      this.logger.warn(`No se pudo extender el TTL de macCache para sessionId='${sessionId}': ${err?.message}`);
    }
  }

  /** Recibe el payload ya verificado por JwtAuthGuard */
  async cerrarSesionMac(user: any, context?: { traceId?: string }) {
    const cached = await this.macCache.get(user.sessionId);
    if (cached) {
      try {
        await this.macDao.cerrarSesion(cached.macToken, user.username);
        await this.macCache.delete(user.sessionId);
      } catch (macErr: any) {
        await this.kafkaLogger.log({
          eventType: 'LOGOUT', level: 'WARN', traceId: context?.traceId,
          userId: user.sub, username: user.username, sessionId: user.sessionId,
          action: 'LOGOUT', outcome: 'MAC_ERROR', payload: { reason: macErr?.message },
        });
      }
    }

    await this.kafkaLogger.log({
      eventType: 'LOGOUT', level: 'INFO', traceId: context?.traceId,
      userId: user.sub, username: user.username, sessionId: user.sessionId,
      action: 'LOGOUT', outcome: 'SUCCESS',
    });

    return { success: true, message: 'Sesión cerrada correctamente' };
  }

  /** Recibe el payload ya verificado por JwtAuthGuard */
  async cambiarContrasena(user: any, actualContrasena: string, nuevaContrasena: string) {
    const cached = await this.macCache.get(user.sessionId);
    if (!cached) throw new UnauthorizedException('Sesión MAC no encontrada o expirada');
    try {
      const result = await this.macDao.cambiarContrasena(cached.macToken, user.username, actualContrasena, nuevaContrasena);
      await this.kafkaLogger.log({
        eventType: 'PASSWORD_CHANGE', level: 'INFO',
        userId: user.sub, username: user.username, sessionId: user.sessionId,
        action: 'PASSWORD_CHANGE', outcome: 'SUCCESS',
      });
      return result;
    } catch (err) {
      if (err instanceof MacTokenExpiredException) await this.macCache.delete(user.sessionId);
      throw err;
    }
  }

  async validateToken(token: string) {
    try {
      const d = this.jwt.verify(token) as any;
      return {
        success: true, message: 'Token is valid',
        data: { userId: d.sub, username: d.username, email: d.email, roles: d.roles, sessionId: d.sessionId, exp: d.exp, iat: d.iat },
      };
    } catch {
      throw new UnauthorizedException('Token inválido o expirado');
    }
  }

  /**
   * Equivalente a LlenarOpcionesRecursivo() de UtilSeguridad.vb (.NET)
   */
  private flattenOpciones(opciones: any[]): Array<{ codigo: string; titulo: string; indicador: string }> {
    const result: Array<{ codigo: string; titulo: string; indicador: string }> = [];
    for (const op of opciones) {
      result.push({
        codigo:    String(op.codigo    ?? '').trim(),
        titulo:    String(op.titulo    ?? '').trim(),
        indicador: String(op.indicador ?? '').trim(),
      });
      if (op.opciones?.length) result.push(...this.flattenOpciones(op.opciones));
    }
    return result;
  }
}
