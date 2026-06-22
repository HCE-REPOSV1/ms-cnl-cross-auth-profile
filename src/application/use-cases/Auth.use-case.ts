import { Injectable, UnauthorizedException, HttpException, Inject } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { randomUUID } from 'crypto';
import { AUTH_DAO, IAuthDao, MAC_DAO, IMacAuthDao } from '../../domain/repositories/auth-dao.interface';
import { MacTokenCacheService } from '../../infrastructure/cache/mac-token-cache.service';
import { KafkaLoggerService } from '../../logger/kafka-logger.service';
import { MacTokenExpiredException } from '../../domain/exceptions/mac-token-expired.exception';

@Injectable()
export class AuthUseCase {
  constructor(
    private readonly jwt:         JwtService,
    private readonly config:      ConfigService,
    @Inject(AUTH_DAO) private readonly authDao:   IAuthDao,
    @Inject(MAC_DAO)  private readonly macDao:    IMacAuthDao,
    private readonly macCache:    MacTokenCacheService,
    private readonly kafkaLogger: KafkaLoggerService,
  ) {}

  async login(username: string, password: string, context?: { ip?: string; userAgent?: string; traceId?: string }) {
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
        this.macCache.set(sessionId, user.macToken, user.perfil ?? '');
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
        const status   = err.getStatus();
        const blocked   = status === 403;
        const reason    = (err.getResponse() as any)?.mensaje ?? err.message;
        await this.kafkaLogger.log({
          eventType: blocked ? 'LOGIN_BLOCKED' : 'LOGIN_FAILED', level: 'WARN', traceId: attemptTraceId,
          username, action: 'LOGIN', outcome: blocked ? 'BLOCKED' : 'FAILED', payload: { reason },
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
    const cached = this.macCache.get(user.sessionId);
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
      if (err instanceof MacTokenExpiredException) this.macCache.delete(user.sessionId);
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
   * No revalida contra MAC ni extiende el macCache — si la sesión MAC ya expiró,
   * getAccesos/cambiarContrasena seguirán fallando hasta un login nuevo (ver diseño en memoria).
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

  /** Recibe el payload ya verificado por JwtAuthGuard */
  async cerrarSesionMac(user: any, context?: { traceId?: string }) {
    const cached = this.macCache.get(user.sessionId);
    if (cached) {
      try {
        await this.macDao.cerrarSesion(cached.macToken, user.username);
        this.macCache.delete(user.sessionId);
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
    const cached = this.macCache.get(user.sessionId);
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
      if (err instanceof MacTokenExpiredException) this.macCache.delete(user.sessionId);
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
