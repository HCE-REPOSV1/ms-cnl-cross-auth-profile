import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';

/**
 * Guard que verifica el JWT y adjunta el payload a req.user.
 * Acepta token desde cookie httpOnly o desde Authorization header.
 * Los métodos protegidos del controller reciben req.user directamente
 * sin necesidad de re-verificar el token en el service.
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private readonly jwt: JwtService) {}

  canActivate(ctx: ExecutionContext): boolean {
    const req         = ctx.switchToHttp().getRequest<Request>();
    const cookieToken = (req.cookies as any)?.['access_token'] as string | undefined;
    const authHeader  = req.headers['authorization'] as string | undefined;

    const token = cookieToken
      ?? (authHeader?.startsWith('Bearer ') ? authHeader.replace('Bearer ', '').trim() : null);

    if (!token) throw new UnauthorizedException('Token requerido');

    try {
      req['user'] = this.jwt.verify(token);
      return true;
    } catch {
      throw new UnauthorizedException('Token inválido o expirado');
    }
  }
}
