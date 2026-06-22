import { Controller, Post, Get, Body, Req, Res, UseGuards, UnauthorizedException } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth, ApiCookieAuth } from '@nestjs/swagger';
import { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { AuthUseCase } from '../../application/use-cases/Auth.use-case';
import { LoginDto, CambiarContrasenaDto } from '../../dto/login.dto';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';

const COOKIE_ACCESS  = 'access_token';
const COOKIE_REFRESH = 'refresh_token';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  private readonly cookieSecure:        boolean;
  private readonly cookieMaxAge:        number;
  private readonly refreshCookieMaxAge: number;

  constructor(
    private readonly authUseCase: AuthUseCase,
    private readonly config:      ConfigService,
  ) {
    this.cookieSecure        = config.get<string>('COOKIE_SECURE', 'false') === 'true';
    this.cookieMaxAge        = this.parseDuration(config.get<string>('JWT_EXPIRES_IN', '4h'));
    this.refreshCookieMaxAge = this.parseDuration(config.get<string>('JWT_REFRESH_EXPIRES_IN', '7d'));
  }

  private parseDuration(raw: string): number {
    const match = raw.match(/^(\d+)(s|m|h|d)$/);
    if (!match) return 4 * 3_600_000;
    const multipliers: Record<string, number> = { s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 };
    return Number(match[1]) * (multipliers[match[2]] ?? 3_600_000);
  }

  // refresh_token solo se setea cuando se emite uno nuevo (login / refresh) y nunca
  // viaja en el body de la respuesta, a diferencia de access_token (que sí, porque
  // algunos gateways internos lo necesitan como Bearer explícito).
  private setCookies(res: Response, accessToken: string, refreshToken?: string): void {
    res.cookie(COOKIE_ACCESS, accessToken, {
      httpOnly: true,
      secure:   this.cookieSecure,
      sameSite: 'lax' as const,
      path:     '/',
      maxAge:   this.cookieMaxAge,
    });
    if (refreshToken) {
      res.cookie(COOKIE_REFRESH, refreshToken, {
        httpOnly: true,
        secure:   this.cookieSecure,
        sameSite: 'lax' as const,
        path:     '/',
        maxAge:   this.refreshCookieMaxAge,
      });
    }
  }

  private clearCookies(res: Response): void {
    res.clearCookie(COOKIE_ACCESS,  { path: '/' });
    res.clearCookie(COOKIE_REFRESH, { path: '/' });
  }

  // ── Rutas públicas ─────────────────────────────────────────────

  @ApiOperation({ summary: 'Login — retorna JWT en cookie httpOnly y en body (refresh_token solo en cookie)' })
  @Post('login')
  async login(
    @Body() body: LoginDto,
    @Req()  req:  Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authUseCase.login(body.username, body.password, {
      ip:        (req.headers['x-forwarded-for'] as string) ?? req.ip,
      userAgent: req.headers['user-agent'],
      traceId:   req.headers['x-trace-id'] as string,
    });
    this.setCookies(res, result.data.access_token, result.data.refresh_token);
    const { refresh_token, ...data } = result.data;
    return { ...result, data };
  }

  @ApiOperation({ summary: 'Renueva access_token a partir de la cookie refresh_token (rota ambas)' })
  @ApiCookieAuth('refresh_token')
  @Post('refresh')
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const token = (req.cookies as any)?.[COOKIE_REFRESH] as string | undefined;
    if (!token) throw new UnauthorizedException('Refresh token requerido');

    try {
      const result = await this.authUseCase.refreshAccessToken(token);
      this.setCookies(res, result.data.access_token, result.data.refresh_token);
      const { refresh_token, ...data } = result.data;
      return { ...result, data };
    } catch (err) {
      // Refresh inválido/expirado: no queda sesión recuperable, limpiar ambas cookies.
      this.clearCookies(res);
      throw err;
    }
  }

  @ApiOperation({ summary: 'Valida un JWT — usado internamente por el API Gateway' })
  @Post('validate')
  validate(@Req() req: Request) {
    const cookieToken = (req.cookies as any)?.['access_token'] as string | undefined;
    const authHeader  = req.headers['authorization'] as string | undefined;
    const token = cookieToken ?? (authHeader?.replace('Bearer ', '').trim() ?? '');
    return this.authUseCase.validateToken(token);
  }

  @ApiOperation({ summary: 'Health check' })
  @Get('health')
  health() {
    return { status: 'OK', service: 'auth-pruebas-auth', timestamp: new Date().toISOString() };
  }

  // ── Rutas protegidas (requieren JWT válido) ────────────────────

  @ApiOperation({ summary: 'Datos del usuario autenticado (desde JWT, sin DB lookup)' })
  @ApiBearerAuth()
  @ApiCookieAuth('access_token')
  @UseGuards(JwtAuthGuard)
  @Get('me')
  getMe(@Req() req: Request) {
    return this.authUseCase.getMe(req['user']);
  }

  @ApiOperation({ summary: 'Árbol de accesos del usuario en MAC' })
  @ApiBearerAuth()
  @ApiCookieAuth('access_token')
  @UseGuards(JwtAuthGuard)
  @Get('accesos')
  async getAccesos(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    try {
      return await this.authUseCase.getAccesos(req['user']);
    } catch (err) {
      // AuthUseCase.getAccesos solo lanza UnauthorizedException por dos motivos: MAC
      // rechazó el token (MacTokenExpiredException) o el macCache no tiene la entrada
      // (ej. el proceso se reinició y perdió el Map en memoria). En ambos casos la
      // sesión ya no es recuperable sin un login nuevo — limpiar cookies.
      if (err instanceof UnauthorizedException) this.clearCookies(res);
      throw err;
    }
  }

  @ApiOperation({ summary: 'Cierra sesión en MAC y limpia la cookie' })
  @ApiBearerAuth()
  @ApiCookieAuth('access_token')
  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logout(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authUseCase.cerrarSesionMac(req['user'], {
      traceId: req.headers['x-trace-id'] as string,
    });
    this.clearCookies(res);
    return result;
  }

  @ApiOperation({ summary: 'Cambio de contraseña vía MAC' })
  @ApiBearerAuth()
  @ApiCookieAuth('access_token')
  @UseGuards(JwtAuthGuard)
  @Post('cambiar-contrasena')
  async cambiarContrasena(
    @Req()  req:  Request,
    @Body() body: CambiarContrasenaDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    try {
      return await this.authUseCase.cambiarContrasena(req['user'], body.actualContrasena, body.nuevaContrasena);
    } catch (err) {
      if (err instanceof UnauthorizedException) this.clearCookies(res);
      throw err;
    }
  }
}
