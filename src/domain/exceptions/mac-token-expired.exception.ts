import { UnauthorizedException } from '@nestjs/common';

/**
 * MAC no emite refresh_token propio — cuando su token bearer vence, la sesión
 * MAC es irrecuperable sin un login nuevo. Se distingue de UnauthorizedException
 * genérico para que AuthController pueda limpiar las cookies del usuario.
 */
export class MacTokenExpiredException extends UnauthorizedException {
  constructor() {
    super('Sesión MAC expirada, vuelve a iniciar sesión');
  }
}
