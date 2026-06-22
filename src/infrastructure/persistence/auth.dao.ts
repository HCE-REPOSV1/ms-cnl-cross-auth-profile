import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { UserInfo } from '../../domain/models/user-info.interface';

// Autenticación local contra variables de entorno.
// Reemplazar por ExternalAuthDao para delegar a un servicio externo (MAC, LDAP, etc.)
@Injectable()
export class AuthDao {
  constructor(private readonly config: ConfigService) {}

  async validateUser(username: string, password: string): Promise<UserInfo | null> {
    const validUser = this.config.get<string>('AUTH_USER',     'admin');
    const validPass = this.config.get<string>('AUTH_PASSWORD', '');
    if (username !== validUser || password !== validPass) return null;
    return {
      userId:   `local-${username}`,
      username,
      roles:    ['admin'],
      email:    '',
    };
  }
}
