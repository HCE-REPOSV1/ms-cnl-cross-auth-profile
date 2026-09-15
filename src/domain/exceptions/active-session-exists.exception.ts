import { ConflictException } from '@nestjs/common';

/**
 * HU01 "Multiples sesiones abiertas": el username ya tiene una sesion activa (detectada
 * via MacTokenCacheService.trySetActiveSession/getActiveSessionForUser). El front debe
 * mostrar el mensaje y ofrecer "Cerrar Sesión" (reintentar POST /auth/login con
 * forceLogout: true) o "Cancelar".
 */
export class ActiveSessionExistsException extends ConflictException {
  constructor() {
    super({
      codigo: 'SESION_ACTIVA',
      mensaje:
        'Ya existe una sesión abierta con este usuario. Si desea iniciar sesión aquí, ' +
        'asegúrese de haber cerrado correctamente su sesión en cualquier otra ventana o dispositivo.',
    });
  }
}
