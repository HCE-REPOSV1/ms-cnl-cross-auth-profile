import { UnauthorizedException }  from '@nestjs/common';
import { JwtService }             from '@nestjs/jwt';
import { ConfigService }          from '@nestjs/config';
import { AuthUseCase }            from './Auth.use-case';
import { MacTokenCacheService }   from '../../infrastructure/cache/mac-token-cache.service';
import { IAuthDao, IMacAuthDao }  from '../../domain/repositories/auth-dao.interface';
import { KafkaLoggerService }     from '../../logger/kafka-logger.service';
import { ActiveSessionExistsException } from '../../domain/exceptions/active-session-exists.exception';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeCfg(overrides: Record<string, string> = {}): ConfigService {
  const map: Record<string, string> = {
    JWT_EXPIRES_IN: '4h',
    JWT_SECRET:     'test-secret-32-chars-padding-xx',
    ...overrides,
  };
  return { get: (k: string, d?: string) => map[k] ?? d } as any;
}

function makeJwt(): jest.Mocked<JwtService> {
  return { sign: jest.fn().mockReturnValue('signed-token'), verify: jest.fn() } as any;
}

function makeAuthDao(userResult: any = null): jest.Mocked<IAuthDao> {
  return { validateUser: jest.fn().mockResolvedValue(userResult) } as any;
}

function makeMacDao(accesosResult: any = { data: { opciones: [] } }): jest.Mocked<IMacAuthDao> {
  return {
    getAccesos:       jest.fn().mockResolvedValue(accesosResult),
    cerrarSesion:     jest.fn().mockResolvedValue({}),
    cambiarContrasena: jest.fn().mockResolvedValue({}),
  } as any;
}

/** trySetActiveSession resuelve true por defecto (sin sesion previa) — mismo default que
 * un usuario que loguea por primera vez, para no tener que setearlo en cada test existente. */
function makeCache(): jest.Mocked<MacTokenCacheService> {
  return {
    set:                     jest.fn().mockResolvedValue(undefined),
    get:                     jest.fn().mockResolvedValue(null),
    delete:                  jest.fn().mockResolvedValue(undefined),
    trySetActiveSession:     jest.fn().mockResolvedValue(true),
    getActiveSessionForUser: jest.fn().mockResolvedValue(null),
    closeUserSession:        jest.fn().mockResolvedValue(null),
  } as any;
}

function makeKafka(): jest.Mocked<KafkaLoggerService> {
  return { log: jest.fn().mockResolvedValue(undefined) } as any;
}

function makeService(overrides: {
  authDao?: jest.Mocked<IAuthDao>;
  macDao?:  jest.Mocked<IMacAuthDao>;
  cache?:   jest.Mocked<MacTokenCacheService>;
  jwt?:     jest.Mocked<JwtService>;
  cfg?:     ConfigService;
} = {}) {
  const cfg     = overrides.cfg     ?? makeCfg();
  const jwt     = overrides.jwt     ?? makeJwt();
  const authDao = overrides.authDao ?? makeAuthDao();
  const macDao  = overrides.macDao  ?? makeMacDao();
  const cache   = overrides.cache   ?? makeCache();
  const kafka   = makeKafka();

  const svc = new AuthUseCase(jwt, cfg, authDao, macDao, cache, kafka);
  return { svc, jwt, authDao, macDao, cache, kafka };
}

const FULL_USER = {
  userId: 'u1', username: 'JPEREZ', roles: ['12'], email: 'j@x.com',
  nombres: 'Juan', apellidoPaterno: 'Pérez', apellidoMaterno: '',
  nombreCompleto: 'Juan Pérez', nombrePerfil: 'Médico', numeroDocumento: '12345',
  sucursales: [], idUsuario: '99',
  macToken: 'mac-tok-xyz', perfil: '12', requirePasswordChange: false,
};

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('AuthUseCase', () => {

  describe('login()', () => {
    it('login exitoso (sin sesion previa) → firma JWT y reserva la sesion activa en cache', async () => {
      const { svc, jwt, cache } = makeService({ authDao: makeAuthDao(FULL_USER) });

      const result = await svc.login('JPEREZ', 'pass123');

      expect(jwt.sign).toHaveBeenCalled();
      expect(cache.trySetActiveSession).toHaveBeenCalledWith(expect.any(String), 'mac-tok-xyz', '12', 'JPEREZ');
      expect(cache.set).not.toHaveBeenCalled();
      expect(result.data.access_token).toBe('signed-token');
      expect(result.success).toBe(true);
    });

    it('credenciales inválidas (validateUser devuelve null) → lanza UnauthorizedException', async () => {
      const { svc } = makeService({ authDao: makeAuthDao(null) });
      await expect(svc.login('JPEREZ', 'wrong')).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('sin mac_token → no llama a ningun metodo de cache', async () => {
      const user = { ...FULL_USER, macToken: '' };
      const { svc, cache } = makeService({ authDao: makeAuthDao(user) });
      await svc.login('JPEREZ', 'pass');
      expect(cache.set).not.toHaveBeenCalled();
      expect(cache.trySetActiveSession).not.toHaveBeenCalled();
    });

    describe('HU01 "Múltiples sesiones abiertas"', () => {
      it('ya existe sesion activa (trySetActiveSession=false) → lanza ActiveSessionExistsException, sin firmar JWT', async () => {
        const cache = makeCache();
        cache.trySetActiveSession.mockResolvedValue(false);
        const { svc, jwt } = makeService({ authDao: makeAuthDao(FULL_USER), cache });

        await expect(svc.login('JPEREZ', 'pass123')).rejects.toBeInstanceOf(ActiveSessionExistsException);
        expect(jwt.sign).not.toHaveBeenCalled();
      });

      it('forceLogout=true → cierra la sesion previa contra MAC y en cache, y emite la sesion nueva', async () => {
        const cache = makeCache();
        cache.closeUserSession.mockResolvedValue({ macToken: 'tok-viejo', sessionId: 'session-vieja' });
        const macDao = makeMacDao();
        const { svc, jwt, cache: cacheUsed } = makeService({ authDao: makeAuthDao(FULL_USER), cache, macDao });

        const result = await svc.login('JPEREZ', 'pass123', undefined, true);

        expect(cache.closeUserSession).toHaveBeenCalledWith('JPEREZ');
        expect(macDao.cerrarSesion).toHaveBeenCalledWith('tok-viejo', 'JPEREZ');
        expect(cacheUsed.set).toHaveBeenCalledWith(expect.any(String), 'mac-tok-xyz', '12', 'JPEREZ');
        expect(cache.trySetActiveSession).not.toHaveBeenCalled();
        expect(jwt.sign).toHaveBeenCalled();
        expect(result.success).toBe(true);
      });

      it('forceLogout=true sin sesion previa (closeUserSession=null) → no llama a macDao.cerrarSesion, igual emite la sesion nueva', async () => {
        const cache = makeCache();
        cache.closeUserSession.mockResolvedValue(null);
        const macDao = makeMacDao();
        const { svc, cache: cacheUsed } = makeService({ authDao: makeAuthDao(FULL_USER), cache, macDao });

        await svc.login('JPEREZ', 'pass123', undefined, true);

        expect(macDao.cerrarSesion).not.toHaveBeenCalled();
        expect(cacheUsed.set).toHaveBeenCalledWith(expect.any(String), 'mac-tok-xyz', '12', 'JPEREZ');
      });

      it('forceLogout=true y macDao.cerrarSesion falla → no bloquea el login (best-effort)', async () => {
        const cache = makeCache();
        cache.closeUserSession.mockResolvedValue({ macToken: 'tok-viejo', sessionId: 'session-vieja' });
        const macDao = makeMacDao();
        macDao.cerrarSesion.mockRejectedValue(new Error('MAC token ya expirado'));
        const { svc, jwt } = makeService({ authDao: makeAuthDao(FULL_USER), cache, macDao });

        const result = await svc.login('JPEREZ', 'pass123', undefined, true);

        expect(jwt.sign).toHaveBeenCalled();
        expect(result.success).toBe(true);
      });

      it('Redis no disponible (trySetActiveSession rechaza) → degrada con gracia, permite el login igual', async () => {
        const cache = makeCache();
        cache.trySetActiveSession.mockRejectedValue(new Error('ECONNREFUSED'));
        const { svc, jwt, kafka } = makeService({ authDao: makeAuthDao(FULL_USER), cache });

        const result = await svc.login('JPEREZ', 'pass123');

        expect(jwt.sign).toHaveBeenCalled();
        expect(result.success).toBe(true);
        expect(kafka.log).toHaveBeenCalledWith(expect.objectContaining({ eventType: 'LOGIN_SESSION_CACHE_UNAVAILABLE' }));
      });
    });
  });

  describe('getMe()', () => {
    it('retorna los datos del usuario desde el payload del JWT', () => {
      const { svc } = makeService();
      const payload = {
        sub: 'u1', username: 'JPEREZ', email: 'j@x.com', roles: ['12'],
        sessionId: 'sess-1', idUsuario: '99', nombres: 'Juan',
        apellidoPaterno: 'P', apellidoMaterno: 'G',
        nombreCompleto: 'Juan P G', nombrePerfil: 'Médico',
        numeroDocumento: '12345', sucursales: [],
      };
      const result = svc.getMe(payload);
      expect(result.data.userId).toBe('u1');
      expect(result.data.username).toBe('JPEREZ');
      expect(result.data.sessionId).toBe('sess-1');
    });
  });

  describe('getAccesos()', () => {
    it('sin entrada en cache → lanza UnauthorizedException', async () => {
      const cache = makeCache();
      cache.get.mockResolvedValue(null);
      const { svc } = makeService({ cache });
      await expect(svc.getAccesos({ sessionId: 's1' })).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('con cache → llama macDao.getAccesos y retorna opciones + permisos aplanados', async () => {
      const cache = makeCache();
      cache.get.mockResolvedValue({ macToken: 'tok', perfil: '12' });

      const opciones = [
        { codigo: '01', titulo: 'Módulo A', indicador: 'E', opciones: [
          { codigo: '01/01', titulo: 'Sub A1', indicador: 'E' },
        ]},
      ];
      const macDao = makeMacDao({ data: { opciones } });
      const { svc } = makeService({ cache, macDao });

      const result = await svc.getAccesos({ sessionId: 's1' });

      expect(macDao.getAccesos).toHaveBeenCalledWith('tok', '12');
      expect(result.data.opciones).toEqual(opciones);
      // flattenOpciones debe aplanar el árbol (padre + hijo = 2 entradas)
      expect(result.data.permisos).toHaveLength(2);
      expect(result.data.permisos[0]).toMatchObject({ codigo: '01', indicador: 'E' });
      expect(result.data.permisos[1]).toMatchObject({ codigo: '01/01', indicador: 'E' });
    });

    it('opciones vacías en respuesta MAC → permisos = []', async () => {
      const cache = makeCache();
      cache.get.mockResolvedValue({ macToken: 'tok', perfil: '12' });
      const { svc } = makeService({ cache, macDao: makeMacDao({ data: { opciones: [] } }) });
      const result = await svc.getAccesos({ sessionId: 's1' });
      expect(result.data.permisos).toHaveLength(0);
    });
  });

  describe('flattenOpciones() — via getAccesos', () => {
    async function flatten(opciones: any[]) {
      const cache = makeCache();
      cache.get.mockResolvedValue({ macToken: 't', perfil: 'p' });
      const macDao = makeMacDao({ data: { opciones } });
      const { svc } = makeService({ cache, macDao });
      return (await svc.getAccesos({ sessionId: 's' })).data.permisos;
    }

    it('árbol de 3 niveles se aplana correctamente', async () => {
      const tree = [{
        codigo: '01', titulo: 'Root', indicador: 'E',
        opciones: [{
          codigo: '01/01', titulo: 'L2', indicador: 'L',
          opciones: [{ codigo: '01/01/01', titulo: 'L3', indicador: 'O' }],
        }],
      }];
      const permisos = await flatten(tree);
      expect(permisos).toHaveLength(3);
      expect(permisos.map((p: any) => p.codigo)).toEqual(['01', '01/01', '01/01/01']);
    });

    it('campos nulos en opciones no rompen el aplanado', async () => {
      const tree = [{ codigo: null, titulo: undefined, indicador: null }];
      const permisos = await flatten(tree);
      expect(permisos).toHaveLength(1);
      expect(permisos[0]).toMatchObject({ codigo: '', titulo: '', indicador: '' });
    });
  });
});
