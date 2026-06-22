import { UnauthorizedException }  from '@nestjs/common';
import { JwtService }             from '@nestjs/jwt';
import { ConfigService }          from '@nestjs/config';
import { AuthUseCase }            from './Auth.use-case';
import { MacTokenCacheService }   from '../../infrastructure/cache/mac-token-cache.service';
import { IAuthDao, IMacAuthDao }  from '../../domain/repositories/auth-dao.interface';
import { KafkaLoggerService }     from '../../logger/kafka-logger.service';

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

function makeCache(): jest.Mocked<MacTokenCacheService> {
  return { set: jest.fn(), get: jest.fn(), delete: jest.fn() } as any;
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

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('AuthUseCase', () => {

  describe('login()', () => {
    it('login exitoso → firma JWT y almacena mac_token en cache', async () => {
      const user = {
        userId: 'u1', username: 'JPEREZ', roles: ['12'], email: 'j@x.com',
        nombres: 'Juan', apellidoPaterno: 'Pérez', apellidoMaterno: '',
        nombreCompleto: 'Juan Pérez', nombrePerfil: 'Médico', numeroDocumento: '12345',
        sucursales: [], idUsuario: '99',
        macToken: 'mac-tok-xyz', perfil: '12', requirePasswordChange: false,
      };
      const { svc, jwt, cache } = makeService({ authDao: makeAuthDao(user) });

      const result = await svc.login('JPEREZ', 'pass123');

      expect(jwt.sign).toHaveBeenCalled();
      expect(cache.set).toHaveBeenCalledWith(expect.any(String), 'mac-tok-xyz', '12');
      expect(result.data.access_token).toBe('signed-token');
      expect(result.success).toBe(true);
    });

    it('credenciales inválidas (validateUser devuelve null) → lanza UnauthorizedException', async () => {
      const { svc } = makeService({ authDao: makeAuthDao(null) });
      await expect(svc.login('JPEREZ', 'wrong')).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('sin mac_token → no llama cache.set', async () => {
      const user = {
        userId: 'u1', username: 'JPEREZ', roles: [], email: '',
        nombres: '', apellidoPaterno: '', apellidoMaterno: '',
        nombreCompleto: '', nombrePerfil: '', numeroDocumento: '',
        sucursales: [], idUsuario: '',
        macToken: '',   // sin token MAC
        perfil: '', requirePasswordChange: false,
      };
      const { svc, cache } = makeService({ authDao: makeAuthDao(user) });
      await svc.login('JPEREZ', 'pass');
      expect(cache.set).not.toHaveBeenCalled();
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
      cache.get.mockReturnValue(null);
      const { svc } = makeService({ cache });
      await expect(svc.getAccesos({ sessionId: 's1' })).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('con cache → llama macDao.getAccesos y retorna opciones + permisos aplanados', async () => {
      const cache = makeCache();
      cache.get.mockReturnValue({ macToken: 'tok', perfil: '12' });

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
      cache.get.mockReturnValue({ macToken: 'tok', perfil: '12' });
      const { svc } = makeService({ cache, macDao: makeMacDao({ data: { opciones: [] } }) });
      const result = await svc.getAccesos({ sessionId: 's1' });
      expect(result.data.permisos).toHaveLength(0);
    });
  });

  describe('flattenOpciones() — via getAccesos', () => {
    async function flatten(opciones: any[]) {
      const cache = makeCache();
      cache.get.mockReturnValue({ macToken: 't', perfil: 'p' });
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
