import { MacTokenCacheService } from './mac-token-cache.service';
import { RedisLike } from './redis-client.provider';
import { ConfigService } from '@nestjs/config';

/** Crea un ConfigService mínimo que responde JWT_EXPIRES_IN */
function makeCfg(expiresIn = '4h'): ConfigService {
  return { get: (key: string, def?: string) => key === 'JWT_EXPIRES_IN' ? expiresIn : def } as any;
}

/**
 * Fake en memoria de RedisLike — respeta EX (TTL) y NX (set-if-absent) igual que ioredis
 * real, para poder probar MacTokenCacheService sin depender de un Redis levantado.
 */
class FakeRedis implements RedisLike {
  private readonly store = new Map<string, { value: string; expiresAt: number }>();

  private isExpired(key: string): boolean {
    const entry = this.store.get(key);
    if (!entry) return true;
    if (Date.now() > entry.expiresAt) { this.store.delete(key); return true; }
    return false;
  }

  async get(key: string): Promise<string | null> {
    if (this.isExpired(key)) return null;
    return this.store.get(key)!.value;
  }

  async set(key: string, value: string, _mode: 'EX', ttlSeconds: number, nx?: 'NX'): Promise<any> {
    if (nx === 'NX' && !this.isExpired(key)) return null;
    this.store.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
    return 'OK';
  }

  async del(key: string): Promise<unknown> {
    return this.store.delete(key) ? 1 : 0;
  }
}

describe('MacTokenCacheService', () => {

  describe('set / get', () => {
    it('almacena y recupera la entrada correctamente', async () => {
      const svc = new MacTokenCacheService(new FakeRedis(), makeCfg());
      await svc.set('session-1', 'mac-tok-abc', 'perfil-12', 'jperez');
      await expect(svc.get('session-1')).resolves.toEqual({ macToken: 'mac-tok-abc', perfil: 'perfil-12' });
    });

    it('devuelve null para una sessionId desconocida', async () => {
      const svc = new MacTokenCacheService(new FakeRedis(), makeCfg());
      await expect(svc.get('no-existe')).resolves.toBeNull();
    });

    it('sobrescribe la entrada si se llama set dos veces con la misma session', async () => {
      const svc = new MacTokenCacheService(new FakeRedis(), makeCfg());
      await svc.set('s', 'tok1', 'p1', 'jperez');
      await svc.set('s', 'tok2', 'p2', 'jperez');
      await expect(svc.get('s')).resolves.toEqual({ macToken: 'tok2', perfil: 'p2' });
    });
  });

  describe('TTL', () => {
    beforeEach(() => jest.useFakeTimers());
    afterEach(() => jest.useRealTimers());

    it('devuelve null tras expirar (1s)', async () => {
      const svc = new MacTokenCacheService(new FakeRedis(), makeCfg('1s'));
      await svc.set('s', 'tok', 'p', 'jperez');
      jest.advanceTimersByTime(999);
      await expect(svc.get('s')).resolves.not.toBeNull();
      jest.advanceTimersByTime(2);
      await expect(svc.get('s')).resolves.toBeNull();
    });

    it('TTL en minutos (30m) se calcula correctamente', async () => {
      const svc = new MacTokenCacheService(new FakeRedis(), makeCfg('30m'));
      await svc.set('s', 'tok', 'p', 'jperez');
      jest.advanceTimersByTime(30 * 60 * 1000 - 1);
      await expect(svc.get('s')).resolves.not.toBeNull();
      jest.advanceTimersByTime(2);
      await expect(svc.get('s')).resolves.toBeNull();
    });

    it('TTL en días (1d) se calcula correctamente', async () => {
      const svc = new MacTokenCacheService(new FakeRedis(), makeCfg('1d'));
      await svc.set('s', 'tok', 'p', 'jperez');
      jest.advanceTimersByTime(86_400_000 - 1);
      await expect(svc.get('s')).resolves.not.toBeNull();
      jest.advanceTimersByTime(2);
      await expect(svc.get('s')).resolves.toBeNull();
    });

    it('formato inválido usa default 4h', async () => {
      const svc = new MacTokenCacheService(new FakeRedis(), makeCfg('INVALID'));
      await svc.set('s', 'tok', 'p', 'jperez');
      jest.advanceTimersByTime(4 * 3_600_000 - 1);
      await expect(svc.get('s')).resolves.not.toBeNull();
      jest.advanceTimersByTime(2);
      await expect(svc.get('s')).resolves.toBeNull();
    });
  });

  describe('delete', () => {
    it('elimina la entrada del store', async () => {
      const svc = new MacTokenCacheService(new FakeRedis(), makeCfg());
      await svc.set('s', 'tok', 'p', 'jperez');
      await svc.delete('s');
      await expect(svc.get('s')).resolves.toBeNull();
    });

    it('delete en sessionId inexistente no lanza error', async () => {
      const svc = new MacTokenCacheService(new FakeRedis(), makeCfg());
      await expect(svc.delete('no-existe')).resolves.not.toThrow();
    });

    it('tambien limpia el indice username->sessionId', async () => {
      const svc = new MacTokenCacheService(new FakeRedis(), makeCfg());
      await svc.set('s', 'tok', 'p', 'jperez');
      await svc.delete('s');
      await expect(svc.getActiveSessionForUser('jperez')).resolves.toBeNull();
    });
  });

  describe('indice username -> sessionId (HU01 "Múltiples sesiones abiertas")', () => {
    it('getActiveSessionForUser devuelve null si el usuario no tiene sesion activa', async () => {
      const svc = new MacTokenCacheService(new FakeRedis(), makeCfg());
      await expect(svc.getActiveSessionForUser('jperez')).resolves.toBeNull();
    });

    it('getActiveSessionForUser encuentra la sesion creada por set()', async () => {
      const svc = new MacTokenCacheService(new FakeRedis(), makeCfg());
      await svc.set('session-1', 'tok', 'p', 'jperez');
      await expect(svc.getActiveSessionForUser('jperez')).resolves.toBe('session-1');
    });

    it('getActiveSessionForUser es case-insensitive en el username', async () => {
      const svc = new MacTokenCacheService(new FakeRedis(), makeCfg());
      await svc.set('session-1', 'tok', 'p', 'jperez');
      await expect(svc.getActiveSessionForUser('JPEREZ')).resolves.toBe('session-1');
    });

    describe('trySetActiveSession', () => {
      it('reserva la sesion y devuelve true si el usuario no tenia ninguna activa', async () => {
        const svc = new MacTokenCacheService(new FakeRedis(), makeCfg());
        await expect(svc.trySetActiveSession('session-1', 'tok', 'p', 'jperez')).resolves.toBe(true);
        await expect(svc.get('session-1')).resolves.toEqual({ macToken: 'tok', perfil: 'p' });
      });

      it('devuelve false y NO escribe la sesion si el usuario ya tenia una activa', async () => {
        const svc = new MacTokenCacheService(new FakeRedis(), makeCfg());
        await svc.trySetActiveSession('session-1', 'tok1', 'p1', 'jperez');
        await expect(svc.trySetActiveSession('session-2', 'tok2', 'p2', 'jperez')).resolves.toBe(false);
        await expect(svc.get('session-2')).resolves.toBeNull();
        // la sesion original sigue intacta
        await expect(svc.getActiveSessionForUser('jperez')).resolves.toBe('session-1');
      });

      it('simula la carrera de dos logins casi simultaneos: solo uno de los dos gana', async () => {
        const svc = new MacTokenCacheService(new FakeRedis(), makeCfg());
        const [a, b] = await Promise.all([
          svc.trySetActiveSession('session-a', 'tokA', 'p', 'jperez'),
          svc.trySetActiveSession('session-b', 'tokB', 'p', 'jperez'),
        ]);
        expect([a, b].filter(Boolean)).toHaveLength(1);
      });
    });

    describe('closeUserSession', () => {
      it('devuelve null si el usuario no tenia sesion activa', async () => {
        const svc = new MacTokenCacheService(new FakeRedis(), makeCfg());
        await expect(svc.closeUserSession('jperez')).resolves.toBeNull();
      });

      it('cierra la sesion activa y devuelve su macToken/sessionId', async () => {
        const svc = new MacTokenCacheService(new FakeRedis(), makeCfg());
        await svc.set('session-1', 'tok-viejo', 'p', 'jperez');
        await expect(svc.closeUserSession('jperez')).resolves.toEqual({ macToken: 'tok-viejo', sessionId: 'session-1' });
        await expect(svc.get('session-1')).resolves.toBeNull();
        await expect(svc.getActiveSessionForUser('jperez')).resolves.toBeNull();
      });

      it('libera el slot para que un trySetActiveSession posterior pueda reservarlo', async () => {
        const svc = new MacTokenCacheService(new FakeRedis(), makeCfg());
        await svc.set('session-1', 'tok-viejo', 'p', 'jperez');
        await svc.closeUserSession('jperez');
        await expect(svc.trySetActiveSession('session-2', 'tok-nuevo', 'p', 'jperez')).resolves.toBe(true);
      });
    });
  });
});
