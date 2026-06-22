import { MacTokenCacheService } from './mac-token-cache.service';
import { ConfigService }        from '@nestjs/config';

/** Crea un ConfigService mínimo que responde JWT_EXPIRES_IN */
function makeCfg(expiresIn = '4h'): ConfigService {
  return { get: (key: string, def?: string) => key === 'JWT_EXPIRES_IN' ? expiresIn : def } as any;
}

describe('MacTokenCacheService', () => {

  describe('set / get', () => {
    it('almacena y recupera la entrada correctamente', () => {
      const svc = new MacTokenCacheService(makeCfg());
      svc.set('session-1', 'mac-tok-abc', 'perfil-12');
      expect(svc.get('session-1')).toEqual({ macToken: 'mac-tok-abc', perfil: 'perfil-12' });
    });

    it('devuelve null para una sessionId desconocida', () => {
      const svc = new MacTokenCacheService(makeCfg());
      expect(svc.get('no-existe')).toBeNull();
    });

    it('sobrescribe la entrada si se llama set dos veces con la misma session', () => {
      const svc = new MacTokenCacheService(makeCfg());
      svc.set('s', 'tok1', 'p1');
      svc.set('s', 'tok2', 'p2');
      expect(svc.get('s')).toEqual({ macToken: 'tok2', perfil: 'p2' });
    });
  });

  describe('TTL', () => {
    beforeEach(() => jest.useFakeTimers());
    afterEach(() => jest.useRealTimers());

    it('devuelve null tras expirar (1s)', () => {
      const svc = new MacTokenCacheService(makeCfg('1s'));
      svc.set('s', 'tok', 'p');
      jest.advanceTimersByTime(999);
      expect(svc.get('s')).not.toBeNull();
      jest.advanceTimersByTime(2);
      expect(svc.get('s')).toBeNull();
    });

    it('TTL en minutos (30m) se calcula correctamente', () => {
      const svc = new MacTokenCacheService(makeCfg('30m'));
      svc.set('s', 'tok', 'p');
      jest.advanceTimersByTime(30 * 60 * 1000 - 1);
      expect(svc.get('s')).not.toBeNull();
      jest.advanceTimersByTime(2);
      expect(svc.get('s')).toBeNull();
    });

    it('TTL en días (1d) se calcula correctamente', () => {
      const svc = new MacTokenCacheService(makeCfg('1d'));
      svc.set('s', 'tok', 'p');
      jest.advanceTimersByTime(86_400_000 - 1);
      expect(svc.get('s')).not.toBeNull();
      jest.advanceTimersByTime(2);
      expect(svc.get('s')).toBeNull();
    });

    it('formato inválido usa default 4h', () => {
      const svc = new MacTokenCacheService(makeCfg('INVALID'));
      svc.set('s', 'tok', 'p');
      jest.advanceTimersByTime(4 * 3_600_000 - 1);
      expect(svc.get('s')).not.toBeNull();
      jest.advanceTimersByTime(2);
      expect(svc.get('s')).toBeNull();
    });
  });

  describe('delete', () => {
    it('elimina la entrada del store', () => {
      const svc = new MacTokenCacheService(makeCfg());
      svc.set('s', 'tok', 'p');
      svc.delete('s');
      expect(svc.get('s')).toBeNull();
    });

    it('delete en sessionId inexistente no lanza error', () => {
      const svc = new MacTokenCacheService(makeCfg());
      expect(() => svc.delete('no-existe')).not.toThrow();
    });
  });
});
