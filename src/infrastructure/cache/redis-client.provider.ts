import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';

export const REDIS_CLIENT = Symbol('REDIS_CLIENT');

/**
 * Subconjunto de la API de ioredis que este servicio realmente usa — permite inyectar un
 * fake en tests (ver mac-token-cache.service.spec.ts) sin depender de un Redis real.
 */
export interface RedisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode: 'EX', ttlSeconds: number): Promise<unknown>;
  /** SET ... EX ttlSeconds NX — escribe solo si la key no existia. 'OK' si escribio, null si ya existia (ioredis). */
  set(key: string, value: string, mode: 'EX', ttlSeconds: number, nx: 'NX'): Promise<'OK' | null>;
  del(key: string): Promise<unknown>;
}

/**
 * Cliente Redis real, para escalar MacTokenCacheService mas alla de una sola instancia de
 * ms-cnl-cross-auth-profile (requisito real: multiples logins concurrentes a medida que
 * crece el nuevo sistema HCE — un Map en memoria de proceso no detecta sesiones activas
 * creadas en OTRA instancia/replica). Sin auth por defecto (REDIS_PASSWORD vacio) para
 * paridad con el resto de infra de desarrollo del proyecto (ej. Kafka sin SASL en dev).
 */
export function createRedisClient(cfg: ConfigService): Redis {
  const password = cfg.get<string>('REDIS_PASSWORD', '');
  return new Redis({
    host: cfg.get<string>('REDIS_HOST', 'localhost'),
    port: Number(cfg.get<string>('REDIS_PORT', '6379')),
    password: password || undefined,
    db: Number(cfg.get<string>('REDIS_DB', '0')),
    // Reintentos con backoff acotado -- nunca debe bloquear el arranque del servicio
    // si Redis todavia no esta listo (ej. orden de arranque en docker compose).
    retryStrategy: (attempt: number) => Math.min(attempt * 200, 5000),
    maxRetriesPerRequest: 3,
  });
}
