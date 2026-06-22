import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

interface CacheEntry {
  macToken: string;
  perfil:   string;
  expiresAt: number;
}

/**
 * Almacena el mac_token externo en memoria del servidor, indexado por sessionId.
 * El JWT ya NO carga el mac_token — solo viaja el sessionId para buscar aquí.
 *
 * Para escalar a múltiples instancias: reemplazar `Map` por un cliente Redis
 * inyectado vía un módulo de cache (ej: @nestjs/cache-manager con ioredis).
 * La interfaz de set/get/delete no cambia → AuthUseCase no requiere modificación.
 */
@Injectable()
export class MacTokenCacheService {
  private readonly store  = new Map<string, CacheEntry>();
  private readonly ttlMs: number;

  constructor(cfg: ConfigService) {
    const raw   = cfg.get<string>('JWT_EXPIRES_IN', '4h');
    const match = raw.match(/^(\d+)(s|m|h|d)$/);
    const mult: Record<string, number> = { s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 };
    this.ttlMs  = match ? Number(match[1]) * (mult[match[2]] ?? 3_600_000) : 4 * 3_600_000;
  }

  set(sessionId: string, macToken: string, perfil: string): void {
    this.store.set(sessionId, { macToken, perfil, expiresAt: Date.now() + this.ttlMs });
  }

  get(sessionId: string): { macToken: string; perfil: string } | null {
    const entry = this.store.get(sessionId);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.store.delete(sessionId);
      return null;
    }
    return { macToken: entry.macToken, perfil: entry.perfil };
  }

  delete(sessionId: string): void {
    this.store.delete(sessionId);
  }
}
