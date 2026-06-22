import { Injectable, Logger, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Kafka, Producer, logLevel } from 'kafkajs';

export interface AuditLogEntry {
  traceId?:   string;
  userId?:    string;
  username?:  string;
  sessionId?: string;
  level?:       string;
  eventType?:   string;
  action?:      string;
  outcome?:     string;
  message?:     string;
  payload?:     Record<string, any>;
  // Específicos de eventos de autenticación (login/logout) — el AuditEvent del
  // audit-logger sí tiene columnas ip_address/user_agent, a diferencia del resto
  // de campos genéricos que solo se persisten dentro de payload_encrypted.
  ipAddress?: string;
  userAgent?: string;
}

@Injectable()
export class KafkaLoggerService implements OnModuleInit, OnModuleDestroy {
  private readonly nestLogger = new Logger(KafkaLoggerService.name);
  private producer!: Producer;

  /** true si el audit logger está habilitado vía AUDIT_LOGGER_ENABLED. */
  private readonly enabled: boolean;

  constructor(private readonly cfg: ConfigService) {
    this.enabled = this.cfg.get<string>('AUDIT_LOGGER_ENABLED', 'true').trim().toLowerCase() !== 'false';
  }

  async onModuleInit() {
    if (!this.enabled) {
      this.nestLogger.log('Audit logger deshabilitado (AUDIT_LOGGER_ENABLED=false) — Kafka no será utilizado.');
      return;
    }

    const kafka = new Kafka({
      clientId: 'auth-pruebas-auth-logger',
      brokers:  (this.cfg.get<string>('KAFKA_BROKER', 'localhost:9092')).split(','),
      logLevel: logLevel.ERROR,
    });
    this.producer = kafka.producer();
    try {
      await this.producer.connect();
    } catch (err: any) {
      this.nestLogger.error(`FATAL: AUDIT_LOGGER_ENABLED=true pero no se pudo conectar a Kafka — el servicio no puede iniciar. Causa: ${err?.message}`);
      process.exit(1);
    }
  }

  async onModuleDestroy() {
    if (this.enabled) {
      await this.producer.disconnect();
    }
  }

  async log(entry: AuditLogEntry): Promise<void> {
    if (!this.enabled) return;

    try {
      await this.producer.send({
        topic: this.cfg.get<string>('KAFKA_TOPIC', 'platform.logs'),
        messages: [{
          value: JSON.stringify({
            source_system: 'ms-cnl-cross-auth-profile',
            event_type:    entry.eventType  ?? 'SERVICE_CALL',
            level:         entry.level      ?? 'INFO',
            trace_id:      entry.traceId,
            user_id:       entry.userId,
            username:      entry.username,
            session_id:    entry.sessionId,
            action:        entry.action     ?? entry.message ?? '',
            outcome:       entry.outcome    ?? 'SUCCESS',
            message:       entry.message    ?? '',
            payload:       entry.payload    ?? {},
            ip_address:    entry.ipAddress,
            user_agent:    entry.userAgent,
            timestamp:     new Date().toISOString(),
          }),
        }],
      });
    } catch (err: any) {
      // Fire and forget — nunca interrumpe el flujo de autenticación, pero se deja registro del fallo.
      this.nestLogger.warn(`Kafka send fallido: ${err?.message}`);
    }
  }

  extractAuditContext(headers: Record<string, any>): Pick<AuditLogEntry, 'traceId' | 'userId' | 'username' | 'sessionId'> {
    return {
      traceId:   headers['x-trace-id']   as string | undefined,
      userId:    headers['x-user-id']    as string | undefined,
      username:  headers['x-username']   as string | undefined,
      sessionId: headers['x-session-id'] as string | undefined,
    };
  }
}
