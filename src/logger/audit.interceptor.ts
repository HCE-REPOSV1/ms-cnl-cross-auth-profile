import {
  Injectable, NestInterceptor, ExecutionContext, CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { KafkaLoggerService } from './kafka-logger.service';

@Injectable()
export class AuditInterceptor implements NestInterceptor {
  constructor(private readonly logger: KafkaLoggerService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const req = context.switchToHttp().getRequest();
    if (req.url === '/health') return next.handle();
    const start = Date.now();
    const headerCtx = this.logger.extractAuditContext(req.headers);

    return next.handle().pipe(
      tap({
        next: () => {
          const res      = context.switchToHttp().getResponse();
          const duration = Date.now() - start;
          // En rutas protegidas, JwtAuthGuard ya corrió antes del handler y dejó
          // el payload del JWT en req.user — de ahí sacamos sessionId, ya que
          // apigw-cnl-cross no propaga x-session-id (solo x-user-id/x-username).
          const sessionId = headerCtx.sessionId ?? req['user']?.sessionId;
          this.logger.log({
            ...headerCtx,
            sessionId,
            eventType: 'SERVICE_CALL',
            level:     res.statusCode < 400 ? 'INFO' : 'WARN',
            action:    `${req.method} ${req.url}`,
            outcome:   res.statusCode < 400 ? 'SUCCESS' : 'FAILED',
            message:   `${req.method} ${req.url} — ${res.statusCode} (${duration}ms)`,
            payload:   { method: req.method, url: req.url, statusCode: res.statusCode, duration },
          });
        },
        error: (err) => {
          const duration  = Date.now() - start;
          const sessionId = headerCtx.sessionId ?? req['user']?.sessionId;
          this.logger.log({
            ...headerCtx,
            sessionId,
            eventType: 'SERVICE_CALL',
            level:     'ERROR',
            action:    `${req.method} ${req.url}`,
            outcome:   'ERROR',
            message:   `${req.method} ${req.url} — ERROR (${duration}ms): ${err?.message}`,
            payload:   { method: req.method, url: req.url, duration, error: err?.message },
          });
        },
      }),
    );
  }
}
