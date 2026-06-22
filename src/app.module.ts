import { Module } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { HttpModule } from '@nestjs/axios';
import { HealthModule } from './health/health.module';
import { KafkaLoggerModule } from './logger/kafka-logger.module';
import { AuditInterceptor } from './logger/audit.interceptor';
import { AuthUseCase } from './application/use-cases/Auth.use-case';
import { AuthController } from './infrastructure/controllers/Auth.controller';
import { ExternalAuthDao } from './infrastructure/persistence/external-auth.dao';
import { MacTokenCacheService } from './infrastructure/cache/mac-token-cache.service';
import { JwtAuthGuard } from './infrastructure/guards/jwt-auth.guard';
import { AUTH_DAO, MAC_DAO } from './domain/repositories/auth-dao.interface';

@Module({
  imports: [
    HealthModule,
    ConfigModule.forRoot({ isGlobal: true }),
    JwtModule.registerAsync({
      imports:    [ConfigModule],
      useFactory: (cfg: ConfigService) => ({
        secret:      cfg.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: cfg.get<string>('JWT_EXPIRES_IN', '4h') as any },
      }),
      inject: [ConfigService],
    }),
    HttpModule.registerAsync({
      imports:    [ConfigModule],
      useFactory: (cfg: ConfigService) => ({
        timeout: Number(cfg.get<string>('EXTERNAL_AUTH_TIMEOUT_MS', '5000')),
      }),
      inject: [ConfigService],
    }),
    KafkaLoggerModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthUseCase,
    ExternalAuthDao,
    MacTokenCacheService,
    JwtAuthGuard,
    { provide: AUTH_DAO, useClass: ExternalAuthDao },
    { provide: MAC_DAO,  useClass: ExternalAuthDao },
    { provide: APP_INTERCEPTOR, useClass: AuditInterceptor },
  ],
})
export class AppModule {}
