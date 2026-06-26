import { NestFactory }    from '@nestjs/core';
import { ValidationPipe, VersioningType } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule }      from './app.module';
import * as http  from 'http';
import * as https from 'https';
import * as cookieParser from 'cookie-parser';
import { buildHttpsOptions } from './ssl/ssl-config.util';
import { GlobalExceptionFilter } from './filters/global-exception.filter';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { logger: ['log', 'warn', 'error', 'debug'] });

  // Excepción a la regla "MS Canal no necesita cookieParser": el GW solo convierte
  // la cookie access_token a Bearer automáticamente, pero refresh_token nunca pasa por
  // esa conversión — este servicio (el único que la usa) necesita leerla directamente.
  app.use(cookieParser());
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));
  app.useGlobalFilters(new GlobalExceptionFilter());

  app.setGlobalPrefix('api', { exclude: ['health'] });
  app.enableVersioning({ type: VersioningType.URI, defaultVersion: '1', prefix: 'v' });

  if (process.env['NODE_ENV'] !== 'production') {
    const doc = new DocumentBuilder()
      .setTitle('Auth Service — ms-cnl-cross-auth-profile')
      .setDescription('Microservicio de autenticación JWT + integración MAC')
      .setVersion('1.0')
      .addBearerAuth()
      .addCookieAuth('access_token')
      .build();
    SwaggerModule.setup('api/docs', app, SwaggerModule.createDocument(app, doc));
  }

  await app.init();
  const expressApp = app.getHttpAdapter().getInstance();

  const port = Number(process.env['PORT'] ?? 10701);
  http.createServer(expressApp).listen(port, () => {
    console.log(`[ms-cnl-cross-auth-profile] HTTP  -> http://localhost:${port}`);
    if (process.env['NODE_ENV'] !== 'production') {
      console.log(`[ms-cnl-cross-auth-profile] Swagger -> http://localhost:${port}/api/docs`);
    }
  });

  const httpsOptions = buildHttpsOptions();
  if (httpsOptions) {
    const sslPort = Number(process.env['SSL_PORT'] ?? 20701);
    try {
      https.createServer(httpsOptions, expressApp).listen(sslPort, () => {
        console.log(`[ms-cnl-cross-auth-profile] HTTPS -> https://localhost:${sslPort}`);
      });
    } catch (e: any) {
      console.error('Error al iniciar HTTPS:', e.message, '— solo HTTP activo');
    }
  }
}
bootstrap();
