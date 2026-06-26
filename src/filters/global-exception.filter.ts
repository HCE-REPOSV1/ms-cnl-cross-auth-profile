import { ArgumentsHost, Catch, ExceptionFilter, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { Request, Response } from 'express';
import { QueryFailedError } from 'typeorm';

/** Códigos de error de SQL Server que representan un conflicto de estado (no un fallo del servidor). */
const SQL_CONFLICT_ERROR_NUMBERS = new Set([2627, 2601, 547]);

/**
 * Códigos de error de SQL Server que indican un dato de entrada incompatible con el tipo de columna:
 * 2628/8152 = varchar/nvarchar/binary truncado, 8115/220 = overflow numérico (numeric/decimal/tinyint/smallint),
 * 8114/245 = conversión de tipo inválida, 241/242/295/296 = fecha/hora inválida o fuera de rango,
 * 8169 = uniqueidentifier inválido, 515 = NULL en columna que no lo permite.
 */
const SQL_BAD_INPUT_ERROR_NUMBERS = new Set([2628, 8152, 8115, 220, 8114, 245, 241, 242, 295, 296, 8169, 515]);

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger('ExceptionFilter');

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      const body = exception.getResponse();
      response.status(status).json(typeof body === 'string' ? { statusCode: status, message: body } : body);
      return;
    }

    if (exception instanceof QueryFailedError) {
      const driverCode: string | undefined = (exception as any).code ?? (exception as any).driverError?.code;
      const sqlNumber: number | undefined =
        typeof (exception as any).number === 'number'
          ? (exception as any).number
          : typeof (exception as any).driverError?.number === 'number'
            ? (exception as any).driverError.number
            : undefined;

      this.logger.error(
        `QueryFailedError [code=${driverCode} number=${sqlNumber}] en ${request.method} ${request.originalUrl}: ${exception.message}`,
      );

      // El driver (tedious) valida tipo/rango de cada parámetro ANTES de enviarlo a SQL Server
      // (ej. fecha fuera del rango 0001-9999, bit/uniqueidentifier con formato inválido). Cuando
      // rechaza el valor, lo hace con code 'EPARAM' y sin número de error SQL — nunca llega a la BD.
      if (driverCode === 'EPARAM') {
        response.status(HttpStatus.BAD_REQUEST).json({
          statusCode: HttpStatus.BAD_REQUEST,
          error: 'Bad Request',
          message: 'El valor enviado no es válido para el tipo de dato del campo (formato, rango o tipo incorrecto)',
        });
        return;
      }

      if (sqlNumber && SQL_CONFLICT_ERROR_NUMBERS.has(sqlNumber)) {
        response.status(HttpStatus.CONFLICT).json({
          statusCode: HttpStatus.CONFLICT,
          error: 'Conflict',
          message: this.extractConstraintMessage(exception.message),
        });
        return;
      }

      if (sqlNumber && SQL_BAD_INPUT_ERROR_NUMBERS.has(sqlNumber)) {
        response.status(HttpStatus.BAD_REQUEST).json({
          statusCode: HttpStatus.BAD_REQUEST,
          error: 'Bad Request',
          message: this.extractBadInputMessage(sqlNumber, exception.message),
        });
        return;
      }

      response.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
        error: 'Internal Server Error',
        message: 'Error al procesar la operación en base de datos',
      });
      return;
    }

    this.logger.error(`Excepción no controlada en ${request.method} ${request.originalUrl}`, (exception as any)?.stack);
    response.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
      statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
      error: 'Internal Server Error',
      message: 'Error interno del servidor',
    });
  }

  private extractConstraintMessage(raw: string): string {
    const match = raw.match(/constraint '([^']+)'/i) ?? raw.match(/index '([^']+)'/i);
    const constraint = match ? match[1] : undefined;
    if (/unique/i.test(raw)) {
      return constraint
        ? `Ya existe un registro con ese valor único (constraint: ${constraint})`
        : 'Ya existe un registro con ese valor único';
    }
    if (/check constraint/i.test(raw)) {
      return constraint
        ? `La operación viola una regla de integridad de datos (constraint: ${constraint})`
        : 'La operación viola una regla de integridad de datos';
    }
    return 'La operación viola una restricción de integridad de datos';
  }

  private extractBadInputMessage(sqlNumber: number, raw: string): string {
    const colMatch = raw.match(/column '([^']+)'/i);
    const column = colMatch ? colMatch[1] : undefined;
    switch (sqlNumber) {
      case 8152:
      case 2628:
        return column
          ? `El valor enviado es demasiado largo para el campo '${column}'`
          : 'El valor enviado es demasiado largo para el campo';
      case 8115:
      case 220:
        return 'El valor numérico enviado excede el rango o la precisión permitida para el campo';
      case 8114:
      case 245:
        return 'El valor enviado no tiene un tipo de dato válido para el campo';
      case 241:
      case 242:
      case 295:
      case 296:
        return 'El valor de fecha/hora enviado es inválido o está fuera de rango para el campo';
      case 8169:
        return 'El valor enviado no es un identificador único (uniqueidentifier) válido';
      case 515:
        return column
          ? `El campo '${column}' no puede ser nulo`
          : 'Un campo obligatorio no puede ser nulo';
      default:
        return 'El valor enviado no es válido para uno de los campos';
    }
  }
}
