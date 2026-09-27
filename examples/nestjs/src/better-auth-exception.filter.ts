import {
  type ArgumentsHost,
  Catch,
  type ExceptionFilter,
} from '@nestjs/common';
import { APIError } from 'better-auth/api';
import type { Response } from 'express';

@Catch(APIError)
export class BetterAuthExceptionFilter implements ExceptionFilter<APIError> {
  catch(exception: APIError, host: ArgumentsHost): void {
    const statusCode = exception.statusCode;
    host.switchToHttp().getResponse<Response>().status(statusCode).json({
      statusCode,
      message: exception.message,
    });
  }
}
