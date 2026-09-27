import { Controller, Get } from '@nestjs/common';
import { AllowAnonymous } from '@thallesp/nestjs-better-auth';

@Controller()
export class HealthController {
  @Get('health')
  @AllowAnonymous()
  getHealth(): { status: 'ok' } {
    return { status: 'ok' };
  }
}
