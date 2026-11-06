import type { ModuleMetadata } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { AuthModule } from '@thallesp/nestjs-better-auth';
import { BetterAuthExceptionFilter } from './better-auth-exception.filter.js';
import { HealthController } from './health.controller.js';
import { ProfileController } from './profile.controller.js';

type AuthInstance = Parameters<typeof AuthModule.forRoot>[0]['auth'];

/** Module wiring shared by the production module and isolated E2E profiles. */
export function createAppModuleMetadata(
  authInstance: AuthInstance,
): ModuleMetadata {
  return {
    imports: [AuthModule.forRoot({ auth: authInstance })],
    controllers: [HealthController, ProfileController],
    providers: [{ provide: APP_FILTER, useClass: BetterAuthExceptionFilter }],
  };
}
