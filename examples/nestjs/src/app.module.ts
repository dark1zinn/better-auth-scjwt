import { Module } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { AuthModule } from '@thallesp/nestjs-better-auth';
import { auth } from './auth.js';
import { BetterAuthExceptionFilter } from './better-auth-exception.filter.js';
import { HealthController } from './health.controller.js';
import { ProfileController } from './profile.controller.js';

@Module({
  imports: [AuthModule.forRoot({ auth })],
  controllers: [HealthController, ProfileController],
  providers: [{ provide: APP_FILTER, useClass: BetterAuthExceptionFilter }],
})
export class AppModule {}
