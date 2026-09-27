import { Module } from '@nestjs/common';
import { AuthModule } from '@thallesp/nestjs-better-auth';
import { auth } from './auth.js';
import { HealthController } from './health.controller.js';
import { ProfileController } from './profile.controller.js';

@Module({
  imports: [AuthModule.forRoot({ auth })],
  controllers: [HealthController, ProfileController],
})
export class AppModule {}
