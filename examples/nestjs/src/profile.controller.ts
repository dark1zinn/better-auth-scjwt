import { Controller, Get } from '@nestjs/common';
import {
  Session,
  type UserSession,
} from '@thallesp/nestjs-better-auth';
import type { auth } from './auth.js';

@Controller()
export class ProfileController {
  @Get('me')
  getProfile(@Session() session: UserSession<typeof auth>): {
    id: string;
    email: string;
  } {
    return { id: session.user.id, email: session.user.email };
  }
}
