import type { UserSession } from '@thallesp/nestjs-better-auth';
import { ProfileController } from '../../src/profile.controller.js';

describe('ProfileController', () => {
  it('returns only the authenticated user identity', () => {
    const now = new Date('2026-01-01T00:00:00.000Z');
    const session = {
      user: {
        id: 'user-1',
        name: 'Nest User',
        email: 'nest@example.com',
        emailVerified: true,
        image: null,
        createdAt: now,
        updatedAt: now,
        role: 'user',
      },
      session: {
        id: 'session-1',
        token: 'opaque-session-token',
        userId: 'user-1',
        expiresAt: new Date('2026-01-02T00:00:00.000Z'),
        createdAt: now,
        updatedAt: now,
        ipAddress: '127.0.0.1',
        userAgent: 'vitest',
      },
    } satisfies UserSession;

    const result = new ProfileController().getProfile(session);

    expect(result).toEqual({ id: 'user-1', email: 'nest@example.com' });
    expect(Object.keys(result).sort()).toEqual(['email', 'id']);
  });
});
