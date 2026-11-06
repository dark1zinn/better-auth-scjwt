import { admin } from 'better-auth/plugins/admin';
import {
  createNestAuthHarness,
  expectNoScjwt,
  expectScjwt,
  PASSWORD,
  responseCookies,
  sessionIdOf,
  type AuthClient,
} from './support/nest-auth-harness.js';

type UserRecord = { id: string; email: string; role?: string; name?: string };
type SessionRecord = { id: string; token: string; userId: string };

const ADMIN_EMAIL = 'admin@example.com';
const TARGET_EMAIL = 'target@example.com';
const OTHER_EMAIL = 'other@example.com';
const NEW_PASSWORD = 'new-admin-password-123';

describe('NestJS Admin profile', () => {
  let harness: Awaited<
    ReturnType<typeof createNestAuthHarness<[ReturnType<typeof admin>]>>
  >;
  let cookieName: string;
  let adminId: string;
  let targetId: string;
  let adminClient: AuthClient;
  let targetEmail: string;
  let targetToken: string;
  let targetSecondToken: string;
  let targetClient: AuthClient;
  let targetSecondClient: AuthClient;
  let unrelatedClient: AuthClient;
  beforeAll(async () => {
    harness = await createNestAuthHarness({
      name: 'admin',
      additionalPlugins: [admin()],
    });
    cookieName = harness.sessionCookieName;
    adminClient = harness.createClient();
    const adminSignup = await adminClient.post('/api/auth/sign-up/email', {
      name: 'Initial Admin',
      email: ADMIN_EMAIL,
      password: PASSWORD,
    });
    expect(adminSignup.status).toBe(200);
    const adminUser = adminSignup.body.user as UserRecord;
    adminId = adminUser.id;
    await harness.context.internalAdapter.updateUser(adminId, {
      role: 'admin',
    });
    expect((await adminClient.get('/me')).status).toBe(200);
  });

  beforeEach(async () => {
    targetClient = harness.createClient();
    targetSecondClient = harness.createClient();
    unrelatedClient = harness.createClient();
    targetEmail = `${TARGET_EMAIL.replace('@', Date.now() + '@')}`;
    const targetSignup = await targetClient.post('/api/auth/sign-up/email', {
      name: 'Target User',
      email: targetEmail,
      password: PASSWORD,
    });
    expect(targetSignup.status).toBe(200);
    targetToken = expectScjwt(targetSignup, cookieName);
    targetId = (targetSignup.body.user as UserRecord).id;
    targetSecondToken = expectScjwt(
      await targetSecondClient.post('/api/auth/sign-in/email', {
        email: targetSignup.body.user.email,
        password: PASSWORD,
      }),
      cookieName,
    );
    const unrelated = await unrelatedClient.post('/api/auth/sign-up/email', {
      name: 'Unrelated User',
      email: `${OTHER_EMAIL.replace('@', Date.now() + '@')}`,
      password: PASSWORD,
    });
    expect(unrelated.status).toBe(200);
    expectScjwt(unrelated, cookieName);
  });

  afterAll(async () => {
    await harness?.close();
  });

  it('denies anonymous and ordinary users while allowing core admin CRUD', async () => {
    const anonymous = harness.createClient();
    expect((await anonymous.get('/api/auth/admin/list-users')).status).toBe(
      401,
    );
    const denied = await targetClient.post('/api/auth/admin/set-role', {
      userId: adminId,
      role: 'user',
    });
    expect(denied.status).toBe(403);
    expectNoScjwt(denied, cookieName);
    const deniedBan = await targetClient.post('/api/auth/admin/ban-user', {
      userId: adminId,
    });
    expect(deniedBan.status).toBe(403);
    expectNoScjwt(deniedBan, cookieName);

    const created = await adminClient.post('/api/auth/admin/create-user', {
      name: 'Created User',
      email: 'created@example.com',
      password: PASSWORD,
    });
    expect(created.status).toBe(200);
    const createdUser = created.body.user as UserRecord;
    expect(createdUser.email).toBe('created@example.com');
    const fetched = await adminClient.get(
      `/api/auth/admin/get-user?id=${createdUser.id}`,
    );
    expect(fetched.status).toBe(200);
    expect((fetched.body as UserRecord).id).toBe(createdUser.id);
    const listed = await adminClient.get('/api/auth/admin/list-users?limit=50');
    expect(listed.status).toBe(200);
    expect(
      (listed.body.users as UserRecord[]).some((u) => u.id === createdUser.id),
    ).toBe(true);
    const updated = await adminClient.post('/api/auth/admin/update-user', {
      userId: createdUser.id,
      data: { name: 'Updated User' },
    });
    expect(updated.status).toBe(200);
    expect((updated.body as UserRecord).name).toBe('Updated User');
    const role = await adminClient.post('/api/auth/admin/set-role', {
      userId: createdUser.id,
      role: 'admin',
    });
    expect(role.status).toBe(200);
    expectNoScjwt(role, cookieName);
    const verify = await adminClient.get(
      `/api/auth/admin/get-user?id=${createdUser.id}`,
    );
    expect((verify.body as UserRecord).role).toBe('admin');
    await adminClient.post('/api/auth/admin/set-role', {
      userId: createdUser.id,
      role: 'user',
    });
  });

  it('bans and unbans users without reviving their old tokens', async () => {
    const banned = await adminClient.post('/api/auth/admin/ban-user', {
      userId: targetId,
      banReason: 'test',
    });
    expect(banned.status).toBe(200);
    expectNoScjwt(banned, cookieName);
    expect((await harness.getWithToken('/me', targetToken)).status).toBe(401);
    expect((await harness.getWithToken('/me', targetSecondToken)).status).toBe(
      401,
    );
    const blocked = await harness
      .createClient()
      .post('/api/auth/sign-in/email', {
        email: targetEmail,
        password: PASSWORD,
      });
    expect(blocked.status).toBe(403);
    expect(blocked.body.code).toBe('BANNED_USER');
    expect((await unrelatedClient.get('/me')).status).toBe(200);
    expect((await adminClient.get('/me')).status).toBe(200);
    const unbanned = await adminClient.post('/api/auth/admin/unban-user', {
      userId: targetId,
    });
    expect(unbanned.status).toBe(200);
    const fresh = harness.createClient();
    const signin = await fresh.post('/api/auth/sign-in/email', {
      email: targetEmail,
      password: PASSWORD,
    });
    expect(signin.status).toBe(200);
    expectScjwt(signin, cookieName);
    expect((await harness.getWithToken('/me', targetToken)).status).toBe(401);
  });

  it('lists and revokes individual and all target sessions', async () => {
    const listed = await adminClient.post(
      '/api/auth/admin/list-user-sessions',
      { userId: targetId },
    );
    expect(listed.status).toBe(200);
    const sessions = listed.body.sessions as SessionRecord[];
    expect(sessions.length).toBeGreaterThanOrEqual(2);
    const chosen = sessions.find((s) => s.id === sessionIdOf(targetToken));
    expect(chosen).toBeDefined();
    const one = await adminClient.post('/api/auth/admin/revoke-user-session', {
      sessionToken: chosen?.token,
    });
    expect(one.status).toBe(200);
    expectNoScjwt(one, cookieName);
    expect((await harness.getWithToken('/me', targetToken)).status).toBe(401);
    expect((await harness.getWithToken('/me', targetSecondToken)).status).toBe(
      200,
    );
    const all = await adminClient.post('/api/auth/admin/revoke-user-sessions', {
      userId: targetId,
    });
    expect(all.status).toBe(200);
    expect((await harness.getWithToken('/me', targetSecondToken)).status).toBe(
      401,
    );
  });

  it('impersonates and restores the original admin session', async () => {
    const original = adminClient.token();
    expect(original).toBeDefined();
    const impersonated = await adminClient.post(
      '/api/auth/admin/impersonate-user',
      { userId: targetId },
    );
    expect(impersonated.status).toBe(200);
    const token = expectScjwt(impersonated, cookieName);
    expect(
      (await adminClient.get('/api/auth/get-session')).body.session
        .impersonatedBy,
    ).toBe(adminId);
    expect((await adminClient.get('/me')).body.id).toBe(targetId);
    const adminCookieName = `${cookieName.split('.')[0]}.admin_session`;
    expect(adminClient.cookie(adminCookieName)).toBeDefined();
    const stopped = await adminClient.post(
      '/api/auth/admin/stop-impersonating',
    );
    expect(stopped.status).toBe(200);
    const restored = expectScjwt(stopped, cookieName);
    expect(sessionIdOf(restored)).toBe(sessionIdOf(original as string));
    expect(
      responseCookies(stopped, adminCookieName).some((c) => c.deleted),
    ).toBe(true);
    expect([undefined, '']).toContain(adminClient.cookie(adminCookieName));
    expect((await harness.getWithToken('/me', token)).status).toBe(401);
    expect((await adminClient.get('/me')).body.id).toBe(adminId);
  });

  it('sets a user password and removes the user', async () => {
    const set = await adminClient.post('/api/auth/admin/set-user-password', {
      userId: targetId,
      newPassword: NEW_PASSWORD,
    });
    expect(set.status).toBe(200);
    expectNoScjwt(set, cookieName);
    const old = await harness.createClient().post('/api/auth/sign-in/email', {
      email: targetEmail,
      password: PASSWORD,
    });
    expect(old.status).toBe(401);
    const fresh = harness.createClient();
    const next = await fresh.post('/api/auth/sign-in/email', {
      email: targetEmail,
      password: NEW_PASSWORD,
    });
    expect(next.status).toBe(200);
    const nextToken = expectScjwt(next, cookieName);
    const removed = await adminClient.post('/api/auth/admin/remove-user', {
      userId: targetId,
    });
    expect(removed.status).toBe(200);
    expectNoScjwt(removed, cookieName);
    expect((await harness.getWithToken('/me', nextToken)).status).toBe(401);
    expect(
      (await adminClient.get(`/api/auth/admin/get-user?id=${targetId}`)).status,
    ).toBe(404);
  });
});
