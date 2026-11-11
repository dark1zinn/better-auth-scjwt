import { admin } from 'better-auth/plugins/admin';
import { defaultStatements } from 'better-auth/plugins/admin/access';
import {
  createNestAuthHarness,
  expectNoScjwt,
  expectScjwt,
  PASSWORD,
  sessionIdOf,
  type AuthClient,
  type ProfileHarness,
} from './support/nest-auth-harness.js';
import { rbacAdminOptions } from './support/plugin-fixtures.js';

interface UserRecord {
  id: string;
  role?: string;
  email: string;
}

describe('NestJS Admin RBAC profile', () => {
  let harness: ProfileHarness<[ReturnType<typeof admin>]>;
  let cookieName: string;
  let adminClient: AuthClient;
  let userClient: AuthClient;
  let adminId: string;
  let userId: string;
  let userToken: string;

  beforeAll(async () => {
    harness = await createNestAuthHarness({
      name: 'rbac',
      additionalPlugins: [admin(rbacAdminOptions)],
    });
    cookieName = harness.sessionCookieName;
    adminClient = harness.createClient();
    userClient = harness.createClient();
    const adminSignup = await adminClient.post('/api/auth/sign-up/email', {
      name: 'RBAC Admin',
      email: 'rbac-admin@example.com',
      password: PASSWORD,
    });
    expect(adminSignup.status).toBe(200);
    adminId = (adminSignup.body.user as UserRecord).id;
    await harness.context.internalAdapter.updateUser(adminId, {
      role: 'admin',
    });
    expect((await adminClient.get('/me')).status).toBe(200);
    const userSignup = await userClient.post('/api/auth/sign-up/email', {
      name: 'RBAC User',
      email: 'rbac-user@example.com',
      password: PASSWORD,
    });
    expect(userSignup.status).toBe(200);
    userToken = expectScjwt(userSignup, cookieName);
    userId = (userSignup.body.user as UserRecord).id;
  });

  afterAll(async () => {
    await harness?.close();
  });

  async function permission(
    client: AuthClient,
    permissions: Record<string, string[]>,
  ) {
    return client.post('/api/auth/admin/has-permission', { permissions });
  }

  it('observes role changes through existing SCJWTs and keeps role changes session-free', async () => {
    const before = await permission(userClient, { project: ['read'] });
    expect(before.status).toBe(200);
    expect(before.body).toEqual({ error: null, success: false });
    const beforeSid = sessionIdOf(userToken);
    const sessionsBefore =
      await harness.context.internalAdapter.listSessions(userId);
    const changed = await adminClient.post('/api/auth/admin/set-role', {
      userId,
      role: 'auditor',
    });
    expect(changed.status).toBe(200);
    expectNoScjwt(changed, cookieName);
    expect(sessionIdOf(userToken)).toBe(beforeSid);
    expect(
      (await harness.context.internalAdapter.listSessions(userId)).length,
    ).toBe(sessionsBefore.length);
    const read = await permission(userClient, { project: ['read'] });
    expect(read.status).toBe(200);
    expect(read.body).toEqual({ error: null, success: true });
    for (const action of ['create', 'delete']) {
      const denied = await permission(userClient, { project: [action] });
      expect(denied.status).toBe(200);
      expect(denied.body).toEqual({ error: null, success: false });
    }
  });

  it('enforces auditor permissions on actual Admin mutations while admin retains them', async () => {
    const deniedRole = await userClient.post('/api/auth/admin/set-role', {
      userId: adminId,
      role: 'user',
    });
    expect(deniedRole.status).toBe(403);
    expectNoScjwt(deniedRole, cookieName);
    const deniedBan = await userClient.post('/api/auth/admin/ban-user', {
      userId: adminId,
    });
    expect(deniedBan.status).toBe(403);
    expectNoScjwt(deniedBan, cookieName);
    const deniedList = await userClient.get('/api/auth/admin/list-users');
    expect(deniedList.status).toBe(403);
    expectNoScjwt(deniedList, cookieName);

    const adminCreate = await adminClient.post('/api/auth/admin/create-user', {
      name: 'Created by Admin',
      email: 'rbac-created@example.com',
      password: PASSWORD,
    });
    expect(adminCreate.status).toBe(200);
    const permitted = await permission(adminClient, { project: ['create'] });
    expect(permitted.status).toBe(200);
    expect(permitted.body).toEqual({ error: null, success: true });
  });

  it('rejects unknown roles and leaves the user unchanged', async () => {
    const rejected = await adminClient.post('/api/auth/admin/set-role', {
      userId,
      role: 'superhero',
    });
    expect(rejected.status).toBe(400);
    expect(rejected.body.code).toBe(
      'YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE',
    );
    expectNoScjwt(rejected, cookieName);
    const user = await adminClient.get(`/api/auth/admin/get-user?id=${userId}`);
    expect(user.status).toBe(200);
    expect((user.body as UserRecord).role).toBe('auditor');
  });

  it('uses the standard Admin statements for the configured roles', async () => {
    expect(defaultStatements.user).toContain('set-role');
    expect(defaultStatements.session).toContain('revoke');
  });
});

describe('NestJS Admin RBAC profile with the Better Auth cookie cache', () => {
  let harness: ProfileHarness<[ReturnType<typeof admin>]>;

  beforeAll(async () => {
    harness = await createNestAuthHarness({
      name: 'rbac-cookie-cache',
      additionalPlugins: [admin(rbacAdminOptions)],
      session: { cookieCache: { enabled: true, maxAge: 300 } },
    });
  });

  afterAll(async () => {
    await harness?.close();
  });

  it('applies a live role downgrade without waiting for the cached snapshot to expire', async () => {
    const adminClient = harness.createClient();
    const adminSignup = await adminClient.post('/api/auth/sign-up/email', {
      name: 'Cache Admin',
      email: 'cache-admin@example.com',
      password: PASSWORD,
    });
    expect(adminSignup.status).toBe(200);
    await harness.context.internalAdapter.updateUser(
      (adminSignup.body.user as UserRecord).id,
      { role: 'admin' },
    );
    const userClient = harness.createClient();
    const userSignup = await userClient.post('/api/auth/sign-up/email', {
      name: 'Cache User',
      email: 'cache-user@example.com',
      password: PASSWORD,
    });
    expect(userSignup.status).toBe(200);
    const userId = (userSignup.body.user as UserRecord).id;
    const promoted = await adminClient.post('/api/auth/admin/set-role', {
      userId,
      role: 'auditor',
    });
    expect(promoted.status).toBe(200);

    const asAuditor = await userClient.get('/api/auth/get-session');
    expect(asAuditor.status).toBe(200);
    expect((asAuditor.body.user as UserRecord).role).toBe('auditor');
    // The client now holds a fresh snapshot that still says "auditor".
    expect(
      userClient.cookie(harness.context.authCookies.sessionData.name),
    ).toBeTruthy();

    const downgraded = await adminClient.post('/api/auth/admin/set-role', {
      userId,
      role: 'user',
    });
    expect(downgraded.status).toBe(200);
    const asUser = await userClient.get('/api/auth/get-session');
    expect((asUser.body.user as UserRecord).role).toBe('user');
    const read = await userClient.post('/api/auth/admin/has-permission', {
      permissions: { project: ['read'] },
    });
    expect(read.status).toBe(200);
    expect(read.body).toEqual({ error: null, success: false });
  });
});
