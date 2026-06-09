### A Session-Centric JWT (or Stateful JWT) is a hybrid authentication model. It uses JSON Web Tokens for client-side API statelessness, but pairs them with server-side session tracking (like Redis or a database) to retain the security and control advantages of traditional session-based auth.

## Why Use a Hybrid Approach?

Pure "stateless JWTs" have a major flaw: inability to be revoked. If a token is stolen, the server has no way to invalidate it before it expires. Session-centric JWTs solve this by tracking key session data on the server.

## How It Works

- **Initial Login:** The server validates credentials and generates a short-lived Access Token (JWT) and a unique session_id.

- **Payload State:** The JWT payload contains standard claims along with the specific session_id and a version identifier.

- **Request Validation:** With every API call, the server decodes the JWT and queries its server-side cache (e.g., Redis) to check if the session is still active and valid.

- **Revocation:** If a user logs out, their password gets compromised, or the device is lost, the server deletes that session_id from the cache. The next API request using the associated JWT is immediately rejected.

## Architecture Comparison

| Feature     | Traditional Stateless JWT                      | Traditional Session                  | Session-Centric JWT                                  |
|-------------|------------------------------------------------|--------------------------------------|------------------------------------------------------|
| Revocation  | Impossible (must wait for expiration)          | Instant (delete from server)         | Instant (remove session ID from server)              |
| Scalability | High (no database hits for every request)      | Medium (requires shared state across servers) | High (JWT carries the bulk of data; Redis cache keeps checks fast) |
| Security    | Low (risk of stolen tokens)                    | High (server manages state)          | High (best of both worlds)                           |

For a visual breakdown of how stateless (pure JWT) and stateful (session) authentications differ in their routing and flow: https://www.youtube.com/watch?v=fyTxwIa-1U0

## Revoke path audit

Better Auth session revocation vs SCJWT invalidation: [REVOKE_AUDIT.md](./REVOKE_AUDIT.md)

## Learn more

- [Why pure JWTs are dangerous and how to pair it with sessions for security](https://redis.io/blog/json-web-tokens-jwt-are-dangerous-for-user-sessions/)
- [A robust authentication system](https://dev.to/titre123/creating-a-robust-authentication-system-harnessing-the-power-of-jwt-and-session-authentication-2efc)
- [Maintaining a session using JWT](https://medium.com/@hafizsheetab/maintaining-a-session-for-your-restful-apis-using-jwt-and-redis-a3a4aff6b470)
