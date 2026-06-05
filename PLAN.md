# Comprehensive Technical Specification: better-auth-csjwt

This document defines the architectural blueprint, structural constraints, and implementation mechanics for a custom plugin compatible with the `better-auth` ecosystem. This plugin implements a high-security, state-backed, device-fingerprinted hybrid authentication pattern named **Session-Centric JWT (CSJWT)**.

---

## 1. Architectural Blueprint & Core Invariants

Standard JWT solutions delegate the ultimate source of truth directly to a stateless, cryptographically signed token. This introduces significant lag or structural complexity when handling immediate, omni-channel token revocation. 

The `better-auth-csjwt` plugin overrides this behavior by combining the portability of a signed JSON Web Token with the absolute, deterministic state tracking of a database session repository.

### 1.1 Core Invariants
* **Database as the Sole Source of Truth:** The JWT is strictly an un-queryable, tamper-proof pointer to an explicit database primary key row (`session.id`).
* **Cryptographic Device Binding:** Every issued token embeds a physical deterministic hardware signature ($fp$). If a request contains a valid signature but exhibits a fingerprint mismatch, the token is flagged as compromised.
* **Instant, Aggressive Poisoning (Fail-Closed):** Upon fingerprint mismatch detection, the plugin triggers an immediate side-effect: the referenced database session is deleted instantly, and the current request execution pipeline terminates with a `419` or `401 Unauthorized` state.

---

## 2. Token Layout & Structural Mapping

The generated JWT payload must conform exactly to the following strict schema layout. No database properties or user demographic info are allowed within the payload to ensure absolute visual opacity.

### 2.1 JSON Schema Schema Definition
```json
{
  "$schema": "[https://json-schema.org/draft/2020-12/schema](https://json-schema.org/draft/2020-12/schema)",
  "title": "CentricJWTSessionPayload",
  "type": "object",
  "properties": {
    "iss": {
      "type": "string",
      "description": "Fully qualified URL of the token issuer authority."
    },
    "sub": {
      "type": "string",
      "pattern": "^user:[a-zA-Z0-9_\\-]+$",
      "description": "Namespace-prefixed identifier mapping back to the user identity record."
    },
    "fp": {
      "type": "string",
      "pattern": "^[a-f0-9]{64}$",
      "description": "Deterministic SHA-256 hex digest representing client network/device constraints."
    },
    "iat": {
      "type": "integer",
      "description": "Unix epoch timestamp designating token generation runtime."
    },
    "exp": {
      "type": "integer",
      "description": "Unix epoch timestamp dictating strict cryptographic death."
    },
    "sid": {
      "type": "string",
      "description": "The exact database primary key identifying the tracking session row."
    }
  },
  "required": ["iss", "sub", "fp", "iat", "exp", "sid"],
  "additionalProperties": false
}
```

### 2.2 Concrete Mapping Dictionary

- `iss`: Value extracted directly from plugin configuration parameters (`options.issuer`).
    
- `sub`: Literal template string `user:${session.userId}`.
    
- `fp`: Hex output of `SHA-256(JSON.stringify({ ip, ua, platform }))`.
    
- `sid`: The exact `session.id` string yielded by the underlying `better-auth` database adapter.
    

## 3. Configuration & Interface API Design

The plugin must expose a clean, strongly typed factory function adhering to the standard `BetterAuthPlugin` typing specifications.

### 3.1 TypeScript Definitions

```ts
import { BetterAuthPlugin } from "better-auth";

export interface CentricJwtOptions {
  /**
   * Cryptographic key used to sign and verify HS256 JWT tokens.
   */
  jwtSecret: string;
  /**
   * The explicit string asserting authority over token issuance (e.g., '[https://api.domain.com](https://api.domain.com)').
   */
  issuer: string;
  /**
   * Window of structural validity for the cryptographic envelope in seconds. Defaults to 3600.
   */
  expiresInSeconds?: number;
  /**
   * String identifier mapping the HTTP-Only cookie key name. Defaults to 'centric_session_jwt'.
   */
  cookieName?: string;
  /**
   * Dictates the network boundary strategy utilized for transport execution.
   * 'cookie' -> Enforces HTTP-Only, Secure, SameSite=Lax headers.
   * 'header' -> Appends to Authorization headers and exposes CORS validation vectors.
   * @default "cookie"
   */
  tokenPlacement?: "cookie" | "header";
}

export declare const centricJwtSession: (options: CentricJwtOptions) => BetterAuthPlugin;
```

## 4. Lifecycle Hook Mechanics & Execution Pipeline

The runtime environment handles requests through two distinct phases: intercepting creation vectors (`hooks.after`) and intercepting authorization sweeps (`onRequest`).

### 4.1 Token Issuance Loop (`hooks.after`)

This interceptor hooks execution after standard authentication pathways (`/sign-in/*`, `/sign-up/*`) complete processing and have successfully committed an active session tracking record to the storage adapter layer.

```
[Authentication Success]
         │
         ▼
Extract Context (session.id, session.userId)
         │
         ▼
Compute Fingerprint (IP + User-Agent + Platform)
         │
         ▼
Calculate SHA-256 Hex Hash (fp)
         │
         ▼
Sign JWT (HS256) via jose Framework
         │
         ▼
Strip Default Opaque Better-Auth Cookies (Set-Cookie: clear)
         │
         ▼
┌─────────────────────────┴─────────────────────────┐
│ tokenPlacement === "cookie"                       │ tokenPlacement === "header"
▼                                                   ▼
Append HTTP-Only Cookie Header                      Set 'Authorization: Bearer <JWT>'
Max-Age, Secure, SameSite=Lax                       Expose Headers via CORS Policy
└─────────────────────────┬─────────────────────────┘
         │
         ▼
[Return Response to Client Context]
```

### 4.2 Gateway Guard Loop (`onRequest`)

This interceptor intercepts **every** incoming network transaction handled by the host endpoint architecture before internal routing patterns or resource layers compute business logic.

```
[Incoming Request Processed]
         │
         ▼
┌─────────────────────────┴─────────────────────────┐
│ Configured Mode: "cookie"                          │ Configured Mode: "header"
▼                                                   ▼
Extract value from cookieName                       Extract value from 'Authorization' Header
└─────────────────────────┬─────────────────────────┘
         │
         ▼
Token Found? ───[ No ]───> [Exit Interceptor: Fall Through to Standard Handling]
         │
       [ Yes ]
         │
         ▼
Execute jose.jwtVerify() Signature Check using options.jwtSecret
         │
         ├─► [Signature/Exp Failure] ───► Throw APIError("UNAUTHORIZED")
         │
         ▼
Extract Claims payload: { sid, fp, sub }
         │
         ▼
Gather Current Request Context Attributes (IP, UA, Platform)
         │
         ▼
Compute currentFpHash = SHA-256(Current Attributes)
         │
         ▼
Does currentFpHash === payload.fp?
         │
       ├───[ No: Token Compromised ]
         │         │
         │         ▼
         │   Execute Database Command: adapter.delete("session", where id == payload.sid)
         │         │
         │         ▼
         │   Throw APIError("UNAUTHORIZED", "Machine fingerprint mismatch. Session revoked.")
         │
       [ Yes ]
         │
         ▼
Query Storage: adapter.findOne("session", where id == payload.sid)
         │
         ├─► [Row Missing / Session Dead] ───► Throw APIError("UNAUTHORIZED")
         │
         ▼
Map Context: Assign database session record to context.session object
         │
         ▼
[Exit Interceptor: Request Cleared to Continue Seamless Downstream Pipeline]
```

## 5. Security Fail-Safes & Edge Cases

An implementing engine or agent must explicitly verify and test code logic compliance against the following edge cases:

- **Header Stripping Proximity:** When operating in `cookie` placement mode, any pre-existing cookie strings injected by the base layers of `better-auth` must be parsed out and completely omitted from output headers during execution tracking hooks. This forces clients to carry only the highly secure `centric_session_jwt` token.
    
- **Context Resolution Bridging:** Setting `context.session = dbSession` during the pipeline sequence ensures compatibility with other native plugins or core application APIs (like calling `auth.api.getSession()`). This mapping prevents downstream plugins from failing due to empty context assumptions.
    
- **Graceful Failure Fall-Through:** If the extraction phase returns no tokens from headers or cookies, the pipeline must exit smoothly using a clear return statement without throwing errors. This allows non-authenticated public routes (e.g., viewing public documentation or pricing pages) to render correctly.