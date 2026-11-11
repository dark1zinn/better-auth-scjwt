import type { FingerprintMode, TokenPlacement } from "./types";

export const PLUGIN_ID = "scjwt" as const;
export const FINALIZER_PLUGIN_ID = "scjwt-session-finalizer" as const;
/** Better Auth's native `Authorization` transport; mutually exclusive with SCJWT. */
export const BEARER_PLUGIN_ID = "bearer" as const;
/**
 * Lifetime Better Auth gives `rememberMe: false` sessions regardless of
 * `session.expiresIn` (`internalAdapter.createSession`); such sessions never refresh.
 */
export const NONPERSISTENT_SESSION_SECONDS: number = 60 * 60 * 24;
export const DEFAULT_TOKEN_PLACEMENT: TokenPlacement = "cookie";
export const DEFAULT_FINGERPRINT_MODE: FingerprintMode = "strict";
