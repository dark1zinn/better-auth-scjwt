import type { TokenPlacement } from "./types.ts";

export const PLUGIN_ID = "scjwt" as const;

export const DEFAULT_COOKIE_NAME = "auth-token";
export const DEFAULT_TOKEN_PLACEMENT: TokenPlacement = "cookie";
export const DEFAULT_EXPIRES_IN_SECONDS = 3600;
export const DEFAULT_SLIDING_SESSION = false;

/** Refresh JWT when remaining lifetime is at or below this fraction of `expiresInSeconds`. */
export const SLIDING_THRESHOLD_RATIO = 0.2;
