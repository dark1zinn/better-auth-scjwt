import type { FingerprintMode, TokenPlacement } from "./types";

export const PLUGIN_ID = "scjwt" as const;
export const FINALIZER_PLUGIN_ID = "scjwt-session-finalizer" as const;
export const DEFAULT_TOKEN_PLACEMENT: TokenPlacement = "cookie";
export const DEFAULT_FINGERPRINT_MODE: FingerprintMode = "strict";
