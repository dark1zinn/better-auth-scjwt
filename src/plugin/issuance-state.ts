export interface ScjwtIssuanceState {
	token: string;
}

const ISSUANCE_STATE_KEY = "scjwtIssuance";

export function setIssuanceToken(
	context: Record<string, unknown>,
	token: string,
): void {
	context[ISSUANCE_STATE_KEY] = { token } satisfies ScjwtIssuanceState;
}

export function getIssuanceToken(
	context: Record<string, unknown>,
): string | undefined {
	const state = context[ISSUANCE_STATE_KEY] as ScjwtIssuanceState | undefined;
	return state?.token;
}
