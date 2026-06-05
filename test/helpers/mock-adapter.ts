import type { AuthContext } from "better-auth";

export type SessionUpdateCall = {
	model: string;
	where: Array<{ field: string; value: string }>;
	update: { expiresAt: Date };
};

/**
 * Minimal adapter stub that records `update` calls for unit tests.
 */
export function createMockAdapter() {
	const updates: SessionUpdateCall[] = [];

	const adapter = {
		update: async (args: SessionUpdateCall) => {
			updates.push(args);
		},
	} as AuthContext["adapter"];

	return { adapter, updates };
}
