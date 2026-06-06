import type { AuthContext } from "better-auth";

export const DATABASE_REQUIRED_ERROR =
	"[scjwt] database adapter is required; stateless mode is not supported.";

export function assertDatabaseConfigured(context: AuthContext): void {
	if (context.options.database === undefined) {
		throw new Error(DATABASE_REQUIRED_ERROR);
	}
}

export function createDatabaseRequiredInit() {
	return (context: AuthContext): void => {
		assertDatabaseConfigured(context);
	};
}
