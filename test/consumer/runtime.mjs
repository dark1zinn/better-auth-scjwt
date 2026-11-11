// Runs inside a temporary project that installed the packed tarball; see scripts/check-package.ts.
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { scjwt } from "better-auth-scjwt";
import { scjwtClient } from "better-auth-scjwt/client";

const BASE_URL = "http://localhost:3000";
const runtime = typeof Bun === "undefined" ? `node ${process.version}` : `bun ${Bun.version}`;

const auth = betterAuth({
	database: memoryAdapter({ user: [], session: [], account: [], verification: [] }),
	baseURL: BASE_URL,
	secret: "packed-consumer-secret-at-least-32-bytes",
	emailAndPassword: { enabled: true },
	plugins: [scjwt({ tokenPlacement: "header" })],
});
const headers = { "content-type": "application/json", "user-agent": "packed-consumer" };
const email = "packed-consumer@example.com";

const signUp = await auth.handler(
	new Request(`${BASE_URL}/api/auth/sign-up/email`, {
		method: "POST",
		headers,
		body: JSON.stringify({ name: "Packed", email, password: "correct-horse-battery-staple" }),
	}),
);
const token = signUp.headers.get("set-auth-token");
if (signUp.status !== 200 || token?.split(".").length !== 3) {
	throw new Error(`[${runtime}] sign-up did not issue an SCJWT (status ${signUp.status})`);
}
const session = await auth.handler(
	new Request(`${BASE_URL}/api/auth/get-session`, {
		headers: { ...headers, authorization: `Bearer ${token}` },
	}),
);
const body = await session.json();
if (body?.user?.email !== email) {
	throw new Error(`[${runtime}] the issued SCJWT did not authenticate`);
}
if (scjwtClient().id !== "scjwt") {
	throw new Error(`[${runtime}] the client entrypoint did not load`);
}
console.log(`packed consumer runtime ok (${runtime})`);
