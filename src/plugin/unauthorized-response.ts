import { APIError } from "better-auth/api";

export type OnRequestInterrupt = { response: Response };

export function interruptWithUnauthorized(
	message: string,
): OnRequestInterrupt {
	const error = APIError.from("UNAUTHORIZED", {
		code: "UNAUTHORIZED",
		message,
	});

	return {
		response: new Response(
			JSON.stringify({
				code: error.body?.code ?? "UNAUTHORIZED",
				message: error.message,
			}),
			{
				status: 401,
				headers: { "Content-Type": "application/json" },
			},
		),
	};
}
