/**
 * Subset of Better Auth `context.authCookies` needed to identify native cookies.
 */
export interface BetterAuthCookies {
	sessionToken: { name: string };
	sessionData: { name: string };
	dontRememberToken: { name: string };
	accountData: { name: string };
}

/**
 * Collects native Better Auth cookie names that should be omitted when issuing SCJWT.
 */
export function collectBetterAuthCookieNames(
	authCookies: BetterAuthCookies,
): ReadonlySet<string> {
	return new Set([
		authCookies.sessionToken.name,
		authCookies.sessionData.name,
		authCookies.dontRememberToken.name,
		authCookies.accountData.name,
	]);
}

/**
 * Removes native Better Auth session cookies from response `Set-Cookie` headers.
 */
export function stripBetterAuthCookiesFromHeaders(
	headers: Headers,
	authCookies: BetterAuthCookies,
): void {
	const stripNames = collectBetterAuthCookieNames(authCookies);
	const setCookies = getSetCookieValues(headers);

	if (setCookies.length === 0) {
		return;
	}

	headers.delete("set-cookie");

	for (const setCookie of setCookies) {
		const name = getSetCookieName(setCookie);
		if (!name || shouldStripCookieName(name, stripNames)) {
			continue;
		}

		headers.append("set-cookie", setCookie);
	}
}

/**
 * Returns a new `Response` with native Better Auth session cookies stripped.
 */
export function stripBetterAuthCookiesFromResponse(
	response: Response,
	authCookies: BetterAuthCookies,
): Response {
	const headers = new Headers(response.headers);
	stripBetterAuthCookiesFromHeaders(headers, authCookies);

	return new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers,
	});
}

function getSetCookieValues(headers: Headers): string[] {
	if (typeof headers.getSetCookie === "function") {
		return headers.getSetCookie();
	}

	const combined = headers.get("set-cookie");
	if (!combined) {
		return [];
	}

	return splitSetCookieHeader(combined);
}

/**
 * Splits a combined `Set-Cookie` header value into individual cookie strings.
 * Handles comma-separated headers where commas appear only between cookies.
 */
function splitSetCookieHeader(setCookie: string): string[] {
	const result: string[] = [];
	let start = 0;

	for (let i = 0; i < setCookie.length; i++) {
		if (setCookie[i] !== ",") {
			continue;
		}

		let j = i + 1;
		while (j < setCookie.length && setCookie[j] === " ") {
			j++;
		}

		while (
			j < setCookie.length &&
			setCookie[j] !== "=" &&
			setCookie[j] !== ";" &&
			setCookie[j] !== ","
		) {
			j++;
		}

		if (j < setCookie.length && setCookie[j] === "=") {
			const part = setCookie.slice(start, i).trim();
			if (part) {
				result.push(part);
			}
			start = i + 1;
			while (start < setCookie.length && setCookie[start] === " ") {
				start++;
			}
			i = start - 1;
		}
	}

	const last = setCookie.slice(start).trim();
	if (last) {
		result.push(last);
	}

	return result;
}

function getSetCookieName(setCookie: string): string | null {
	const [nameValue] = setCookie.split(";");
	const trimmed = nameValue?.trim();
	if (!trimmed) {
		return null;
	}

	const separatorIndex = trimmed.indexOf("=");
	if (separatorIndex === -1) {
		return null;
	}

	return trimmed.slice(0, separatorIndex).trim();
}

function shouldStripCookieName(
	name: string,
	stripNames: ReadonlySet<string>,
): boolean {
	if (stripNames.has(name)) {
		return true;
	}

	for (const baseName of stripNames) {
		if (!name.startsWith(`${baseName}.`)) {
			continue;
		}

		const suffix = name.slice(baseName.length + 1);
		if (/^\d+$/.test(suffix)) {
			return true;
		}
	}

	return false;
}
