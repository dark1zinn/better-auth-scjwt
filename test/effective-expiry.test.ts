import { describe, expect, test } from "bun:test";
import {
	computeJwtExpiresInSeconds,
	getEffectiveExpirySeconds,
	isPastEffectiveExpiry,
	sessionExpiresAtToSeconds,
} from "../src/plugin/effective-expiry";

describe("sessionExpiresAtToSeconds", () => {
	test("converts Date to Unix seconds", () => {
		const date = new Date("2026-01-15T12:00:00.000Z");
		expect(sessionExpiresAtToSeconds(date)).toBe(
			Math.floor(date.getTime() / 1000),
		);
	});
});

describe("getEffectiveExpirySeconds", () => {
	const jwtExp = 1_800_000_000;

	test("uses JWT exp when database expires later", () => {
		const dbLater = new Date((jwtExp + 3600) * 1000);
		expect(getEffectiveExpirySeconds(jwtExp, dbLater)).toBe(jwtExp);
	});

	test("uses database exp when it expires sooner", () => {
		const dbSooner = new Date((jwtExp - 1800) * 1000);
		expect(getEffectiveExpirySeconds(jwtExp, dbSooner)).toBe(jwtExp - 1800);
	});

	test("returns the same value when aligned", () => {
		const aligned = new Date(jwtExp * 1000);
		expect(getEffectiveExpirySeconds(jwtExp, aligned)).toBe(jwtExp);
	});
});

describe("isPastEffectiveExpiry", () => {
	const jwtExp = 1_000_000;
	const dbExp = 1_000_500;

	test("returns false before effective expiry", () => {
		expect(
			isPastEffectiveExpiry(jwtExp, new Date(dbExp * 1000), jwtExp - 1),
		).toBe(false);
	});

	test("returns true at effective expiry boundary", () => {
		expect(isPastEffectiveExpiry(jwtExp, new Date(dbExp * 1000), jwtExp)).toBe(
			true,
		);
	});

	test("returns true when database expiry is sooner and has passed", () => {
		expect(
			isPastEffectiveExpiry(jwtExp, new Date(dbExp * 1000), dbExp),
		).toBe(true);
	});
});

describe("computeJwtExpiresInSeconds", () => {
	const issuedAt = 1_000_000;
	const configuredTtl = 3600;

	test("returns configured TTL when session outlives it", () => {
		const sessionExpiresAt = new Date((issuedAt + 7200) * 1000);
		expect(
			computeJwtExpiresInSeconds(issuedAt, configuredTtl, sessionExpiresAt),
		).toBe(3600);
	});

	test("caps TTL to remaining session lifetime", () => {
		const sessionExpiresAt = new Date((issuedAt + 1800) * 1000);
		expect(
			computeJwtExpiresInSeconds(issuedAt, configuredTtl, sessionExpiresAt),
		).toBe(1800);
	});

	test("returns zero when session is already expired", () => {
		const sessionExpiresAt = new Date((issuedAt - 60) * 1000);
		expect(
			computeJwtExpiresInSeconds(issuedAt, configuredTtl, sessionExpiresAt),
		).toBe(0);
	});
});
