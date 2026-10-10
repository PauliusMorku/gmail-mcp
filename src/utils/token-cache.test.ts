import {
	afterEach, describe, expect, test, vi,
} from 'vitest';
import {isTokenValid} from './token-cache.js';

function mockGoogle(tokeninfo: Record<string, unknown>, email = 'me@gmail.com') {
	vi.stubGlobal('fetch', vi.fn(async (url: string) => {
		const body = url.includes('tokeninfo') ? tokeninfo : {emailAddress: email};
		return new Response(JSON.stringify(body), {status: 200});
	}));
}

afterEach(() => {
	vi.unstubAllGlobals();
});

describe('isTokenValid policy', () => {
	test('accepts matching audience and mailbox', async () => {
		mockGoogle({expires_in: 3600, aud: 'client-1'}, 'Me@Gmail.com');
		expect(await isTokenValid('t1', {audience: 'client-1', allowedEmails: ['me@gmail.com']})).toBe(true);
	});

	test('rejects token issued to another client', async () => {
		mockGoogle({expires_in: 3600, aud: 'other'});
		expect(await isTokenValid('t2', {audience: 'client-1'})).toBe(false);
	});

	test('rejects other mailbox', async () => {
		mockGoogle({expires_in: 3600, aud: 'client-1'}, 'stranger@gmail.com');
		expect(await isTokenValid('t3', {audience: 'client-1', allowedEmails: ['me@gmail.com']})).toBe(false);
	});

	test('caches rejection', async () => {
		mockGoogle({expires_in: 3600, aud: 'other'});
		await isTokenValid('t4', {audience: 'client-1'});
		mockGoogle({expires_in: 3600, aud: 'client-1'});
		expect(await isTokenValid('t4', {audience: 'client-1'})).toBe(false);
	});

	test('no policy keeps old behaviour', async () => {
		mockGoogle({expires_in: 3600, aud: 'anything'});
		expect(await isTokenValid('t5')).toBe(true);
	});
});
