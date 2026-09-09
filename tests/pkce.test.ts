/**
 * PKCE (RFC 7636, S256) for the socialite OAuth flow (#243).
 *
 * redirect() must send a code_challenge (S256) and carry the matching verifier
 * in an HttpOnly cookie; user() must forward the verifier to the token exchange
 * and fail closed when a PKCE driver's verifier cookie is absent; a
 * usesPkce=false driver must behave exactly as before PKCE.
 *
 * @module @lockness/socialite/tests/pkce
 */

import { describe, it } from '@std/testing/bdd'
import { expect } from '@std/expect'
import { encodeBase64Url } from '@std/encoding/base64url'
import {
    BaseOAuth2Driver,
    type OAuthTokens,
    pkceChallenge,
    type ProviderConfig,
    type SocialUser,
} from '../mod.ts'
import type { Context } from 'hono'

/** Run `fn` with env vars temporarily set (undefined = deleted), then restore. */
function withEnv(vars: Record<string, string | undefined>, fn: () => void) {
    const prev: Record<string, string | undefined> = {}
    for (const k of Object.keys(vars)) {
        prev[k] = Deno.env.get(k)
        const v = vars[k]
        if (v === undefined) Deno.env.delete(k)
        else Deno.env.set(k, v)
    }
    try {
        fn()
    } finally {
        for (const k of Object.keys(prev)) {
            const v = prev[k]
            if (v === undefined) Deno.env.delete(k)
            else Deno.env.set(k, v)
        }
    }
}

const config: ProviderConfig = {
    clientId: 'id',
    clientSecret: 'secret',
    redirectUri: 'http://localhost:3000/auth/test/callback',
}

const fakeUser: SocialUser = {
    id: '1',
    email: 'a@b.c',
    name: 'A',
    avatar: null,
    accessToken: 'tok',
    refreshToken: null,
    expiresIn: null,
    raw: {},
}

/** PKCE-on driver (default) that records the verifier `getTokens` received. */
class PkceDriver extends BaseOAuth2Driver {
    protected authUrl = 'https://provider.test/auth'
    protected tokenUrl = 'https://provider.test/token'
    protected userInfoUrl = 'https://provider.test/user'
    protected defaultScopes = ['openid']
    seenVerifier: string | null = null
    override getTokens(
        _code: string,
        codeVerifier?: string,
    ): Promise<OAuthTokens> {
        this.seenVerifier = codeVerifier ?? null
        return Promise.resolve({ access_token: 'tok' } as OAuthTokens)
    }
    getUserFromTokens(): Promise<SocialUser> {
        return Promise.resolve(fakeUser)
    }
}

/** Capability opt-out driver. */
class NoPkceDriver extends PkceDriver {
    protected override usesPkce = false
}

/** A driver using the BASE getTokens, to exercise its body assembly. */
class BaseTokensDriver extends BaseOAuth2Driver {
    protected authUrl = 'https://provider.test/auth'
    protected tokenUrl = 'https://provider.test/token'
    protected userInfoUrl = 'https://provider.test/user'
    protected defaultScopes = ['openid']
    getUserFromTokens(): Promise<SocialUser> {
        return Promise.resolve(fakeUser)
    }
}

function callbackCtx(
    query: Record<string, string>,
    cookie?: string,
): Context {
    return {
        req: {
            query: (k: string) => query[k],
            header: (k: string) =>
                k.toLowerCase() === 'cookie' ? cookie : undefined,
        },
    } as unknown as Context
}

/** The verifier cookie's "name=value" from a redirect() response, or ''. */
function verifierCookie(res: Response): string {
    for (const c of res.headers.getSetCookie()) {
        if (/pkce_verifier=/.test(c)) return c.split(';')[0]
    }
    return ''
}

describe('OAuth PKCE (#243)', () => {
    it('redirect() sends an S256 challenge + a verifier cookie that hashes to it', async () => {
        const res = new PkceDriver(config).redirect()

        const cookie = verifierCookie(res)
        const verifier = cookie.split('=')[1] ?? ''
        expect(verifier.length).toBeGreaterThanOrEqual(43)
        expect(verifier).not.toContain('=') // base64url-unpadded

        const location = res.headers.get('Location') ?? ''
        expect(location).toContain('code_challenge_method=S256')

        // Independently derive the challenge (async global crypto, not the
        // implementation's digestSync) — no tautology.
        const digest = await crypto.subtle.digest(
            'SHA-256',
            new TextEncoder().encode(verifier),
        )
        const expected = encodeBase64Url(new Uint8Array(digest))
        expect(location).toContain(`code_challenge=${expected}`)

        const raw =
            res.headers.getSetCookie().find((c) => /pkce_verifier=/.test(c)) ??
                ''
        expect(raw).toContain('HttpOnly')
        expect(raw).toContain('SameSite=Lax')
    })

    it('base getTokens includes code_verifier in the token body', async () => {
        const original = globalThis.fetch
        let body = ''
        globalThis.fetch = ((_u: unknown, init?: RequestInit) => {
            body = String(init?.body)
            return Promise.resolve(
                new Response(JSON.stringify({ access_token: 'tok' }), {
                    status: 200,
                    headers: { 'content-type': 'application/json' },
                }),
            )
        }) as typeof fetch
        try {
            await new BaseTokensDriver(config).getTokens(
                'the-code',
                'the-verif',
            )
            const params = new URLSearchParams(body)
            expect(params.get('code')).toBe('the-code')
            expect(params.get('code_verifier')).toBe('the-verif')
        } finally {
            globalThis.fetch = original
        }
    })

    it('user() forwards the verifier cookie to the token exchange', async () => {
        const driver = new PkceDriver(config)
        const vc = verifierCookie(driver.redirect()) // env-correct cookie name
        const ctx = callbackCtx(
            { code: 'abc', state: 'match' },
            `lockness_oauth_state=match; ${vc}`,
        )

        const u = await driver.user(ctx)
        expect(u.id).toBe('1')
        expect(driver.seenVerifier).toBe(vc.split('=')[1])
    })

    it('user() fails closed when PKCE is on but the verifier cookie is absent', async () => {
        const driver = new PkceDriver(config)
        const ctx = callbackCtx(
            { code: 'abc', state: 'match' },
            'lockness_oauth_state=match',
        )
        await expect(driver.user(ctx)).rejects.toThrow(/verifier/i)
        expect(driver.seenVerifier).toBeNull() // never reached the exchange
    })

    it('a usesPkce=false driver sends no challenge, no verifier cookie, no code_verifier', async () => {
        const driver = new NoPkceDriver(config)
        const res = driver.redirect()

        expect(res.headers.get('Location') ?? '').not.toContain(
            'code_challenge',
        )
        expect(
            res.headers.getSetCookie().some((c) => /pkce_verifier=/.test(c)),
        ).toBe(false)

        const ctx = callbackCtx(
            { code: 'abc', state: 'match' },
            'lockness_oauth_state=match',
        )
        const u = await driver.user(ctx)
        expect(u.id).toBe('1')
        expect(driver.seenVerifier).toBeNull() // getTokens got undefined
    })

    it('the verifier cookie is __Host- prefixed and Secure outside development', () => {
        withEnv({ DENO_ENV: undefined, APP_ENV: undefined }, () => {
            const raw = new PkceDriver(config).redirect().headers.getSetCookie()
                .find((c) => /pkce_verifier=/.test(c)) ?? ''
            expect(raw.startsWith('__Host-')).toBe(true)
            expect(raw).toContain('Secure')
            expect(raw).toContain('Path=/')
        })
    })

    it('in explicit development the verifier cookie is unprefixed and not Secure', () => {
        withEnv({ DENO_ENV: 'development', APP_ENV: undefined }, () => {
            const raw = new PkceDriver(config).redirect().headers.getSetCookie()
                .find((c) => /pkce_verifier=/.test(c)) ?? ''
            expect(raw.startsWith('lockness_pkce_verifier=')).toBe(true)
            expect(raw).not.toContain('Secure')
        })
    })

    it('pkceChallenge matches the RFC 7636 Appendix B S256 vector', () => {
        // RFC 7636 Appendix B: verifier → challenge.
        expect(pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'))
            .toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
    })

    it('user() does not echo the verifier when the token exchange fails (FR-009)', async () => {
        class ThrowingDriver extends PkceDriver {
            override getTokens(
                _code: string,
                codeVerifier?: string,
            ): Promise<OAuthTokens> {
                this.seenVerifier = codeVerifier ?? null
                return Promise.reject(new Error('provider rejected the code'))
            }
        }
        const driver = new ThrowingDriver(config)
        const vc = verifierCookie(driver.redirect())
        const verifier = vc.split('=')[1] ?? ''
        const ctx = callbackCtx(
            { code: 'abc', state: 'match' },
            `lockness_oauth_state=match; ${vc}`,
        )
        let message = ''
        try {
            await driver.user(ctx)
        } catch (e) {
            message = (e as Error).message
        }
        // The exchange failed (the verifier reached getTokens) …
        expect(driver.seenVerifier).toBe(verifier)
        expect(message).toContain('provider rejected the code')
        // … and the failure never leaked the verifier value.
        expect(message).not.toContain(verifier)
    })

    it('user() fails closed when the verifier cookie is present but empty', async () => {
        const driver = new PkceDriver(config)
        const name = verifierCookie(driver.redirect()).split('=')[0]
        const ctx = callbackCtx(
            { code: 'abc', state: 'match' },
            `lockness_oauth_state=match; ${name}=`,
        )
        await expect(driver.user(ctx)).rejects.toThrow(/verifier/i)
        expect(driver.seenVerifier).toBeNull()
    })
})
