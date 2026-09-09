/**
 * OAuth `state` (login-CSRF) enforcement for the base driver (M3, #169).
 *
 * redirect() must set a state cookie and echo the same state in the auth URL;
 * user() must reject a callback whose `state` is missing or does not match that
 * cookie, and proceed only when they match.
 *
 * @module @lockness/socialite/tests/state_csrf
 */

import { describe, it } from '@std/testing/bdd'
import { expect } from '@std/expect'
import {
    BaseOAuth2Driver,
    type OAuthTokens,
    type ProviderConfig,
    type SocialUser,
} from '../mod.ts'
import type { Context } from 'hono'

const config: ProviderConfig = {
    clientId: 'id',
    clientSecret: 'secret',
    redirectUri: 'http://localhost:3000/auth/test/callback',
}

/** A driver with the network calls stubbed, so user() flow is testable offline. */
class TestDriver extends BaseOAuth2Driver {
    protected authUrl = 'https://provider.test/auth'
    protected tokenUrl = 'https://provider.test/token'
    protected userInfoUrl = 'https://provider.test/user'
    protected defaultScopes = ['openid']
    // This suite isolates the `state` (login-CSRF) check; PKCE has its own suite
    // (pkce.test.ts), so disable PKCE here to keep the state flow uncoupled.
    protected override usesPkce = false
    override getTokens(_code: string): Promise<OAuthTokens> {
        return Promise.resolve({ access_token: 'tok' } as OAuthTokens)
    }
    getUserFromTokens(_tokens: OAuthTokens): Promise<SocialUser> {
        return Promise.resolve({
            id: '1',
            email: 'a@b.c',
            name: 'A',
            avatar: null,
            accessToken: 'tok',
            refreshToken: null,
            expiresIn: null,
            raw: {},
        })
    }
}

/** Build a minimal callback Context with the given query + optional cookie. */
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

/** Pull the state cookie value out of a redirect() response. */
function stateFromRedirect(res: Response): string {
    const setCookie = res.headers.get('Set-Cookie') ?? ''
    const m = setCookie.match(/lockness_oauth_state=([^;]+)/)
    return m ? m[1] : ''
}

describe('OAuth state enforcement (#169)', () => {
    it('redirect() sets a state cookie matching the state in the auth URL', () => {
        const res = new TestDriver(config).redirect()
        const cookieState = stateFromRedirect(res)
        expect(cookieState.length).toBeGreaterThan(0)
        const location = res.headers.get('Location') ?? ''
        expect(location).toContain(`state=${cookieState}`)
        const setCookie = res.headers.get('Set-Cookie') ?? ''
        expect(setCookie).toContain('HttpOnly')
        expect(setCookie).toContain('SameSite=Lax')
    })

    it('user() rejects when no state cookie is present', async () => {
        const driver = new TestDriver(config)
        const ctx = callbackCtx({ code: 'abc', state: 'anything' })
        await expect(driver.user(ctx)).rejects.toThrow(/state/i)
    })

    it('user() rejects when the returned state does not match the cookie', async () => {
        const driver = new TestDriver(config)
        const ctx = callbackCtx(
            { code: 'abc', state: 'attacker' },
            'lockness_oauth_state=victim',
        )
        await expect(driver.user(ctx)).rejects.toThrow(/state/i)
    })

    it('user() proceeds when the returned state matches the cookie', async () => {
        const driver = new TestDriver(config)
        const ctx = callbackCtx(
            { code: 'abc', state: 'match' },
            'lockness_oauth_state=match',
        )
        const user = await driver.user(ctx)
        expect(user.id).toBe('1')
    })
})
