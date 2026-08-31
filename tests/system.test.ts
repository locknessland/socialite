/**
 * Tests for @lockness/socialite - System & Custom Drivers
 */

import { afterEach, beforeEach, describe, it } from '@std/testing/bdd'
import { expect } from '@std/expect'
import {
    BaseOAuth2Driver,
    configureSocialite,
    generateState,
    getSocialiteConfig,
    type OAuthTokens,
    type ProviderConfig,
    registerSocialiteDriver,
    socialite,
    type SocialUser,
} from '../mod.ts'

describe('socialite system', () => {
    const mockConfig: ProviderConfig = {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:3000/auth/callback',
    }

    beforeEach(() => {
        // Reset config before each test
        configureSocialite({})
    })

    afterEach(() => {
        configureSocialite({})
    })

    it('configureSocialite sets up providers', () => {
        configureSocialite({
            google: mockConfig,
            github: mockConfig,
        })

        const config = getSocialiteConfig()
        expect(config.google).toBeDefined()
        expect(config.github).toBeDefined()
        expect(config.google?.clientId).toBe('test-client-id')
    })

    it('socialite throws for unconfigured provider', () => {
        expect(() => socialite('google')).toThrow(
            'Socialite provider "google" is not configured',
        )
    })

    it('socialite returns driver for configured provider', () => {
        configureSocialite({ google: mockConfig })

        const driver = socialite('google')
        expect(driver).toBeDefined()
        expect(driver.redirect).toBeDefined()
        expect(driver.user).toBeDefined()
    })

    it('socialite throws for unknown provider', () => {
        configureSocialite({ unknown: mockConfig })

        expect(() => socialite('unknown')).toThrow(
            'Unknown socialite provider "unknown"',
        )
    })

    it('generateState returns a UUID', () => {
        const state = generateState()
        expect(state).toMatch(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
        )
    })

    it('generateState returns unique values', () => {
        const state1 = generateState()
        const state2 = generateState()
        expect(state1).not.toBe(state2)
    })
})

describe('custom driver registration', () => {
    class CustomDriver extends BaseOAuth2Driver {
        protected authUrl = 'https://custom.example.com/oauth/authorize'
        protected tokenUrl = 'https://custom.example.com/oauth/token'
        protected userInfoUrl = 'https://custom.example.com/api/user'
        protected defaultScopes = ['profile']

        getUserFromTokens(tokens: OAuthTokens): Promise<SocialUser> {
            return Promise.resolve({
                id: 'custom-123',
                email: 'test@example.com',
                name: 'Test User',
                avatar: null,
                accessToken: tokens.access_token,
                refreshToken: null,
                expiresIn: null,
                raw: {},
            })
        }
    }

    it('registerSocialiteDriver adds custom driver', () => {
        registerSocialiteDriver('custom', CustomDriver)
        configureSocialite({
            custom: {
                clientId: 'custom-id',
                clientSecret: 'custom-secret',
                redirectUri: 'http://localhost:3000/auth/custom/callback',
            },
        })

        const driver = socialite('custom')
        expect(driver).toBeDefined()

        const url = driver.getAuthUrl()
        expect(url).toContain('https://custom.example.com/oauth/authorize')
    })
})
