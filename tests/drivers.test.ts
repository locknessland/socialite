/**
 * Tests for @lockness/socialite - Official Drivers (Google, GitHub, Discord)
 */

import { describe, it } from '@std/testing/bdd'
import { expect } from '@std/expect'
import {
    DiscordDriver,
    GitHubDriver,
    GoogleDriver,
    type ProviderConfig,
} from '../mod.ts'

describe('GoogleDriver', () => {
    const config: ProviderConfig = {
        clientId: 'google-client-id',
        clientSecret: 'google-client-secret',
        redirectUri: 'http://localhost:3000/auth/google/callback',
    }

    it('generates correct auth URL', () => {
        const driver = new GoogleDriver(config)
        const url = driver.getAuthUrl()

        expect(url).toContain('https://accounts.google.com/o/oauth2/v2/auth')
        expect(url).toContain('client_id=google-client-id')
        expect(url).toContain(
            'redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fgoogle%2Fcallback',
        )
        expect(url).toContain('response_type=code')
        expect(url).toContain('scope=openid+email+profile')
        expect(url).toContain('access_type=offline')
    })

    it('includes state in auth URL when provided', () => {
        const driver = new GoogleDriver(config)
        const url = driver.getAuthUrl('test-state-123')

        expect(url).toContain('state=test-state-123')
    })

    it('uses custom scopes when provided', () => {
        const customConfig = {
            ...config,
            scopes: ['openid', 'email'],
        }
        const driver = new GoogleDriver(customConfig)
        const url = driver.getAuthUrl()

        expect(url).toContain('scope=openid+email')
        expect(url).not.toContain('profile')
    })

    it('redirect returns 302 response', () => {
        const driver = new GoogleDriver(config)
        const response = driver.redirect()

        expect(response.status).toBe(302)
        expect(response.headers.get('Location')).toContain(
            'https://accounts.google.com',
        )
    })
})

describe('GitHubDriver', () => {
    const config: ProviderConfig = {
        clientId: 'github-client-id',
        clientSecret: 'github-client-secret',
        redirectUri: 'http://localhost:3000/auth/github/callback',
    }

    it('generates correct auth URL', () => {
        const driver = new GitHubDriver(config)
        const url = driver.getAuthUrl()

        expect(url).toContain('https://github.com/login/oauth/authorize')
        expect(url).toContain('client_id=github-client-id')
        expect(url).toContain('scope=read%3Auser+user%3Aemail')
    })

    it('redirect returns 302 response', () => {
        const driver = new GitHubDriver(config)
        const response = driver.redirect()

        expect(response.status).toBe(302)
        expect(response.headers.get('Location')).toContain('https://github.com')
    })
})

describe('DiscordDriver', () => {
    const config: ProviderConfig = {
        clientId: 'discord-client-id',
        clientSecret: 'discord-client-secret',
        redirectUri: 'http://localhost:3000/auth/discord/callback',
    }

    it('generates correct auth URL', () => {
        const driver = new DiscordDriver(config)
        const url = driver.getAuthUrl()

        expect(url).toContain('https://discord.com/api/oauth2/authorize')
        expect(url).toContain('client_id=discord-client-id')
        expect(url).toContain('scope=identify+email')
    })

    it('redirect returns 302 response', () => {
        const driver = new DiscordDriver(config)
        const response = driver.redirect()

        expect(response.status).toBe(302)
        expect(response.headers.get('Location')).toContain(
            'https://discord.com',
        )
    })
})
