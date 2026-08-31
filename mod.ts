/**
 * Socialite - Social Authentication Module
 *
 * OAuth2/OIDC providers for social login (Google, GitHub, Discord, etc.)
 *
 * @example
 * ```typescript
 * // Configuration
 * configureSocialite({
 *     google: {
 *         clientId: Deno.env.get('GOOGLE_CLIENT_ID')!,
 *         clientSecret: Deno.env.get('GOOGLE_CLIENT_SECRET')!,
 *         redirectUri: 'http://localhost:3000/auth/google/callback',
 *     },
 * })
 *
 * // Usage in controller
 * @Get('/auth/google')
 * google() {
 *     return socialite('google').redirect()
 * }
 *
 * @Get('/auth/google/callback')
 * async googleCallback(c: Context) {
 *     const user = await socialite('google').user(c)
 *     // { id, email, name, avatar, raw }
 * }
 * ```
 */

import type { Context } from 'hono'

// ============================================================================
// Types
// ============================================================================

/** Normalized social user data */
export interface SocialUser {
    /** Provider-specific user ID */
    id: string
    /** User's email address */
    email: string
    /** User's display name */
    name: string
    /** User's avatar URL */
    avatar: string | null
    /** Access token for API calls */
    accessToken: string
    /** Refresh token (if available) */
    refreshToken: string | null
    /** Token expiration time (if available) */
    expiresIn: number | null
    /** Raw provider response */
    raw: Record<string, unknown>
}

/** OAuth2 token response */
export interface OAuthTokens {
    access_token: string
    token_type: string
    expires_in?: number
    refresh_token?: string
    scope?: string
}

/** Provider configuration */
export interface ProviderConfig {
    clientId: string
    clientSecret: string
    redirectUri: string
    scopes?: string[]
}

/** Socialite configuration */
export interface SocialiteConfig {
    google?: ProviderConfig
    github?: ProviderConfig
    discord?: ProviderConfig
    [key: string]: ProviderConfig | undefined
}

/** OAuth2 provider driver interface */
export interface SocialiteDriver {
    /** Get the authorization URL */
    getAuthUrl(state?: string): string
    /** Exchange code for tokens */
    getTokens(code: string): Promise<OAuthTokens>
    /** Get user info from tokens */
    getUserFromTokens(tokens: OAuthTokens): Promise<SocialUser>
    /** Generate redirect response */
    redirect(state?: string): Response
    /** Get user from callback request */
    user(c: Context): Promise<SocialUser>
}

// ============================================================================
// Configuration
// ============================================================================

let socialiteConfig: SocialiteConfig = {}

/**
 * Configure socialite providers
 */
export function configureSocialite(config: SocialiteConfig): void {
    socialiteConfig = config
}

/**
 * Get socialite configuration
 */
export function getSocialiteConfig(): SocialiteConfig {
    return socialiteConfig
}

// ============================================================================
// Base OAuth2 Driver
// ============================================================================

export abstract class BaseOAuth2Driver implements SocialiteDriver {
    constructor(protected config: ProviderConfig) {}

    /** Authorization endpoint URL */
    protected abstract authUrl: string

    /** Token endpoint URL */
    protected abstract tokenUrl: string

    /** User info endpoint URL */
    protected abstract userInfoUrl: string

    /** Default scopes for this provider */
    protected abstract defaultScopes: string[]

    /** Get the scopes to use */
    protected getScopes(): string[] {
        return this.config.scopes ?? this.defaultScopes
    }

    /** Build authorization URL */
    getAuthUrl(state?: string): string {
        const params = new URLSearchParams({
            client_id: this.config.clientId,
            redirect_uri: this.config.redirectUri,
            response_type: 'code',
            scope: this.getScopes().join(' '),
        })

        if (state) {
            params.set('state', state)
        }

        return `${this.authUrl}?${params.toString()}`
    }

    /** Exchange authorization code for tokens */
    async getTokens(code: string): Promise<OAuthTokens> {
        const response = await fetch(this.tokenUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                Accept: 'application/json',
            },
            body: new URLSearchParams({
                client_id: this.config.clientId,
                client_secret: this.config.clientSecret,
                code,
                redirect_uri: this.config.redirectUri,
                grant_type: 'authorization_code',
            }),
        })

        if (!response.ok) {
            const error = await response.text()
            throw new Error(`Failed to get tokens: ${error}`)
        }

        return await response.json()
    }

    /** Get user info from tokens - implemented by each provider */
    abstract getUserFromTokens(tokens: OAuthTokens): Promise<SocialUser>

    /** Generate redirect response to authorization URL */
    redirect(state?: string): Response {
        const url = this.getAuthUrl(state)
        return new Response(null, {
            status: 302,
            headers: { Location: url },
        })
    }

    /** Get user from callback request */
    async user(c: Context): Promise<SocialUser> {
        const code = c.req.query('code')

        if (!code) {
            const error = c.req.query('error')
            const errorDescription = c.req.query('error_description')
            throw new Error(
                `OAuth error: ${error} - ${
                    errorDescription || 'No code provided'
                }`,
            )
        }

        const tokens = await this.getTokens(code)
        return await this.getUserFromTokens(tokens)
    }
}

// ============================================================================
// Google Driver
// ============================================================================

export class GoogleDriver extends BaseOAuth2Driver {
    protected authUrl = 'https://accounts.google.com/o/oauth2/v2/auth'
    protected tokenUrl = 'https://oauth2.googleapis.com/token'
    protected userInfoUrl = 'https://www.googleapis.com/oauth2/v2/userinfo'
    protected defaultScopes = ['openid', 'email', 'profile']

    override getAuthUrl(state?: string): string {
        const params = new URLSearchParams({
            client_id: this.config.clientId,
            redirect_uri: this.config.redirectUri,
            response_type: 'code',
            scope: this.getScopes().join(' '),
            access_type: 'offline',
            prompt: 'consent',
        })

        if (state) {
            params.set('state', state)
        }

        return `${this.authUrl}?${params.toString()}`
    }

    async getUserFromTokens(tokens: OAuthTokens): Promise<SocialUser> {
        const response = await fetch(this.userInfoUrl, {
            headers: {
                Authorization: `Bearer ${tokens.access_token}`,
            },
        })

        if (!response.ok) {
            throw new Error('Failed to get user info from Google')
        }

        const data = await response.json()

        return {
            id: data.id,
            email: data.email,
            name: data.name,
            avatar: data.picture || null,
            accessToken: tokens.access_token,
            refreshToken: tokens.refresh_token || null,
            expiresIn: tokens.expires_in || null,
            raw: data,
        }
    }
}

// ============================================================================
// GitHub Driver
// ============================================================================

export class GitHubDriver extends BaseOAuth2Driver {
    protected authUrl = 'https://github.com/login/oauth/authorize'
    protected tokenUrl = 'https://github.com/login/oauth/access_token'
    protected userInfoUrl = 'https://api.github.com/user'
    protected defaultScopes = ['read:user', 'user:email']

    async getUserFromTokens(tokens: OAuthTokens): Promise<SocialUser> {
        // Get user profile
        const userResponse = await fetch(this.userInfoUrl, {
            headers: {
                Authorization: `Bearer ${tokens.access_token}`,
                Accept: 'application/json',
            },
        })

        if (!userResponse.ok) {
            throw new Error('Failed to get user info from GitHub')
        }

        const userData = await userResponse.json()

        // Get user emails (in case email is private)
        let email = userData.email
        if (!email) {
            const emailsResponse = await fetch(
                'https://api.github.com/user/emails',
                {
                    headers: {
                        Authorization: `Bearer ${tokens.access_token}`,
                        Accept: 'application/json',
                    },
                },
            )

            if (emailsResponse.ok) {
                const emails = await emailsResponse.json()
                const primaryEmail = emails.find(
                    (e: { primary: boolean }) => e.primary,
                )
                email = primaryEmail?.email || emails[0]?.email
            }
        }

        return {
            id: String(userData.id),
            email: email || '',
            name: userData.name || userData.login,
            avatar: userData.avatar_url || null,
            accessToken: tokens.access_token,
            refreshToken: tokens.refresh_token || null,
            expiresIn: tokens.expires_in || null,
            raw: userData,
        }
    }
}

// ============================================================================
// Discord Driver
// ============================================================================

export class DiscordDriver extends BaseOAuth2Driver {
    protected authUrl = 'https://discord.com/api/oauth2/authorize'
    protected tokenUrl = 'https://discord.com/api/oauth2/token'
    protected userInfoUrl = 'https://discord.com/api/users/@me'
    protected defaultScopes = ['identify', 'email']

    async getUserFromTokens(tokens: OAuthTokens): Promise<SocialUser> {
        const response = await fetch(this.userInfoUrl, {
            headers: {
                Authorization: `Bearer ${tokens.access_token}`,
            },
        })

        if (!response.ok) {
            throw new Error('Failed to get user info from Discord')
        }

        const data = await response.json()

        // Discord avatar URL construction
        let avatar: string | null = null
        if (data.avatar) {
            const ext = data.avatar.startsWith('a_') ? 'gif' : 'png'
            avatar =
                `https://cdn.discordapp.com/avatars/${data.id}/${data.avatar}.${ext}`
        }

        return {
            id: data.id,
            email: data.email || '',
            name: data.global_name || data.username,
            avatar,
            accessToken: tokens.access_token,
            refreshToken: tokens.refresh_token || null,
            expiresIn: tokens.expires_in || null,
            raw: data,
        }
    }
}

// ============================================================================
// Driver Registry
// ============================================================================

const drivers: Record<
    string,
    new (config: ProviderConfig) => SocialiteDriver
> = {
    google: GoogleDriver,
    github: GitHubDriver,
    discord: DiscordDriver,
}

/**
 * Register a custom OAuth2 driver
 */
export function registerSocialiteDriver(
    name: string,
    driver: new (config: ProviderConfig) => SocialiteDriver,
): void {
    drivers[name] = driver
}

// ============================================================================
// Main API
// ============================================================================

/**
 * Get a socialite driver instance
 *
 * @example
 * ```typescript
 * // Redirect to OAuth provider
 * return socialite('google').redirect()
 *
 * // Get user from callback
 * const user = await socialite('google').user(c)
 * ```
 */
export function socialite(provider: string): SocialiteDriver {
    const config = socialiteConfig[provider]

    if (!config) {
        throw new Error(
            `Socialite provider "${provider}" is not configured. ` +
                `Call configureSocialite() with the provider config.`,
        )
    }

    const DriverClass = drivers[provider]

    if (!DriverClass) {
        throw new Error(
            `Unknown socialite provider "${provider}". ` +
                `Available providers: ${Object.keys(drivers).join(', ')}. ` +
                `Use registerSocialiteDriver() to add custom providers.`,
        )
    }

    return new DriverClass(config)
}

/**
 * Stateful socialite helper with CSRF protection
 *
 * @example
 * ```typescript
 * // In your controller
 * @Get('/auth/google')
 * google(c: Context) {
 *     return socialite('google').redirect(crypto.randomUUID())
 * }
 *
 * @Get('/auth/google/callback')
 * async googleCallback(c: Context) {
 *     const state = c.req.query('state')
 *     // Verify state matches what you stored in session
 *     const user = await socialite('google').user(c)
 * }
 * ```
 */
export function generateState(): string {
    return crypto.randomUUID()
}
