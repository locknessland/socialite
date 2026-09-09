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
import { isExplicitlyDevelopment } from '@lockness/contract'
import { crypto as stdCrypto } from '@std/crypto'
import { encodeBase64Url } from '@std/encoding/base64url'

/**
 * Name of the short-lived cookie that carries the OAuth `state` value between
 * {@link BaseOAuth2Driver.redirect} and {@link BaseOAuth2Driver.user}. The
 * cookie is HttpOnly, so an attacker can neither read nor set it; comparing it
 * to the `state` echoed back in the callback query is the standard
 * double-submit defence against OAuth login-CSRF (#169).
 */
const OAUTH_STATE_COOKIE = 'lockness_oauth_state'

/** Seconds the state cookie stays valid — long enough for the round-trip. */
const OAUTH_STATE_TTL = 600

/**
 * Build the `Set-Cookie` header value for the OAuth state cookie.
 *
 * `Secure` is derived fail-closed: on unless the environment is explicitly
 * development, so the cookie is only sent over plaintext HTTP on a localhost dev
 * setup (matches the session cookie posture). `SameSite=Lax` is required so the
 * cookie survives the top-level redirect back from the provider.
 *
 * @param state - The state value to store.
 * @returns The serialized `Set-Cookie` value.
 */
function buildStateCookie(state: string): string {
    return buildShortLivedCookie(OAUTH_STATE_COOKIE, state, OAUTH_STATE_TTL)
}

/**
 * Serialize a short-lived, HttpOnly OAuth cookie (state or PKCE verifier) with
 * the shared posture: `Path=/`, the given `Max-Age`, `HttpOnly`, `SameSite=Lax`
 * (survives the top-level redirect back), and `Secure` unless the environment is
 * explicitly development. The single home for that cookie posture.
 *
 * @param name - The cookie name (already `__Host-`-prefixed by the caller where
 *   applicable).
 * @param value - The cookie value.
 * @param ttlSeconds - `Max-Age` in seconds.
 * @returns The serialized `Set-Cookie` value.
 */
function buildShortLivedCookie(
    name: string,
    value: string,
    ttlSeconds: number,
): string {
    const attrs = [
        `${name}=${value}`,
        'Path=/',
        `Max-Age=${ttlSeconds}`,
        'HttpOnly',
        'SameSite=Lax',
    ]
    if (!isExplicitlyDevelopment()) attrs.push('Secure')
    return attrs.join('; ')
}

/**
 * Read a single cookie value from a raw `Cookie` header.
 *
 * @param header - The request's `Cookie` header, if any.
 * @param name - The cookie name to extract.
 * @returns The decoded value, or `undefined` when absent.
 */
function readCookie(
    header: string | undefined,
    name: string,
): string | undefined {
    if (!header) return undefined
    for (const part of header.split(';')) {
        const eq = part.indexOf('=')
        if (eq === -1) continue
        if (part.slice(0, eq).trim() === name) {
            return part.slice(eq + 1).trim()
        }
    }
    return undefined
}

// ============================================================================
// PKCE (RFC 7636, S256) — #243
// ============================================================================

/**
 * Base name of the short-lived cookie carrying the PKCE `code_verifier` between
 * {@link BaseOAuth2Driver.redirect} and {@link BaseOAuth2Driver.user}. Prefixed
 * with `__Host-` when the cookie is `Secure` (see {@link verifierCookieName}).
 */
const OAUTH_VERIFIER_COOKIE = 'lockness_pkce_verifier'

/** Seconds the verifier cookie stays valid — the auth round-trip window. */
const OAUTH_VERIFIER_TTL = 600

/**
 * Resolve the verifier cookie name. In production the cookie is `Secure`, so it
 * takes the `__Host-` prefix (locking it to this host, `Path=/`, no `Domain`);
 * on the explicit-development plaintext path the prefix is dropped, since
 * `__Host-` requires `Secure`. Both the writer ({@link buildPkceCookie}) and the
 * reader ({@link BaseOAuth2Driver.user}) must agree — this is their single home.
 *
 * @returns The cookie name for the current environment.
 */
function verifierCookieName(): string {
    return isExplicitlyDevelopment()
        ? OAUTH_VERIFIER_COOKIE
        : `__Host-${OAUTH_VERIFIER_COOKIE}`
}

/**
 * Generate a PKCE `code_verifier`: base64url-unpadded of 32 CSPRNG bytes — 43
 * characters from RFC 7636 §4.1's unreserved set, 256 bits of entropy.
 *
 * @returns A fresh code verifier.
 */
export function generatePkceVerifier(): string {
    return encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)))
}

/**
 * Derive the PKCE `code_challenge` from a verifier:
 * BASE64URL-UNPADDED(SHA-256(ASCII(verifier))) — the S256 method.
 *
 * Uses `@std/crypto`'s synchronous `digestSync` so {@link BaseOAuth2Driver.redirect}
 * stays synchronous; the digest input is the ASCII of the verifier STRING, never
 * the raw random bytes.
 *
 * @param verifier - The code verifier produced by {@link generatePkceVerifier}.
 * @returns The S256 code challenge.
 */
export function pkceChallenge(verifier: string): string {
    const digest = stdCrypto.subtle.digestSync(
        'SHA-256',
        new TextEncoder().encode(verifier),
    )
    return encodeBase64Url(new Uint8Array(digest))
}

/**
 * Build the `Set-Cookie` value for the PKCE verifier cookie, mirroring the state
 * cookie's posture: HttpOnly, `SameSite=Lax` (survives the top-level redirect
 * back), `Secure` unless explicitly development, short `Max-Age`.
 *
 * @param verifier - The verifier to store.
 * @returns The serialized `Set-Cookie` value.
 */
function buildPkceCookie(verifier: string): string {
    return buildShortLivedCookie(
        verifierCookieName(),
        verifier,
        OAUTH_VERIFIER_TTL,
    )
}

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
    getTokens(code: string, codeVerifier?: string): Promise<OAuthTokens>
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

    /**
     * Whether this provider participates in PKCE (RFC 7636, S256). Default
     * **on** (opt-out, #243): all bundled providers support S256. A custom or
     * legacy driver whose provider rejects an unknown `code_challenge` sets this
     * `false` to fall back to the pre-PKCE behaviour. Fail-closed posture of
     * epic #164.
     */
    protected usesPkce = true

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

    /**
     * Exchange authorization code for tokens.
     *
     * @param code - The authorization code from the callback.
     * @param codeVerifier - The PKCE verifier (#243); included as `code_verifier`
     *   when present. A custom override must forward this to keep PKCE binding.
     * @returns The provider's token response.
     * @throws {Error} When the token endpoint responds with a non-OK status.
     */
    async getTokens(
        code: string,
        codeVerifier?: string,
    ): Promise<OAuthTokens> {
        const body = new URLSearchParams({
            client_id: this.config.clientId,
            client_secret: this.config.clientSecret,
            code,
            redirect_uri: this.config.redirectUri,
            grant_type: 'authorization_code',
        })
        if (codeVerifier) body.set('code_verifier', codeVerifier)

        const response = await fetch(this.tokenUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                Accept: 'application/json',
            },
            body,
        })

        if (!response.ok) {
            const error = await response.text()
            throw new Error(`Failed to get tokens: ${error}`)
        }

        return await response.json()
    }

    /** Get user info from tokens - implemented by each provider */
    abstract getUserFromTokens(tokens: OAuthTokens): Promise<SocialUser>

    /**
     * Generate a redirect response to the authorization URL.
     *
     * When no `state` is supplied one is generated, and it is stored in a
     * short-lived HttpOnly cookie on the response so {@link user} can verify the
     * callback against it — making the ergonomic path CSRF-safe by default
     * (#169). Pass an explicit `state` only to manage it yourself.
     *
     * When {@link usesPkce} is on, it also mints a PKCE `code_verifier`, appends
     * the S256 `code_challenge` to the authorization URL, and carries the
     * verifier in a second HttpOnly cookie (#243). The challenge is appended
     * HERE, not in {@link getAuthUrl}, so no driver override can strip it.
     *
     * @param state - Optional explicit state value; generated when omitted.
     * @returns A 302 response to the provider, carrying the state (and, when
     *   PKCE is on, the verifier) cookie.
     */
    redirect(state?: string): Response {
        const resolvedState = state ?? generateState()
        const headers = new Headers()
        headers.append('Set-Cookie', buildStateCookie(resolvedState))

        let url = this.getAuthUrl(resolvedState)
        if (this.usesPkce) {
            const verifier = generatePkceVerifier()
            const pkce = new URLSearchParams({
                code_challenge: pkceChallenge(verifier),
                code_challenge_method: 'S256',
            })
            url += (url.includes('?') ? '&' : '?') + pkce.toString()
            headers.append('Set-Cookie', buildPkceCookie(verifier))
        }

        headers.set('Location', url)
        return new Response(null, { status: 302, headers })
    }

    /**
     * Resolve the authenticated user from an OAuth callback request.
     *
     * Verifies the `state` query parameter against the state cookie set by
     * {@link redirect} and rejects on any absence or mismatch — the OAuth
     * login-CSRF defence (#169) — before exchanging the code for tokens.
     *
     * When {@link usesPkce} is on, it also reads the verifier cookie set by
     * {@link redirect} and includes `code_verifier` in the token exchange; an
     * absent verifier fails closed (#243) — a code without its verifier is an
     * interrupted or forged flow, never a fallback to no-PKCE. The verifier
     * value is used only in the token body — never logged or echoed in an error.
     *
     * @param c - The callback request context.
     * @returns The normalised social user.
     * @throws {Error} When the provider returned an error, no code is present,
     *   the `state` is missing or does not match the cookie, or PKCE is on and
     *   the verifier cookie is absent.
     */
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

        // Fail closed on the state check: an absent or mismatched state is a
        // possible login-CSRF and must never proceed to a token exchange.
        const expectedState = readCookie(
            c.req.header('Cookie'),
            OAUTH_STATE_COOKIE,
        )
        const returnedState = c.req.query('state')
        if (
            !expectedState || !returnedState || expectedState !== returnedState
        ) {
            throw new Error(
                'OAuth state mismatch: missing or invalid state (possible CSRF). ' +
                    'Start the flow via redirect() so the state cookie is set.',
            )
        }

        // Fail closed on PKCE: when this provider uses PKCE, the verifier cookie
        // set by redirect() must be present. Its absence is an interrupted or
        // forged flow — never exchange the code without the verifier. The value
        // is never interpolated into this message (#243, FR-009).
        let codeVerifier: string | undefined
        if (this.usesPkce) {
            codeVerifier = readCookie(
                c.req.header('Cookie'),
                verifierCookieName(),
            )
            if (!codeVerifier) {
                throw new Error(
                    'OAuth PKCE verifier missing (possible interrupted or forged flow). ' +
                        'Start the flow via redirect() so the verifier cookie is set.',
                )
            }
        }

        const tokens = await this.getTokens(code, codeVerifier)
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
