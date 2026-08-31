# @lockness/socialite

OAuth2/OIDC social authentication for Deno.

## Features

- 🔐 OAuth2/OIDC authentication
- 🎨 Built-in providers: Google, GitHub, Discord
- 🔌 Extensible driver system
- 🛡️ CSRF state protection support
- 🎯 TypeScript with full type safety
- 📦 Zero dependencies (uses Hono Context)

## Installation

```typescript
import { configureSocialite, socialite } from '@lockness/socialite'
```

## Configuration

```typescript
configureSocialite({
    google: {
        clientId: Deno.env.get('GOOGLE_CLIENT_ID')!,
        clientSecret: Deno.env.get('GOOGLE_CLIENT_SECRET')!,
        redirectUri: 'http://localhost:3000/auth/google/callback',
        scopes: ['openid', 'email', 'profile'], // optional
    },
    github: {
        clientId: Deno.env.get('GITHUB_CLIENT_ID')!,
        clientSecret: Deno.env.get('GITHUB_CLIENT_SECRET')!,
        redirectUri: 'http://localhost:3000/auth/github/callback',
    },
    discord: {
        clientId: Deno.env.get('DISCORD_CLIENT_ID')!,
        clientSecret: Deno.env.get('DISCORD_CLIENT_SECRET')!,
        redirectUri: 'http://localhost:3000/auth/discord/callback',
    },
})
```

## Usage

### Basic Example

```typescript
import { Controller, Get } from '@lockness/contract'
import { socialite } from '@lockness/socialite'
import type { Context } from 'hono'

@Controller('/auth')
class AuthController {
    // Redirect to Google OAuth
    @Get('/google')
    google() {
        return socialite('google').redirect()
    }

    // Handle callback
    @Get('/google/callback')
    async googleCallback(c: Context) {
        const user = await socialite('google').user(c)

        // user.id, user.email, user.name, user.avatar
        // Store in session, create account, etc.

        return c.json({ user })
    }
}
```

### With CSRF Protection

```typescript
import { generateState } from '@lockness/socialite'

@Controller('/auth')
class AuthController {
    @Get('/google')
    async google(c: Context) {
        const state = generateState()

        // Store state in session
        c.get('session').set('oauth_state', state)

        return socialite('google').redirect(state)
    }

    @Get('/google/callback')
    async googleCallback(c: Context) {
        const state = c.req.query('state')
        const sessionState = c.get('session').get('oauth_state')

        if (state !== sessionState) {
            return c.text('Invalid state', 400)
        }

        const user = await socialite('google').user(c)
        return c.json({ user })
    }
}
```

## User Object

The `socialite().user(c)` method returns a normalized user object:

```typescript
interface SocialUser {
    id: string // Provider-specific ID
    email: string // User's email
    name: string // Display name
    avatar: string | null // Avatar URL
    accessToken: string // OAuth access token
    refreshToken: string | null
    expiresIn: number | null
    raw: Record<string, unknown> // Raw provider response
}
```

## Providers

### Google

```typescript
configureSocialite({
    google: {
        clientId: '...',
        clientSecret: '...',
        redirectUri: 'http://localhost:3000/auth/google/callback',
        scopes: ['openid', 'email', 'profile'], // default
    },
})
```

**Get credentials:**
[Google Cloud Console](https://console.cloud.google.com/apis/credentials)

### GitHub

```typescript
configureSocialite({
    github: {
        clientId: '...',
        clientSecret: '...',
        redirectUri: 'http://localhost:3000/auth/github/callback',
        scopes: ['read:user', 'user:email'], // default
    },
})
```

**Get credentials:** [GitHub OAuth Apps](https://github.com/settings/developers)

### Discord

```typescript
configureSocialite({
    discord: {
        clientId: '...',
        clientSecret: '...',
        redirectUri: 'http://localhost:3000/auth/discord/callback',
        scopes: ['identify', 'email'], // default
    },
})
```

**Get credentials:**
[Discord Developer Portal](https://discord.com/developers/applications)

## Custom Providers

Extend `BaseOAuth2Driver` to add custom providers:

```typescript
import { BaseOAuth2Driver, registerSocialiteDriver } from '@lockness/socialite'

class CustomDriver extends BaseOAuth2Driver {
    protected authUrl = 'https://provider.com/oauth/authorize'
    protected tokenUrl = 'https://provider.com/oauth/token'
    protected userInfoUrl = 'https://provider.com/api/user'
    protected defaultScopes = ['read']

    async getUserFromTokens(tokens: OAuthTokens): Promise<SocialUser> {
        const response = await fetch(this.userInfoUrl, {
            headers: { Authorization: `Bearer ${tokens.access_token}` },
        })
        const data = await response.json()

        return {
            id: data.id,
            email: data.email,
            name: data.name,
            avatar: data.avatar_url,
            accessToken: tokens.access_token,
            refreshToken: tokens.refresh_token || null,
            expiresIn: tokens.expires_in || null,
            raw: data,
        }
    }
}

// Register
registerSocialiteDriver('custom', CustomDriver)

// Configure
configureSocialite({
    custom: {
        clientId: '...',
        clientSecret: '...',
        redirectUri: '...',
    },
})

// Use
socialite('custom').redirect()
```

## License

MIT
