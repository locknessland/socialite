# Lockness Socialite

OAuth2/OIDC social authentication with built-in providers for Google, GitHub,
and Discord.

## Overview

@lockness/socialite provides OAuth2/OIDC authentication with CSRF state
protection, extensible driver system, and full TypeScript type safety. Zero
external dependencies.

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
        scopes: ['read:user', 'user:email'], // optional
    },
    discord: {
        clientId: Deno.env.get('DISCORD_CLIENT_ID')!,
        clientSecret: Deno.env.get('DISCORD_CLIENT_SECRET')!,
        redirectUri: 'http://localhost:3000/auth/discord/callback',
        scopes: ['identify', 'email'], // optional
    },
})
```

## Basic Usage

### Simple OAuth Flow

```typescript
import { Controller, Get } from '@lockness/core'
import { socialite } from '@lockness/socialite'
import type { Context } from '@lockness/core'

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
import { session } from '@lockness/session'

@Controller('/auth')
class AuthController {
    @Get('/google')
    async google(c: Context) {
        const state = generateState()

        // Store state in session
        session(c).set('oauth_state', state)

        return socialite('google').redirect(state)
    }

    @Get('/google/callback')
    async googleCallback(c: Context) {
        const state = c.req.query('state')
        const sessionState = session(c).get('oauth_state')

        if (state !== sessionState) {
            return c.text('Invalid state', 400)
        }

        session(c).delete('oauth_state')

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
    refreshToken: string | null // OAuth refresh token (if available)
    expiresIn: number | null // Token expiration in seconds
    raw: Record<string, unknown> // Raw provider response
}
```

## Providers

### Google

**Get credentials:**
[Google Cloud Console](https://console.cloud.google.com/apis/credentials)

```typescript
configureSocialite({
    google: {
        clientId: 'your-client-id',
        clientSecret: 'your-client-secret',
        redirectUri: 'http://localhost:3000/auth/google/callback',
        scopes: ['openid', 'email', 'profile'], // default
    },
})
```

### GitHub

**Get credentials:** [GitHub OAuth Apps](https://github.com/settings/developers)

```typescript
configureSocialite({
    github: {
        clientId: 'your-client-id',
        clientSecret: 'your-client-secret',
        redirectUri: 'http://localhost:3000/auth/github/callback',
        scopes: ['read:user', 'user:email'], // default
    },
})
```

### Discord

**Get credentials:**
[Discord Developer Portal](https://discord.com/developers/applications)

```typescript
configureSocialite({
    discord: {
        clientId: 'your-client-id',
        clientSecret: 'your-client-secret',
        redirectUri: 'http://localhost:3000/auth/discord/callback',
        scopes: ['identify', 'email'], // default
    },
})
```

## Common Use Cases

### Social Login with Account Creation

```typescript
import { auth } from '@lockness/auth'
import { socialite } from '@lockness/socialite'

@Controller('/auth')
export class AuthController {
    @Get('/google/callback')
    async googleCallback(c: Context) {
        const socialUser = await socialite('google').user(c)

        // Find or create user
        let user = await db.query.users.findFirst({
            where: eq(users.email, socialUser.email),
        })

        if (!user) {
            // Create new user
            user = await db.insert(users).values({
                email: socialUser.email,
                name: socialUser.name,
                avatar: socialUser.avatar,
                googleId: socialUser.id,
            }).returning()
        } else if (!user.googleId) {
            // Link existing account
            await db.update(users)
                .set({ googleId: socialUser.id })
                .where(eq(users.id, user.id))
        }

        // Log user in
        await auth(c).loginById(user.id)

        return c.redirect('/dashboard')
    }
}
```

### Multiple OAuth Providers

```typescript
@Controller('/auth')
export class AuthController {
    @Get('/google')
    google() {
        return socialite('google').redirect()
    }

    @Get('/github')
    github() {
        return socialite('github').redirect()
    }

    @Get('/discord')
    discord() {
        return socialite('discord').redirect()
    }

    @Get('/google/callback')
    async googleCallback(c: Context) {
        return await this.handleCallback(c, 'google')
    }

    @Get('/github/callback')
    async githubCallback(c: Context) {
        return await this.handleCallback(c, 'github')
    }

    @Get('/discord/callback')
    async discordCallback(c: Context) {
        return await this.handleCallback(c, 'discord')
    }

    private async handleCallback(
        c: Context,
        provider: 'google' | 'github' | 'discord',
    ) {
        const socialUser = await socialite(provider).user(c)

        let user = await findOrCreateUser(socialUser, provider)

        await auth(c).loginById(user.id)

        return c.redirect('/dashboard')
    }
}
```

### Account Linking

```typescript
@Controller('/settings')
export class SettingsController {
    @Get('/link/github')
    @AuthRequired()
    linkGithub(c: Context) {
        const state = generateState()
        session(c).set('link_state', state)
        session(c).set('link_user_id', c.get('auth').user.id)

        return socialite('github').redirect(state)
    }

    @Get('/link/github/callback')
    async linkGithubCallback(c: Context) {
        const state = c.req.query('state')
        const sessionState = session(c).get('link_state')
        const userId = session(c).get('link_user_id')

        if (state !== sessionState || !userId) {
            return c.text('Invalid state', 400)
        }

        const socialUser = await socialite('github').user(c)

        // Link GitHub account
        await db.update(users)
            .set({ githubId: socialUser.id })
            .where(eq(users.id, userId))

        session(c).delete('link_state')
        session(c).delete('link_user_id')
        session(c).flash('success', 'GitHub account linked successfully')

        return c.redirect('/settings')
    }
}
```

## Custom Providers

Extend `BaseOAuth2Driver` to add custom providers:

```typescript
import { BaseOAuth2Driver, registerSocialiteDriver } from '@lockness/socialite'
import type { OAuthTokens, SocialUser } from '@lockness/socialite'

class LinkedInDriver extends BaseOAuth2Driver {
    protected authUrl = 'https://www.linkedin.com/oauth/v2/authorization'
    protected tokenUrl = 'https://www.linkedin.com/oauth/v2/accessToken'
    protected userInfoUrl = 'https://api.linkedin.com/v2/me'
    protected defaultScopes = ['r_liteprofile', 'r_emailaddress']

    async getUserFromTokens(tokens: OAuthTokens): Promise<SocialUser> {
        const response = await fetch(this.userInfoUrl, {
            headers: {
                'Authorization': `Bearer ${tokens.access_token}`,
            },
        })
        const data = await response.json()

        // Get email separately (LinkedIn specific)
        const emailResponse = await fetch(
            'https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))',
            {
                headers: {
                    'Authorization': `Bearer ${tokens.access_token}`,
                },
            },
        )
        const emailData = await emailResponse.json()
        const email = emailData.elements?.[0]?.['handle~']?.emailAddress

        return {
            id: data.id,
            email: email,
            name: `${data.localizedFirstName} ${data.localizedLastName}`,
            avatar: null,
            accessToken: tokens.access_token,
            refreshToken: tokens.refresh_token || null,
            expiresIn: tokens.expires_in || null,
            raw: data,
        }
    }
}

// Register driver
registerSocialiteDriver('linkedin', LinkedInDriver)

// Configure
configureSocialite({
    linkedin: {
        clientId: 'your-client-id',
        clientSecret: 'your-client-secret',
        redirectUri: 'http://localhost:3000/auth/linkedin/callback',
    },
})

// Use
socialite('linkedin').redirect()
```

## Best Practices

- Always use CSRF state protection in production
- Store OAuth state in session, not cookies
- Validate state parameter on callback
- Use environment variables for client credentials
- Set up proper redirect URIs in provider settings
- Handle OAuth errors gracefully
- Store access tokens securely if needed
- Consider token refresh for long-lived sessions
- Use HTTPS in production for secure OAuth flow
- Implement proper error handling for network failures
- Log OAuth errors for debugging
- Consider rate limiting on OAuth endpoints

## Environment Variables

```bash
# .env

# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# GitHub OAuth
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Discord OAuth
DISCORD_CLIENT_ID=your-discord-client-id
DISCORD_CLIENT_SECRET=your-discord-client-secret
```

## Error Handling

```typescript
@Get('/google/callback')
async googleCallback(c: Context) {
    try {
        const socialUser = await socialite('google').user(c)
        
        // Process user...
        
        return c.redirect('/dashboard')
    } catch (error) {
        console.error('OAuth error:', error)
        
        session(c).flash('error', 'Authentication failed. Please try again.')
        return c.redirect('/login')
    }
}
```
