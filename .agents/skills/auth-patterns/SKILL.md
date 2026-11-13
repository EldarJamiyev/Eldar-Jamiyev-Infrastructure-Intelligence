---
name: auth-patterns
description: JWT, OAuth2/OIDC, session management, refresh token rotation, PKCE, NextAuth/Auth.js
metadata:
  type: skill
  triggers: ["auth", "authentication", "jwt", "oauth", "session", "login", "nextauth", "clerk"]
---

# Authentication Patterns

## JWT best practices
```typescript
// Access token: 15min, stateless
// Refresh token: 7d, httpOnly cookie, DB-tracked

const accessToken = jwt.sign({ userId, role }, process.env.JWT_SECRET!, {
  expiresIn: '15m', algorithm: 'HS256'
});

// Refresh token rotation
async function refreshTokens(oldToken: string) {
  const record = await db.refreshToken.findUnique({ where: { token: oldToken } });
  if (!record || record.expiresAt < new Date()) throw new UnauthorizedError();
  await db.refreshToken.delete({ where: { id: record.id } });
  const newToken = generateSecureToken();
  await db.refreshToken.create({ data: { userId: record.userId, token: newToken, expiresAt: add7days() } });
  return { accessToken: newJWT(record.userId), refreshToken: newToken };
}
```

## OAuth2 PKCE
```typescript
const verifier = generateCodeVerifier();      // 43-128 random chars
const challenge = sha256base64url(verifier);  // S256 method
// Redirect with code_challenge, exchange code + verifier for tokens
```

## NextAuth.js
```typescript
export const { handlers, auth, signIn, signOut } = NextAuth({
  providers: [Google, GitHub],
  callbacks: {
    jwt({ token, user }) { if (user) token.role = user.role; return token; },
    session({ session, token }) { session.user.role = token.role; return session; }
  }
});
```

## Rules
- HttpOnly + Secure + SameSite=Strict for auth cookies
- Never store tokens in localStorage
- Validate JWT on every request (don't trust client-side role)
- Rate-limit login: 5 attempts/15min per IP
