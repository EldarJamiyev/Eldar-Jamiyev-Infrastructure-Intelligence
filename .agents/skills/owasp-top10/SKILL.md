---
name: owasp-top10
description: OWASP Top 10 vulnerability fixes — SQLi, XSS, CSRF, SSRF, path traversal, broken auth
metadata:
  type: skill
  triggers: ["owasp", "xss", "sql injection", "csrf", "ssrf", "security vulnerability", "injection"]
---

# OWASP Top 10 Fixes

## A01 Broken Access Control
```typescript
const post = await db.post.findUnique({ where: { id } });
if (post.userId !== req.user.id) throw new ForbiddenError();
```

## A03 SQL Injection
```typescript
// NEVER: db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)
// ALWAYS parameterized:
const user = await db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
```

## A03 XSS
```typescript
// React auto-escapes JSX — safe by default
// Dangerous: dangerouslySetInnerHTML={{ __html: userInput }}
// If needed: import DOMPurify; DOMPurify.sanitize(html)
```

## A05 Security Misconfiguration
```typescript
app.use(helmet({
  contentSecurityPolicy: { directives: { defaultSrc: ["'self'"] } },
  hsts: { maxAge: 31536000 }
}));
```

## A10 SSRF
```typescript
function isSafeUrl(url: string): boolean {
  const parsed = new URL(url);
  return !['127.0.0.1','localhost','0.0.0.0','169.254.169.254'].includes(parsed.hostname)
    && parsed.protocol === 'https:';
}
```

## A07 Auth failures
- Invalidate sessions on password change/logout
- Account lockout after N failed attempts
- Use `crypto.randomBytes` not `Math.random` for tokens
