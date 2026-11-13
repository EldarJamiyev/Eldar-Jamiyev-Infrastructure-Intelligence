---
name: redis-patterns
description: Redis cache strategy, pub/sub, rate limiting, session store, distributed locks
metadata:
  type: skill
  triggers: ["redis", "cache", "rate limit", "pub sub", "session store", "distributed lock"]
---

# Redis Patterns

## Cache-aside
```typescript
async function getUser(id: string): Promise<User> {
  const cached = await redis.get(`user:${id}`);
  if (cached) return JSON.parse(cached);
  const user = await db.user.findUnique({ where: { id } });
  await redis.set(`user:${id}`, JSON.stringify(user), 'EX', 300);
  return user;
}
await redis.del(`user:${id}`); // invalidate on update
```

## Rate limiting (sliding window)
```typescript
async function rateLimit(key: string, limit: number, windowSec: number): Promise<boolean> {
  const now = Date.now();
  const pipeline = redis.pipeline();
  pipeline.zremrangebyscore(key, 0, now - windowSec * 1000);
  pipeline.zadd(key, now, `${now}-${Math.random()}`);
  pipeline.zcard(key);
  pipeline.expire(key, windowSec);
  const results = await pipeline.exec();
  return (results![2][1] as number) <= limit;
}
```

## Distributed lock (Redlock)
```typescript
import Redlock from 'redlock';
const redlock = new Redlock([redis]);
const lock = await redlock.acquire(['lock:resource'], 5000);
try { /* critical section */ } finally { await lock.release(); }
```
