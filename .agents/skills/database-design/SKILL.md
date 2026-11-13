---
name: database-design
description: PostgreSQL/MySQL schema design, Prisma migrations, index strategy, query optimization, N+1 fix
metadata:
  type: skill
  triggers: ["database", "schema", "migration", "prisma", "sql", "index", "query", "orm"]
---

# Database Design

## Schema design
- UUID/ULID for PKs (not serial int in distributed systems)
- `created_at`/`updated_at` with `DEFAULT now()` on all tables
- Soft delete: `deleted_at TIMESTAMPTZ NULL` + partial index `WHERE deleted_at IS NULL`
- Always add FK constraints

## Indexes
- Index every FK column
- Composite: equality filters first, range/sort last
- Partial: `CREATE INDEX ON orders(user_id) WHERE status = 'active'`
- Run `EXPLAIN ANALYZE` before claiming query is optimized

## N+1 fix
- ORM: use `include`/`with`/eager loading — never load in loop
- Raw SQL: JOIN or `IN (ids)` batch fetch
- DataLoader pattern for GraphQL resolvers

## Migrations
- Each migration: single responsibility
- Never DELETE column in first migration — add nullable, migrate data, then drop
- Always have rollback: `down()` mirrors `up()`

## Prisma
```prisma
model User {
  id        String   @id @default(cuid())
  email     String   @unique
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}
```
```bash
npx prisma migrate dev --name descriptive_name
npx prisma db pull  # introspect existing DB
```
