---
name: graphql-api
description: GraphQL schema design, resolver patterns, N+1 DataLoader, subscriptions, type safety
metadata:
  type: skill
  triggers: ["graphql", "gql", "resolver", "schema", "apollo", "pothos", "dataloader"]
---

# GraphQL API

## Schema
```graphql
type User {
  id: ID!
  email: String!
  posts(limit: Int = 10, offset: Int = 0): PostConnection!
}
type PostConnection { nodes: [Post!]!  totalCount: Int! }
```

## DataLoader (N+1 fix)
```typescript
const userLoader = new DataLoader<string, User>(async (ids) => {
  const users = await db.user.findMany({ where: { id: { in: ids as string[] } } });
  return ids.map(id => users.find(u => u.id === id)!);
});
```

## Resolver
```typescript
const resolvers = {
  Query: {
    user: (_, { id }, { loaders }) => loaders.user.load(id),
  },
  User: {
    posts: (parent, { limit, offset }) =>
      db.post.findMany({ where: { userId: parent.id }, take: limit, skip: offset }),
  },
};
```

## Rules
- DataLoader for all FK-based lookups
- Pagination: cursor-based for feeds, offset for admin
- Validate input with Zod before resolver
- Depth limit: `graphql-depth-limit` (max 5)
