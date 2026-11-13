---
name: openapi-spec
description: OpenAPI 3.1 specification, Zod-to-schema generation, SDK generation, mock servers
metadata:
  type: skill
  triggers: ["openapi", "swagger", "api spec", "api documentation", "zod schema", "sdk generation"]
---

# OpenAPI 3.1

## Basic structure
```yaml
openapi: 3.1.0
info:
  title: My API
  version: 1.0.0
paths:
  /users/{id}:
    get:
      summary: Get user by ID
      parameters:
        - name: id
          in: path
          required: true
          schema: { type: string, format: uuid }
      responses:
        '200':
          content:
            application/json:
              schema: { $ref: '#/components/schemas/User' }
components:
  schemas:
    User:
      type: object
      required: [id, email]
      properties:
        id: { type: string, format: uuid }
        email: { type: string, format: email }
```

## Zod → OpenAPI
```typescript
import { z } from 'zod';
import { extendZodWithOpenApi } from '@asteasolutions/zod-to-openapi';
extendZodWithOpenApi(z);

const UserSchema = z.object({
  id: z.string().uuid().openapi({ example: '123e4567-...' }),
  email: z.string().email(),
}).openapi('User');
```

## SDK generation
```bash
npx @hey-api/openapi-ts -i openapi.yaml -o src/client -c @hey-api/client-fetch
```
