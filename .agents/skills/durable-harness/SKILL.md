---
name: durable-harness
description: Vercel durable harness for AI coding agents. Runs Claude Code, Codex, Pi, fx as durable agents on Workflow SDK with crash resumption, event log persistence, and idempotent tool calling.
---

# durable-harness

Vercel durable harness for AI coding agents. Runs Claude Code, Codex, Pi, fx as durable agents on Workflow SDK with crash resumption, event log persistence, and idempotent tool calling.

## Quick Command / Usage
```bash
npx durable-harness
```

## Documentation & Reference
<div align="center">
  <h1>durable-harness</h1>

<a href="https://vercel.com"><img alt="Vercel logo" src="https://img.shields.io/badge/MADE%20BY%20Vercel-000000.svg?style=for-the-badge&logo=Vercel&labelColor=000"></a>
<a href="https://www.npmjs.com/package/durable-harness"><img alt="npm version" src="https://img.shields.io/npm/v/durable-harness?style=for-the-badge&labelColor=000000"></a>
<a href="https://github.com/vercel-labs/durable-harness/blob/main/LICENSE.md"><img alt="License" src="https://img.shields.io/npm/l/durable-harness.svg?style=for-the-badge&labelColor=000000"></a>

</div>

durable-harness runs coding-agent harnesses (Pi, OpenCode, libfx's fx,
Claude Code and Codex) as durable agents on a
[Workflow SDK](https://workflow-sdk.dev) World. Each session is a workflow
run: its conversation, the turn in flight and every model and tool call are
in the run's event log, so a crash anywhere resumes the turn from the log on
another machine, and a tool call that isn't safe to repeat is never run twice.

> [!NOTE]
> durable-harness is experimental: it's on `0.0.x`, and its API may change
> between releases.

## Quick start

Install it with a harness, here Pi with
[pi-durable](https://www.npmjs.com/package/@earendil-works/pi-durable), in a
Next.js app:

```bash
npm install durable-harness @earendil-works/pi-durable @earendil-works/chord @earendil-works/pi-ai just-bash
```

Open Pi's own durable `Harness` on a World-backed storage. Agents are
tool-less by default; Pi's coding tools go on a virtual workspace, whose files
live in the session's log:

```ts
// lib/agent.ts
import { BACKGROUND_CONTEXT as ctx } from '@earendil-works/chord/context';
import { createRegistry, Harness, type Storage } from '@earendil-works/pi-durable';
import { CodingTools, GATEWAY_PROVIDER, gatewayModels, resumeWith, virtualEnv } from 'durable-harness/pi-durable';

const models = gatewayModels();
const registry = createRegistry();
registry.install(CodingTools);

export const agent = { model: { provider: GATEWAY_PROVIDER, modelId: 'anthropic/claude-sonnet-4.5' } };
export const open = resumeWith((storage: Storage) => Harness.open(storage, { models, registry, env: virtualEnv() }, ctx));
```

Serve it from a chat route, and configure the integration:

```ts
// app/api/chat/route.ts
import { chatRoute } from 'durable-harness/pi-durable';
import { agent, open } from '@/lib/agent';

export const { GET, POST } = chatRoute({ open, agent, authorize: async (request) => { /* your auth */ } });
```

```ts
// next.config.ts
import type { NextConfig } from 'next';
import { withDurableHarness } from 'durable-harness/next';

const nextConfig: NextConfig = {
  // your existing config
};

export default withDurableHarness(nextConfig);
```

`withDurableHarness` discovers modules that export agents created at module
scope with `durableAgent`, `claudeCode`, `codex`, `opencode` or `pi`, and modules
that register a pi-durable opener with `resumeWith`. A script that creates an
agent for itself, an 
