---
name: observability
description: OpenTelemetry, Grafana, Prometheus, structured logging, error tracking, distributed tracing
metadata:
  type: skill
  triggers: ["observability", "monitoring", "logging", "tracing", "metrics", "grafana", "prometheus", "opentelemetry", "sentry"]
---

# Observability

## Structured logging (pino)
```typescript
import pino from 'pino';
const log = pino({ level: 'info' });
log.info({ userId, requestId, duration: Date.now() - start }, 'Request completed');
log.error({ err, userId, endpoint }, 'Request failed');
```

## OpenTelemetry
```typescript
import { NodeSDK } from '@opentelemetry/sdk-node';
const sdk = new NodeSDK({
  traceExporter: new OTLPTraceExporter({ url: 'http://otel-collector:4318' }),
});
sdk.start();

const tracer = trace.getTracer('my-service');
const span = tracer.startSpan('process-order');
span.setAttribute('order.id', orderId);
try { /* work */ } finally { span.end(); }
```

## Prometheus metrics
```typescript
const httpDuration = new Histogram({
  name: 'http_request_duration_seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1],
});
```

## Rules
- Log level: ERROR=exceptions, WARN=recoverable, INFO=business events, DEBUG=dev
- Never log PII (passwords, tokens, card numbers)
- Correlation ID: propagate through all services
- Alert on: error rate > 1%, p99 latency > 2s, pod restarts
