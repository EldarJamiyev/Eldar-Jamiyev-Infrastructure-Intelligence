---
name: queue-workers
description: BullMQ/RabbitMQ job queues, worker pools, retry logic, dead letter queue, priority jobs
metadata:
  type: skill
  triggers: ["queue", "job queue", "bullmq", "rabbitmq", "worker", "background job", "task queue", "dlq"]
---

# Job Queue Patterns (BullMQ)

## Queue + producer
```typescript
import { Queue, Worker } from 'bullmq';
const connection = { host: 'localhost', port: 6379 };
const emailQueue = new Queue('emails', { connection });

await emailQueue.add('send-welcome', { userId, email }, {
  attempts: 3,
  backoff: { type: 'exponential', delay: 1000 },
  priority: 1,
});
```

## Worker
```typescript
const worker = new Worker('emails', async (job) => {
  const { userId, email } = job.data;
  await sendEmail(email);
}, {
  connection,
  concurrency: 5,
});

worker.on('failed', (job, err) => {
  log.error({ jobId: job?.id, err }, 'Job failed');
});
```

## Dead Letter Queue
```typescript
worker.on('failed', async (job, err) => {
  if (job && job.attemptsMade >= job.opts.attempts!) {
    await failedQueue.add('dlq', { ...job.data, error: err.message });
  }
});
```

## Rules
- Idempotent workers: re-running same job must be safe
- Set TTL on completed jobs: `removeOnComplete: { age: 3600 }`
- Monitor queue depth — alert if > threshold
