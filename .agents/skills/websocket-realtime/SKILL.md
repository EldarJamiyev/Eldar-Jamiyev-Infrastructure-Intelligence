---
name: websocket-realtime
description: WebSocket, SSE, Socket.io real-time patterns, connection management, reconnect logic
metadata:
  type: skill
  triggers: ["websocket", "realtime", "socket.io", "sse", "server-sent events", "live update"]
---

# Real-time Patterns

## Choose transport
- **SSE**: server→client only, HTTP, auto-reconnect. Best: feeds, notifications.
- **WebSocket**: bi-directional, lowest latency. Best: chat, gaming, collaboration.
- **Socket.io**: WebSocket + fallback + rooms. Best: when rooms/namespaces needed.

## SSE
```typescript
app.get('/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  const send = (data: object) => res.write(`data: ${JSON.stringify(data)}\n\n`);
  const interval = setInterval(() => send({ time: Date.now() }), 1000);
  req.on('close', () => clearInterval(interval));
});
```

## WebSocket with exponential backoff reconnect
```typescript
function createWS(url: string) {
  let ws: WebSocket; let retries = 0;
  function connect() {
    ws = new WebSocket(url);
    ws.onclose = () => {
      setTimeout(connect, Math.min(1000 * 2 ** retries, 30000));
      retries++;
    };
    ws.onopen = () => { retries = 0; };
  }
  connect();
  return () => ws;
}
```
