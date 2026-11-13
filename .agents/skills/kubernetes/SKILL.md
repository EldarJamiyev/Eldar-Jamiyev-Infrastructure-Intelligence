---
name: kubernetes
description: K8s manifests, Helm charts, pod autoscaling, ingress, secrets, deployment strategies
metadata:
  type: skill
  triggers: ["kubernetes", "k8s", "kubectl", "helm", "pod", "deployment", "ingress"]
---

# Kubernetes Patterns

## Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      containers:
      - name: myapp
        image: myapp:1.2.3
        resources:
          requests: { cpu: "100m", memory: "128Mi" }
          limits: { cpu: "500m", memory: "512Mi" }
        livenessProbe:
          httpGet: { path: /health, port: 3000 }
          initialDelaySeconds: 10
        readinessProbe:
          httpGet: { path: /ready, port: 3000 }
```

## Service + Ingress
```yaml
apiVersion: v1
kind: Service
spec:
  selector: { app: myapp }
  ports: [{ port: 80, targetPort: 3000 }]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
spec:
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service: { name: myapp, port: { number: 80 } }
```

## Rules
- Always set resource requests/limits
- Readiness probe: no traffic until ready
- Never store secrets in YAML — use Kubernetes Secrets
- HPA: target 70% CPU
- Rolling update: `maxUnavailable: 0`
- Never use `latest` image tag
