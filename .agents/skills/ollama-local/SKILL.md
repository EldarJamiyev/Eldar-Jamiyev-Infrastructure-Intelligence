---
name: ollama-local
description: Ollama local LLM setup, Modelfile customization, quantization selection, API integration
metadata:
  type: skill
  triggers: ["ollama", "local llm", "local model", "llama", "mistral local", "modelfile", "quantization"]
---

# Ollama Local LLM

## Install & run
```bash
# Windows: winget install Ollama.Ollama
ollama pull llama3.2          # 3B, fast
ollama pull qwen2.5-coder:7b  # coding
ollama pull nomic-embed-text  # embeddings
```

## Modelfile (custom system prompt)
```
FROM llama3.2
SYSTEM """You are an Azerbaijani assistant. Always respond in Azerbaijani."""
PARAMETER temperature 0.7
PARAMETER num_ctx 8192
```
```bash
ollama create az-assistant -f Modelfile
```

## API (OpenAI-compatible)
```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
response = client.chat.completions.create(
    model="llama3.2",
    messages=[{"role": "user", "content": "Hello"}]
)
```

## Quantization guide
| Format | RAM | Quality |
|--------|-----|---------|
| Q4_K_M | 8GB | Good |
| Q5_K_M | 16GB | Better |
| Q8_0 | 32GB | Near-fp16 |
