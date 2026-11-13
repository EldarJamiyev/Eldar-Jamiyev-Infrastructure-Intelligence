---
name: ai-evals
description: LLM evaluation — RAGAS, LLM-as-judge, benchmark creation, regression tracking
metadata:
  type: skill
  triggers: ["eval", "evaluation", "benchmark", "llm judge", "ragas", "accuracy", "measure llm"]
---

# LLM Evaluation

## Eval types
- **Unit**: single input → expected output (deterministic)
- **Model-graded**: LLM-as-judge scores quality
- **Human**: golden dataset comparison
- **System**: end-to-end pipeline metrics (RAG: faithfulness, relevance)

## LLM-as-judge
```python
JUDGE_PROMPT = """
Score 1-5 on accuracy, completeness, conciseness.
Question: {question}
Response: {response}
Return JSON: {"accuracy": N, "completeness": N, "conciseness": N, "reasoning": "..."}
"""

def judge(question: str, response: str) -> dict:
    result = claude.messages.create(
        model="claude-opus-5-5",
        messages=[{"role": "user", "content": JUDGE_PROMPT.format(question=question, response=response)}]
    )
    return json.loads(result.content[0].text)
```

## RAGAS for RAG
```python
from ragas import evaluate
from ragas.metrics import faithfulness, answer_relevancy, context_precision
result = evaluate(dataset, metrics=[faithfulness, answer_relevancy, context_precision])
```

## Regression tracking
- Save results to JSON with timestamp
- Alert if key metric drops > 5% between model versions
- Track: accuracy, latency p50/p95, cost per query
