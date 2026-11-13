---
name: dbt-patterns
description: dbt model design, tests, documentation, Jinja macros, incremental models, snapshot
metadata:
  type: skill
  triggers: ["dbt", "data build tool", "analytics engineering", "warehouse", "data modeling", "sql model"]
---

# dbt Patterns

## Model structure
```
models/
  staging/        # 1:1 with source, light cleaning
  intermediate/   # business logic, joins
  marts/          # final wide tables for BI
    fct_orders.sql
    dim_customers.sql
```

## Incremental model
```sql
{{ config(materialized='incremental', unique_key='event_id') }}

SELECT event_id, user_id, event_type, occurred_at
FROM {{ source('raw', 'events') }}
{% if is_incremental() %}
  WHERE occurred_at > (SELECT MAX(occurred_at) FROM {{ this }})
{% endif %}
```

## Tests (schema.yml)
```yaml
models:
  - name: fct_orders
    columns:
      - name: order_id
        tests: [unique, not_null]
      - name: status
        tests:
          - accepted_values: { values: ['pending','shipped','delivered','cancelled'] }
      - name: customer_id
        tests:
          - relationships: { to: ref('dim_customers'), field: customer_id }
```

## Commands
```bash
dbt run
dbt test
dbt run --select marts.fct_orders
dbt docs generate && dbt docs serve
```
