---
name: sql-optimization
description: PostgreSQL EXPLAIN ANALYZE, index strategy, CTE, window functions, query optimization
metadata:
  type: skill
  triggers: ["sql optimize", "explain analyze", "slow query", "index strategy", "window function", "cte"]
---

# SQL Optimization

## EXPLAIN ANALYZE
```sql
EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
SELECT * FROM orders WHERE user_id = 123 AND status = 'pending';
```
Look for: Seq Scan on large tables, high actual vs estimated rows, high cost.

## Index strategy
```sql
CREATE INDEX CONCURRENTLY idx_orders_user ON orders(user_id);

-- Composite (equality first, range last)
CREATE INDEX CONCURRENTLY idx_orders_user_status ON orders(user_id, status);

-- Partial
CREATE INDEX CONCURRENTLY idx_orders_pending ON orders(user_id) WHERE status = 'pending';

-- Expression
CREATE INDEX CONCURRENTLY idx_users_email_lower ON users(LOWER(email));
```

## Window functions
```sql
SELECT date, revenue,
  SUM(revenue) OVER (ORDER BY date ROWS UNBOUNDED PRECEDING) AS cumulative
FROM daily_sales;

SELECT user_id, order_total,
  RANK() OVER (PARTITION BY user_id ORDER BY order_total DESC) AS rank
FROM orders;
```

## Rules
- CONCURRENTLY: build indexes without locking production
- Avoid `SELECT *` in production
- Use `LIMIT` on large tables when exploring
- Check `pg_stat_user_tables` for sequential scans
