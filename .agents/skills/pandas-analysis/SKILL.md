---
name: pandas-analysis
description: Pandas/Polars data wrangling, EDA patterns, missing data handling, feature engineering
metadata:
  type: skill
  triggers: ["pandas", "polars", "dataframe", "data analysis", "eda", "data wrangling", "numpy"]
---

# Data Analysis

## EDA checklist
```python
df.info()              # dtypes, nulls
df.describe()          # stats
df.duplicated().sum()  # duplicates
df.isnull().sum()      # missing per column
df.nunique()           # cardinality
```

## Missing data
```python
df['col'].fillna(df['col'].median())   # numeric
df['col'].fillna('Unknown')            # categorical
df['col'].ffill()                        # time series (pandas 2.0+, fillna(method='ffill') deprecated)
# Drop if > 50% null:
df.dropna(thresh=int(0.5 * len(df.columns)), axis=0)
```

## Feature engineering
```python
df['year'] = df['date'].dt.year
df['month'] = df['date'].dt.month
df['day_of_week'] = df['date'].dt.dayofweek

df['age_group'] = pd.cut(df['age'], bins=[0,18,35,60,100],
    labels=['child','young','middle','senior'])

df = pd.get_dummies(df, columns=['category'], drop_first=True)
```

## Polars (faster for large data)
```python
import polars as pl
result = (pl.read_csv('data.csv')
  .filter(pl.col('status') == 'active')
  .group_by('category')
  .agg(pl.col('revenue').sum().alias('total_revenue'))
  .sort('total_revenue', descending=True)
)
```
