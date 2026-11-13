---
name: linkedin-ads
description: LinkedIn Campaign Manager, Lead Gen Forms, matched audiences, B2B funnel, ABM targeting
metadata:
  type: skill
  triggers: ["linkedin ads", "linkedin campaign", "sponsored content", "lead gen form", "b2b ads", "abm"]
---

# LinkedIn Ads for B2B

## Campaign structure
```
Campaign Group (Budget level)
└── Campaign (Targeting + objective)
    └── Ad (Creative)
```

## Targeting (ranked by precision)
1. **Company list upload** (ABM — most precise)
2. **Job title + seniority + company size**
3. **Skills + member groups**
4. **Lookalike** (based on existing customers)
5. **Interest targeting** (least precise, cheapest)

## Lead Gen Form
```
Fields (keep minimal — 3-4 max):
- Pre-filled: First name, Last name, Email, Job title, Company
- Custom: "What's your biggest challenge?" (qualification)
```

## CPL benchmarks (B2B SaaS)
- Sponsored Content: $50-200 CPL
- Message Ads: $30-80 CPL
- Lead Gen Forms: $40-120 CPL

## Rules
- Minimum audience: 50,000
- Frequency cap: 4 impressions/month per member
- Test: single variable per experiment
- Exclude: existing customers, current leads from targeting
