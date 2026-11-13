---
name: growth-loops
description: Viral loop design, referral mechanisms, NPS-driven expansion, product-led growth
metadata:
  type: skill
  triggers: ["growth loop", "viral loop", "referral", "product-led growth", "plg", "k-factor", "nps growth"]
---

# Growth Loops

## Loop types
- **Viral**: user invites → new user → invites more (k > 1 = exponential)
- **Content**: user creates → indexed by search → new users discover
- **Data**: more users → better data → better product → more users
- **Paid**: revenue → ads → users → revenue

## K-factor calculation
```
k = i × c
i = invites sent per user (avg)
c = conversion rate on invites

k > 1: exponential growth
k = 0.5: each user brings 0.5 more (acquisition cost halved)
```

## Referral mechanics
```typescript
{
  referrer: { reward: '$20 credit', trigger: 'friend_first_purchase' },
  referee:  { reward: '$10 off first order', shown_at: 'signup' }
}
```

## NPS expansion
```
NPS survey → Promoters (9-10) → trigger referral flow immediately
           → Passives (7-8) → trigger upgrade/feature discovery
           → Detractors (0-6) → route to support, do NOT ask for referral
```

## Activation → growth
Focus: get users to "aha moment" fast (< 5 minutes).
Measure time-to-value. Remove every step between signup and value.
Activated users refer 3x more than non-activated.
