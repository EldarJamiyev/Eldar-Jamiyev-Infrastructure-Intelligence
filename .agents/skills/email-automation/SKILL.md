---
name: email-automation
description: Klaviyo/Mailchimp flow design, segmentation, deliverability, transactional email, A/B testing
metadata:
  type: skill
  triggers: ["email automation", "klaviyo", "mailchimp", "sendgrid", "email flow", "drip campaign"]
---

# Email Automation

## Flow types
- **Welcome series**: Day 0, 3, 7 — onboard, educate, convert
- **Abandoned cart**: 1hr, 24hr, 72hr — urgency escalation
- **Win-back**: 60d, 90d inactive — special offer
- **Post-purchase**: confirmation, shipping, review request (Day 7)

## Segmentation
```
High-value: LTV > $200 AND orders > 2
At-risk: last_purchase > 90d AND LTV > $100
Engaged: email_open_rate > 20% AND last_30d
New: created_at < 30d ago
```

## Deliverability checklist
- SPF, DKIM, DMARC configured
- Warm up new IPs: start 200/day, double weekly
- Remove hard bounces immediately
- Unsubscribe in 1-click (CAN-SPAM/GDPR)

## SendGrid transactional
```typescript
import sendgrid from '@sendgrid/mail';
sendgrid.setApiKey(process.env.SENDGRID_API_KEY!);
await sendgrid.send({
  to: user.email,
  from: 'noreply@myapp.com',
  templateId: 'd-xxxxx',
  dynamicTemplateData: { name: user.name, link: resetUrl },
});
```

## A/B test ranked by impact
1. Subject line (40% open rate impact)
2. Send time
3. CTA copy + color
4. Personalization tokens
