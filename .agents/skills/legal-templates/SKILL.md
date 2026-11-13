---
name: legal-templates
description: Privacy Policy, Terms of Service, NDA, GDPR/KVKK compliance templates for SaaS products
metadata:
  type: skill
  triggers: ["privacy policy", "terms of service", "tos", "nda", "gdpr", "kvkk", "legal", "cookie policy"]
---

# Legal Templates for SaaS

## Privacy Policy must-haves (GDPR/KVKK)
1. What data you collect (exhaustive list)
2. Why you collect it (legal basis: consent / legitimate interest / contract)
3. Who you share it with (third parties, cloud providers)
4. How long you keep it (retention periods)
5. User rights: access, deletion, portability, rectification
6. Contact: DPO/data controller name + email
7. Last updated date

## Terms of Service must-haves
1. Who can use (eligibility)
2. Account terms (responsibilities, security)
3. Acceptable use policy
4. Intellectual property ownership
5. Payment terms
6. Limitation of liability
7. Governing law + jurisdiction
8. How to terminate account

## Cookie consent (GDPR)
```javascript
const consent = {
  necessary: true,  // always
  analytics: false, // need consent
  marketing: false  // need consent
};
// Set cookies ONLY after checking consent[type] === true
```

## NDA key clauses
- Definition of Confidential Information
- Exclusions (already public, independently developed)
- Term (start date + duration, 2-5 years)
- Permitted disclosures (legal requirement, employees)
- Return/destruction of materials

⚠️ Templates only. Have a lawyer review before use.
