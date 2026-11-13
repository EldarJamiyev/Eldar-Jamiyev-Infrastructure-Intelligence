---
name: ga4-gtm
description: GA4 event tracking, GTM container setup, custom dimensions, conversion events, funnel analysis
metadata:
  type: skill
  triggers: ["ga4", "google analytics", "gtm", "google tag manager", "analytics tracking", "conversion tracking"]
---

# GA4 + GTM

## dataLayer push
```javascript
window.dataLayer = window.dataLayer || [];
window.dataLayer.push({
  event: 'purchase',
  ecommerce: {
    transaction_id: 'T12345',
    value: 25.99,
    currency: 'USD',
    items: [{ item_id: 'SKU123', item_name: 'Product', price: 25.99, quantity: 1 }]
  }
});
```

## Event naming convention
- snake_case: `add_to_cart`, `begin_checkout`, `purchase`
- Standard: GA4 auto-collects `page_view`, `scroll`, `click`, `file_download`
- Custom: prefix with app name `myapp_feature_used`

## GTM Container structure
- Variables → User-defined (dataLayer vars, JS vars)
- Triggers → Page view, click, form submission, custom event
- Tags → GA4 Config, GA4 Event, Conversion Linker

## Funnel analysis
1. Mark conversion steps as GA4 events
2. Explorations → Funnel exploration → add steps in order
3. Segment by user type to find drop-off

## Debugging
- GTM preview mode before publish
- GA4 DebugView: `?debug=1` URL param or GA4 Debugger Chrome extension
