---
name: stripe-integration
description: Stripe checkout sessions, subscriptions, webhook handling, refunds, test mode
metadata:
  type: skill
  triggers: ["stripe", "payment", "subscription", "checkout", "billing", "webhook stripe"]
---

# Stripe Integration

## Checkout session
```typescript
const session = await stripe.checkout.sessions.create({
  payment_method_types: ['card'],
  mode: 'subscription',
  line_items: [{ price: 'price_xxx', quantity: 1 }],
  success_url: `${BASE_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
  cancel_url: `${BASE_URL}/cancel`,
  customer_email: user.email,
  metadata: { userId: user.id },
});
```

## Webhook (must verify signature)
```typescript
app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature']!;
  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET!);
  } catch (err) {
    return res.status(400).send('Webhook signature verification failed');
  }
  switch (event.type) {
    case 'checkout.session.completed':
      await activateSubscription(event.data.object.metadata.userId);
      break;
    case 'customer.subscription.deleted':
      await deactivateSubscription(event.data.object.customer as string);
      break;
  }
  res.json({ received: true });
});
```

## Rules
- Always verify webhook signature
- Idempotency: check if event.id already processed
- Test cards: 4242424242424242
- Never store card numbers — Stripe stores them
