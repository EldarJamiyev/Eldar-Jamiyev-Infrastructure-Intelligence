---
name: testing-e2e
description: End-to-end testing with Playwright and Cypress — setup, selectors, fixtures, CI
metadata:
  type: skill
  triggers: ["playwright", "cypress", "e2e", "end-to-end", "integration test", "browser test"]
---

# E2E Testing

## Setup
```bash
npx playwright install --with-deps
```

## Page Object pattern
```typescript
export class LoginPage {
  constructor(private page: Page) {}
  async login(email: string, password: string) {
    await this.page.getByLabel('Email').fill(email);
    await this.page.getByLabel('Password').fill(password);
    await this.page.getByRole('button', { name: 'Sign in' }).click();
    await this.page.waitForURL('**/dashboard');
  }
}
```

## Test
```typescript
test('user can purchase product', async ({ page }) => {
  await new LoginPage(page).login('test@example.com', 'password');
  await page.getByText('Product').click();
  await page.getByRole('button', { name: 'Add to cart' }).click();
  await expect(page.getByTestId('cart-count')).toHaveText('1');
});
```

## Selector priority
1. `getByRole` (accessible role)
2. `getByLabel` (form label)
3. `getByTestId` (`data-testid`)
4. Never CSS class or XPath (brittle)

## CI
```yaml
- run: npx playwright install --with-deps
- run: npx playwright test --project=chromium
```
