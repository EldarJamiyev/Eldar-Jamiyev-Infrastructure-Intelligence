---
name: mobile-testing
description: Detox E2E, Maestro testing, mobile test automation, device farm integration
metadata:
  type: skill
  triggers: ["detox", "maestro", "mobile testing", "appium", "e2e mobile", "mobile automation"]
---

# Mobile Testing

## Maestro (simplest, YAML)
```yaml
appId: com.myapp
---
- launchApp
- tapOn: "Email"
- inputText: "test@example.com"
- tapOn: "Password"
- inputText: "password123"
- tapOn: "Sign In"
- assertVisible: "Dashboard"
```
```bash
maestro test flows/login.yaml
maestro cloud --apiKey $KEY flows/
```

## Detox (React Native)
```javascript
describe('Login Flow', () => {
  beforeAll(async () => { await device.launchApp(); });
  beforeEach(async () => { await device.reloadReactNative(); });

  it('logs in', async () => {
    await element(by.id('email-input')).typeText('test@example.com');
    await element(by.id('password-input')).typeText('password');
    await element(by.id('login-button')).tap();
    await expect(element(by.id('dashboard'))).toBeVisible();
  });
});
```
```bash
detox build --configuration ios.sim.release
detox test --configuration ios.sim.release
```

## Rules
- Use `testID` props on all interactive elements
- Test on real devices for critical paths
- Fresh app launch per test suite
