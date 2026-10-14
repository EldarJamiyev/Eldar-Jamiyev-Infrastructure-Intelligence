# EJI Mobile Companion Client Architecture (Phase 14)

## Overview
The **EJI Mobile Companion Client** is purpose-built for on-call SREs, network engineers, and application owners who need to receive real-time infrastructure alerts, inspect root-cause analysis (RCA) correlation trees, run rapid Layer 3–7 network probes from anywhere, and authorize Tier 3 remediation actions through touch-optimized dual-custody approval workflows.

---

## Key Capabilities

1. **Swipe-to-Approve Touch Gesture**:
   - Remediation actions requiring dual custody (Tier 3) present an interactive swipe slider.
   - Requires deliberate horizontal swipe exceeding 75% of container width before triggering authorization.
   - Provides tactile haptic feedback (`navigator.vibrate`) on completion.
   - Audit logs capture `EJI Mobile Swipe Gesture` in the cryptographic HMAC trail.

2. **Biometric Dual-Custody Gate**:
   - Integrates with device WebAuthn / Biometrics (Face ID, Touch ID, Windows Hello, Android BiometricPrompt).
   - Authorizes requests with high-assurance cryptographic key assertions.

3. **Offline Alert Caching**:
   - Automatically caches active incident lists into persistent client storage (`localStorage` / `CacheStorage`).
   - If the corporate network or VPN drops, the client retains the last-known state and warns the operator that offline data is displayed.

4. **Rapid Diagnostics**:
   - Real ICMP ping and TCP socket port checks (ports 80, 443, custom) directly against internal nodes via backend relays.

---

## Deployment & Packaging Targets

### Option A: Progressive Web App (PWA)
- Fully installable on iOS (Safari "Add to Home Screen") and Android (Chrome "Install App").
- Service Worker (`public/sw.js`) caches application assets for immediate offline loading.

### Option B: Native Packaging via Capacitor
To wrap into an iOS IPA or Android APK:
```bash
npm install @capacitor/core @capacitor/cli @capacitor/ios @capacitor/android
npx cap init "EJI Mobile" "com.eldarjamiyev.eji" --web-dir mobile
npx cap add android
npx cap add ios
npx cap sync
```
