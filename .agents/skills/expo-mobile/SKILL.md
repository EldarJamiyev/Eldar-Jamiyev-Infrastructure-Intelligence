---
name: expo-mobile
description: "Build and ship React Native apps with Expo: Expo Router, native UI, data fetching, native modules, SDK upgrades, EAS Build/Submit/Update. Use for iOS+Android(+web) apps from one React/TS codebase."
---

# expo-mobile — official Expo skills (18 merged into one router)

Source: `expo/skills` (official). Each topic: `references/<name>/main.md` (+ `scripts/`, sub-references). Start with `expo-overview` when unsure — it routes every Expo/EAS task.

| Task | Read |
|---|---|
| Not sure / new to the project | `expo-overview`, `expo-project-structure` |
| Navigation, tabs, modals, links, layouts | `expo-router` |
| Screens that look native (HIG, SF Symbols, blur, gradients) | `expo-native-ui`; real SwiftUI/Compose widgets, sheets, pickers → `expo-ui` (`scripts/list-components.js <project>` lists what's installed) |
| Tokens, theme, reusable components | `expo-design-system` |
| Animations (decide: should it animate, which thread) | `expo-animation` |
| Network, caching, offline, React Query | `expo-data-fetching` |
| Native code (Swift/Kotlin modules/views) | `expo-module` |
| Reuse a web React/Next app | `expo-web-to-native` (full migration) and `expo-dom` (embed web pieces) |
| Examples/integrations (Stripe, Clerk, Supabase, maps, SQLite…) | `expo-examples` |
| Dev builds on device/TestFlight | `expo-dev-client` |
| Build + submit to App Store / Play | `eas-app-stores` |
| OTA updates, CI/CD, web hosting | `eas-update`, `eas-workflows` (`scripts/fetch.js` for cached doc fetch), `eas-hosting` |
| Upgrade SDK | `expo-upgrade` |

Not copied (rarely needed): app clips, brownfield, EAS Observe/Update Insights/cloud simulator, skill-eval/feedback.

## Local notes
- **LinguaLeap is Flutter**, not Expo — don't mix. Use this skill for new RN projects or if the user decides to port. Compare honestly before recommending a rewrite.
- Windows can't build iOS locally: use EAS cloud builds (needs an Expo account; Apple Developer account is paid and required for store/TestFlight). Android builds run locally or on EAS.
- Credentials (Apple/Google signing, EAS tokens) are the user's to enter; never request them in chat.
- Style: Tailwind/NativeWind is optional — follow the project's existing choice. Finish UI with `ui-quality` (touch target 44pt, labels).
