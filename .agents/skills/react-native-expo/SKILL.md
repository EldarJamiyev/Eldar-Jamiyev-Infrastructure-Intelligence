---
name: react-native-expo
description: Expo managed workflow, navigation, state management, EAS Build, OTA updates
metadata:
  type: skill
  triggers: ["react native", "expo", "react-native", "mobile react", "eas build", "expo router"]
---

# React Native + Expo

## Setup
```bash
npx create-expo-app MyApp --template
cd MyApp && npx expo start
```

## Expo Router (file-based navigation)
```
app/
  _layout.tsx     # root layout
  index.tsx       # home screen
  (tabs)/
    _layout.tsx   # tab bar layout
    home.tsx
    profile.tsx
  [id].tsx        # dynamic route
```

## State (Zustand)
```typescript
import { create } from 'zustand';
const useStore = create<AppState>((set) => ({
  user: null,
  setUser: (user) => set({ user }),
}));
```

## EAS Build
```bash
npm install -g eas-cli
eas login
eas build:configure
eas build --platform android --profile preview
eas build --platform ios --profile production
```

## OTA updates
```bash
eas update --branch production --message "Fix login bug"
```

## Rules
- Use Expo SDK versions with LTS support
- `expo-secure-store` for sensitive data (not AsyncStorage)
- Test on real devices before EAS build
- Configure `app.json` before first build (bundle ID, version)
