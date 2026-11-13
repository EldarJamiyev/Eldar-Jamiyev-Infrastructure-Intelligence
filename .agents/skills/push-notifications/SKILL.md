---
name: push-notifications
description: FCM/APNs push notifications, Expo Notifications, topic subscriptions, notification templates
metadata:
  type: skill
  triggers: ["push notifications", "fcm", "apns", "firebase messaging", "expo notifications", "notification"]
---

# Push Notifications

## Expo Notifications setup
```typescript
import * as Notifications from 'expo-notifications';

async function registerForPushNotifications() {
  const { status } = await Notifications.requestPermissionsAsync();
  if (status !== 'granted') return null;
  
  const token = await Notifications.getExpoPushTokenAsync({
    projectId: Constants.expoConfig?.extra?.eas?.projectId,
  });
  return token.data;
}
```

## Send via Expo Push API
```typescript
const message = {
  to: expoPushToken,
  sound: 'default',
  title: 'New message',
  body: 'You have a new message!',
  data: { screen: 'Chat', chatId: '123' },
};

await fetch('https://exp.host/--/api/v2/push/send', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(message),
});
```

## FCM (direct, production)
```typescript
const admin = require('firebase-admin');
await admin.messaging().send({
  token: fcmToken,
  notification: { title: 'Hello', body: 'World' },
  data: { screen: 'Home' },
  android: { priority: 'high' },
  apns: { payload: { aps: { sound: 'default' } } }
});
```

## Rules
- Always handle permission denial gracefully
- Store push tokens in DB, link to user
- Implement token refresh (tokens expire/change)
- Deep link: use `data` payload to navigate on tap
