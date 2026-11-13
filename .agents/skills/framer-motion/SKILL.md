---
name: framer-motion
description: Framer Motion animation patterns — variants, gestures, layout animation, exit animations
metadata:
  type: skill
  triggers: ["framer motion", "animation", "motion", "animate", "transition", "spring"]
---

# Framer Motion

## Basic
```tsx
import { motion } from 'framer-motion';
<motion.div
  initial={{ opacity: 0, y: 20 }}
  animate={{ opacity: 1, y: 0 }}
  exit={{ opacity: 0, y: -20 }}
  transition={{ duration: 0.3, ease: 'easeOut' }}
/>
```

## Variants (stagger children)
```tsx
const container = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.1 } }
};
const item = { hidden: { opacity: 0, x: -20 }, show: { opacity: 1, x: 0 } };

<motion.ul variants={container} initial="hidden" animate="show">
  {items.map(i => <motion.li key={i} variants={item}>{i}</motion.li>)}
</motion.ul>
```

## Layout animation
```tsx
<motion.div layout layoutId="card-1">content</motion.div>
```

## Gestures
```tsx
<motion.button whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
  Click me
</motion.button>
```

## Rules
- Wrap exits in `<AnimatePresence>` for exit animations
- Use `layoutId` for shared element transitions between pages
- Prefer `spring` over `tween` for natural feel
- Respect `prefers-reduced-motion`: check `useReducedMotion()` hook
