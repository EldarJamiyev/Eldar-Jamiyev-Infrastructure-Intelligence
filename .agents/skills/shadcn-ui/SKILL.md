---
name: shadcn-ui
description: shadcn/ui component system — setup, theming, dark mode, Radix primitives, customization
metadata:
  type: skill
  triggers: ["shadcn", "shadcn/ui", "radix", "ui components", "component library"]
---

# shadcn/ui

## Setup
```bash
npx shadcn@latest init
npx shadcn@latest add button card dialog form input table
```

## Usage
```tsx
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";

<Dialog open={open} onOpenChange={setOpen}>
  <DialogContent>
    <DialogHeader><DialogTitle>Confirm</DialogTitle></DialogHeader>
    <Button onClick={() => setOpen(false)}>Confirm</Button>
  </DialogContent>
</Dialog>
```

## Form + zod
```tsx
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Form, FormField, FormItem, FormLabel, FormControl } from "@/components/ui/form";

const form = useForm<z.infer<typeof schema>>({ resolver: zodResolver(schema) });
```

## Theme (globals.css)
```css
:root { --primary: 240 5.9% 10%; --radius: 0.5rem; }
.dark { --primary: 0 0% 98%; }
```

## Rules
- Components live in `components/ui/` — edit them directly
- Don't import from `shadcn` package — copy-pasted to your project
- Use `cn()` for conditional classes
- Extend with `className` prop, not wrapper divs
