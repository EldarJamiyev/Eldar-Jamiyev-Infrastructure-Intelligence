---
name: threeui
description: Interactive Three.js UI component library and visual layout engine for 3D web apps, games, shaders, and immersive frontend experiences.
---

# threeui

Interactive Three.js UI component library and visual layout engine for 3D web apps, games, shaders, and immersive frontend experiences.

## Quick Command / Usage
```bash
npx threeui
```

## Documentation & Reference
# ThreeUI Community

> **Sponsor ThreeUI:** Linked README placements start at $500/month, with website placements from $1,500/month. [View sponsorship plans](https://threeui.com/sponsorship).

The open-source, login-free edition of ThreeUI. It uses the same application shell, layout, navigation, browse grid, search, themes, responsive behavior, component pages, live renderers, controls, variant picker, and source tabs as the main project.

The catalog is the only product-level difference: Pro and Beta components are removed. Every Community component keeps all of its free variants and controls.

[Browse ThreeUI](https://threeui.com) · [View the source on GitHub](https://github.com/MengTo/threeui)

![ThreeUI Community preview](assets/preview.jpg)

## Sponsor ThreeUI

Sponsorship keeps the open-source Community library maintained and puts your product in front of ThreeUI's developer audience. Website traffic is currently estimated at roughly 90,000 views per day as of 26 August 2026; this is directional traffic context, not a guarantee of sponsor impressions, clicks, or results.

| Plan | Price | Placement and involvement |
| --- | ---: | --- |
| Ecosystem Sponsor | $500/month | Linked banner near the top of the public GitHub README, plus a thank-you credit in this sponsorship section. Up to 6 sponsors. |
| Featured Sponsor | $1,500/month | Everything in Ecosystem, plus a small linked banner in the ThreeUI website documentation sidebar. Up to 2 sponsors. |
| Ultimate Sponsor | $3,000/month | Both banner placements, one approved fixed-scope integration project per agreement, and priority consideration for maintenance needs, sponsor feedback, and reasonable special requests. All work is mutually agreed in writing. |

[See the complete sponsorship details](https://threeui.com/sponsorship) or email [support@designcode.io](mailto:support@designcode.io?subject=ThreeUI%20sponsorship). Sponsorship does not guarantee roadmap changes, editorial control, exclusivity, or private support.

## Included

- 50 Community parent components
- 111 Community routes
- 141 free variant records, plus 23 singleton components (164 browse results)
- Complete Community implementation source and required assets
- No authentication, account state, checkout runtime, Pro implementation, or Beta implementation
- `Get Pro` links to `https://threeui.com/pricing`

## Run locally

```bash
npm install
npm run dev
```

Run the complete publication boundary, type, and production-build checks:

```bash
npm run build
```

## Install the React package

Install the public Community component library from npm:

```bash
npm install @designcodeio/threeui
```

Import a component and the shared styles:

```tsx
import { AtTheHorizon } from "@designcodeio/threeui";
import "@designcodeio/threeui/style.css";

export function Hero() {
  return <AtTheHorizon />;
}
```

For the smallest development import graph, use a component subpath:

```tsx
import { AtTheHorizon } from "@designcodeio/threeui/compone
