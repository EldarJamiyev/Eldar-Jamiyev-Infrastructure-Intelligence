---
name: taste-art-direction
description: Visual aesthetics, typography, and art direction enforcement for agentic UI design. Enforces quiet luxury design principles, eliminates visual clutter, and validates chart scaling inside data-dense cockpits.
license: MIT
---

# Taste Skill — Art Direction & Visual Aesthetics Enforcement

*Taste Skill* establishes strict aesthetic criteria for agent-generated interfaces. It counteracts the typical "AI dashboard slop" (cluttered gradients, oversized padding, generic cards, misaligned charts) by enforcing refined art direction, precise typographic hierarchy, and elegant data density.

---

## 💎 The Quiet Luxury Aesthetic Rules

1. **Subtle Depth over Loud Gradients**:
   - Use hairline borders (`1px solid rgba(255, 255, 255, 0.08)`) and deep obsidian background levels rather than high-contrast drop shadows.
2. **Intentional Color Economy**:
   - 90% neutral background and foreground tones (charcoal, slate, ash white).
   - Accents (cyan, emerald, amber, rose) reserved strictly for semantic state (healthy, active, warning, critical).
3. **Data-Ink Ratio Optimization**:
   - Remove decorative chart gridlines, excessive legends, and redundant labels.
   - Maximize pixels dedicated to actual data representation.

---

## 💻 EJII Integration: Chart Scaling & Topology Aesthetics

In EJII, this skill governs:
- **3-Pane Packet Dissection Hex View**: Precise byte alignment (16 bytes per row, exact 2-space divider, synchronized monospace glyph widths).
- **Network Topology SVG Canvas**: Dynamic node spacing that scales gracefully without edge overlapping or label truncation.
- **Sparkline & Periodogram Rendering**: Clean vector polylines with translucent gradient fills under curves, scaled to exact container bounds.
