---
name: diagram-design
description: Slop-free technical diagramming and layout engineering using native HTML, CSS, and clean SVG vectors without bulky dependencies or unstyled Markdown blobs. Controls rendering performance parameters for EJII's interactive L1–L6 Topological Dependency Graph.
license: MIT
---

# Diagram Design — Slop-Free Technical Layouts & Clean Vector Architecture

Inspired by Cathryn Lavery's *Diagram Design* principles, this skill enforces handcrafted, elegant, high-performance visual technical architecture diagrams using **pure HTML, CSS Grid/Flexbox, and native inline SVG vectors** rather than bloated, unstyled, low-density diagram engines.

---

## 📐 Vector Design Standards

1. **Crisp Monospace Grid Alignment**:
   - Align all diagram bounding boxes to a clean 8px/16px coordinate system.
   - Use crisp 1px strokes with `shape-rendering="crispEdges"` for rectangular frames and orthogonal connectors.
2. **Semantic Color Coding**:
   - Distinct hues for Core Gateways (Emerald), Distribution Switches (Cyan), Edge Endpoints (Slate), and Compromised/APIPA nodes (Amber/Rose).
3. **No Mermaid/Markdown Bloat**:
   - Avoid generic, unstyled markdown graph generators that create excessive whitespace, awkward wrapping, and unreadable labels on complex topologies.

---

## 💻 EJII Integration: L1–L6 Topological Dependency Graph

In EJII, this skill governs the SVG generation in `public/js/components/topology-svg.js`:
- Renders hierarchical Layer 1–6 nodes with fixed card widths (`cardW = 240px`, `colWidth = 255px`).
- Calculates dynamic SVG path splines with smooth cubic Bezier curves (`M x1 y1 C cx1 y1, cx2 y2, x2 y2`).
- Embeds live telemetry pills (Latency, Drop Rate, Blast Radius) directly inside node rects without DOM clipping.
