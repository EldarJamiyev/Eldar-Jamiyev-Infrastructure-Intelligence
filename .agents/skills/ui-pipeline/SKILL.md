---
name: ui-pipeline
description: 4-mərhələli ardıcıl UI/UX pipeline — planla, zövq al, qüsursuzlaşdır, cila ver. Trigger: /ui-pipeline
---

# UI Pipeline — 4 Mərhələli Ardıcıl Workflow

Hər UI/UX tapşırığı üçün bu 4 skili **ardıcıl, sırayla** işlət.
Bir mərhələ bitmədən növbətiyə keçmə.

---

## Mərhələ 1 — PLANLA (`ui-ux-pro-max`)

**Skill:** `ui-ux-pro-max`  
**Məqsəd:** UX strategiyası, axın, məzmun prioritetləşdirmə, hiyerarxiya qərarları  
**Çıxış:** Hansı komponentlər, hansı sırada, nə üçün  

İstifadə: `Skill("ui-ux-pro-max")` → planı tamamla, sonra növbəti mərhələyə keç.

---

## Mərhələ 2 — ZÖVQ TƏYİN ET (`taste-skill`)

**Skill:** `taste-skill` (design-taste-frontend)  
**Məqsəd:** Vizual estetika, rəng, tipografiya, boşluq, hiss  
**Çıxış:** Konkret dizayn qərarları — "bu rəng", "bu spacing", "bu font weight"  

İstifadə: `Skill("taste-skill")` → estetika qərarlarını tamamla, sonra növbəti mərhələyə keç.

---

## Mərhələ 3 — QÜSURSUZ İDARƏ ET (`impeccable`)

**Skill:** `impeccable`  
**Məqsəd:** AI-slop detector, accessibility audit, responsive check, P0-P3 findings  
**Çıxış:** Blokerlər aradan qaldırılır, bütün ciddi problemlər həll olunur  

İstifadə: `/impeccable critique` → `/impeccable audit` → bütün P0/P1 fix et, sonra növbəti mərhələyə keç.

---

## Mərhələ 4 — SON CİLALAMA (`better-interface` + `better-ui`)

**Skill:** `better-interface`, `better-ui` (Jakub Krehel)  
**Məqsəd:** Dəqiq dəyərlər, border-radius, shadows, optik alignment, motion  
**Çıxış:** Gönderilməyə hazır, cila verilmiş interfeys  

İstifadə:
1. `Skill("better-interface")` → tam review, ranked report
2. `Skill("better-ui")` → mikro-polish: shadows, border-radius, icon states, animation

Ehtiyaca görə əlavə:
- `better-typography` — mətn rendering problemləri varsa
- `better-colors` — rəng sistemi düzəltmək lazımdırsa
- `better-accessibility` — a11y issues varsa
- `better-writing` — UI copy (label, error, empty state) yoxlanması

---

## Sürətli İstifadə

```
# Tam pipeline:
/ui-pipeline [komponent/səhifə adı]

# Mərhələ-mərhələ:
/ui-ux-pro-max     → planla
/taste             → estetika
/impeccable init   → ilk dəfə, sonra /impeccable critique
/better-interface  → son yoxlama
/better-ui         → mikro-cila
```

## Nə Vaxt Hansı Mərhələni Atlaya Bilərsən

| Ssenari | Atla |
|---------|------|
| Artıq mövcud UI var, yalnız polish lazımdır | Mərhələ 1+2 atla |
| Sıfırdan dizayn | Hamısını et |
| Sürətli bug fix | Yalnız Mərhələ 3 |
| Yalnız vizual polish | Mərhələ 4-dən başla |
