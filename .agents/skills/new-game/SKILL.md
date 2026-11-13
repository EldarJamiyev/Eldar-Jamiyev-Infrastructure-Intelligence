---
name: new-game
description: >
  Yeni oyun layihəsi yaratmaq üçün istifadə et. Trigger: istifadəçi "oyun yarat",
  "game yarat", "create game", "oyun hazırla", "oyun başlat", "yeni oyun",
  "make a game", "build a game" və ya hər hansı oyun layihəsi açmaq istəyini bildirdikdə
  bu skilin işə sal. Suallar ver, sonra New-Game PowerShell funksiyasını çalıştır
  və Claude Code Game Studios sistemini aktiv et.
---

# New Game Skill

İstifadəçi oyun yaratmaq istəyəndə aşağıdakı addımları izlə:

## Addım 1 — Dəqiqləşdirici suallar ver

Aşağıdakı sualları ardıcıl ver (cavab gözlə):

**1. Oyunun adı nədir?**
(İstifadəçi artıq adı söyləyibsə, təkrar soruşma)

**2. Hansı engine istifadə edəcəksən?**
- Godot 4 (pulsuz, açıq mənbə, Python-a bənzər GDScript)
- Unity (C#, böyük ekosistem)
- Unreal Engine 5 (C++/Blueprint, AAA keyfiyyət)
- Hələ bilmirəm / Mühüm deyil

**3. Oyun növü nədir?**
- 2D / 3D
- Janr: RPG, platformer, puzzle, shooter, strategy, simulation, horror, adventure, arcade...

**4. Multiplayer olacaq?**
- Tək oyunçu
- Multiplayer (local / online)

**5. Hədəf platforma?**
- PC (Windows/Mac/Linux)
- Mobile (Android/iOS)
- Console
- Web (browser)

## Addım 2 — Xülasə göstər, təsdiqlət

Bütün cavabları topla və belə bir xülasə göstər:

```
📋 Oyun planı:
  Ad:        [ad]
  Engine:    [engine]
  Növ:       [2D/3D] [janr]
  Platforma: [platforma]
  Mode:      [single/multi]

Davam edirəm? (bəli/xeyr)
```

## Addım 3 — Layihə yarat

Təsdiq gəldikdən sonra PowerShell-də çalıştır:

```powershell
New-Game "[ad]" -Engine [godot|unity|unreal|generic]
```

Sonra istifadəçiyə de:
- Layihə qovluğu: `C:\Claude\games\[ad]\`
- `cd 'C:\Claude\games\[ad]'` və `claude` yaz
- Claude Code açıldıqda `/start` yaz — Game Studios tam işə düşür

## Addım 4 — Engine seçiminə görə ilk addımları izah et

**Godot seçilibsə:**
- Godot 4 yüklü deyilsə: https://godotengine.org/download
- `/start` → `/setup-engine` → `game-designer` agenti devreye girer

**Unity seçilibsə:**
- Unity Hub lazımdır
- `/start` → `/setup-engine` → unity-specialist agent

**Unreal seçilibsə:**
- Epic Games Launcher lazımdır
- `/start` → `/setup-engine` → unreal-specialist agent

## Qeydlər
- Engine hələ məlum deyilsə `generic` istifadə et
- Ad boşluq ehtiva edirsə tire ilə əvəz et: "My RPG" → "My-RPG"
- Template `C:\Claude\templates\game-studios\`-dən gəlir, avtomatik yenilənir
