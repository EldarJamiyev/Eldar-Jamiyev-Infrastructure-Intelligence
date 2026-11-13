---
name: ios-sideload
description: Sideload, install, and manage iOS apps (.ipa) on iPhone and iPad from Windows using pymobiledevice3, Sideloadly, and AltServer.
---

# iOS App Sideloading & Installation Guide (Windows)

This skill provides complete instructions and commands for installing `.ipa` application packages on iPhone / iPad devices connected to Windows.

## Methods Overview

| Metod | Nə vaxt istifadə edilir | Tələb olunan alət |
|---|---|---|
| **1. CLI / Terminal (Sürətli & AI Uyğun)** | İmzalanmış (ad-hoc / developer) `.ipa` quraşdırmaq | `pymobiledevice3` |
| **2. Sideloadly (GUI - Ən Rahat)** | İxtiyari `.ipa` faylını Apple ID ilə pulsuz imzalayıb quraşdırmaq | `Sideloadly` |
| **3. AltServer / AltStore** | Həftəlik avtomatik yenilənən sideloading | `AltServer` + iTunes |

---

## Metod 1: `pymobiledevice3` (AI və Terminal üçün Tam Avtomatlaşdırılmış)

Kompüterə artıq `pymobiledevice3` quraşdırılıb.

### 1. iPhone-u Kompüterə Qoşun
- USB kabeli vasitəsilə iPhone-u kompüterə qoşun.
- iPhone ekranında **"Bu kompüterə etibar et?" (Trust This Computer)** bildirişi gələndə **"Etibar et" (Trust)** seçin və ekran kodunuzu daxil edin.

### 2. Cihazı Kompüterlə Cütləşdirin (Pairing)
```powershell
python -m pymobiledevice3 lockdown pair
```

### 3. Qoşulmuş iPhone Haqqında Məlumat Alın
```powershell
python -m pymobiledevice3 lockdown info
```

### 4. iPhone-dakı Mövcud Proqramları Siyahılayın
```powershell
python -m pymobiledevice3 apps list
```

### 5. `.ipa` Proqramını iPhone-a Quraşdırın
```powershell
python -m pymobiledevice3 apps install "C:\faylın\yolu\proqram.ipa"
```

### 6. Developer Mode (iOS 16+ üçün)
Əgər iOS 16 və ya daha yeni versiyadırsa, cihazın Developer Mode-unu aktivləşdirmək:
```powershell
python -m pymobiledevice3 amfi enable-developer-mode
```

---

## Metod 2: Sideloadly ilə Quraşdırma (GUI - Ən Populyar)

Sideloadly quraşdırıcı faylı kompüterinizdə yüklənib:
`C:\Users\sahin\Downloads\SideloadlySetup64.exe`

1. **Quraşdırma:** `Downloads` qovluğundakı `SideloadlySetup64.exe` faylını açıb quraşdırın.
2. **İstifadə:**
   - Sideloadly proqramını başladın.
   - iPhone-u USB kabel ilə qoşun.
   - Yükləmək istədiyiniz `.ipa` faylını sürüşdürüb Sideloadly pəncərəsinə atın.
   - Apple ID elektron ünvanınızı daxil edin (tətbiqi sizin adınıza imzalamaq üçün Apple-ın rəsmi mexanizmindən istifadə edir).
   - **Start** düyməsini sıxın. 1-2 dəqiqə ərzində proqram iPhone-a yazılacaq.
3. **iPhone-da İcazə Vermək (Yalnız ilk dəfə):**
   - iPhone-da **Ayarlar (Settings) > Ümumi (General) > VPN və Cihaz İdarəetməsi (VPN & Device Management)** bölməsinə daxil olun.
   - Öz Apple ID-niz üzərinə toxunun və **"Etibar et" (Trust)** seçin.

---

## Metod 3: AltServer ilə Quraşdırma

AltServer arxa fonda işləyir və kompüterlə eyni Wi-Fi şəbəkəsində olduqda tətbiqləri simsiz olaraq hər 7 gündən bir avtomatik yeniləyir.

1. AltServer işə salın (Start Menu > AltServer).
2. Windows bildiriş panelində (saatın yanında) AltServer ikonuna klikləyin.
3. **Install AltStore > [Sizin iPhone]** seçin.
4. Apple ID məlumatlarınızı daxil edin.
5. iPhone-da AltStore proqramı açılacaq və istənilən `.ipa` linkini birbaşa oradan yükləyə bilərsiniz.
