# Windows Advanced Management Suite (WAMS)

##  Genel Bakış

Windows Advanced Management Suite (WAMS), IT yöneticileri ve teknisyenler için geliştirilmiş kapsamlı bir Windows sistem yönetim aracıdır. PowerShell tabanlı bu araç, Windows sistemlerinin performans izleme, bakım, güvenlik, ağ yönetimi ve detaylı raporlama işlemlerini tek bir arayüzden kolayca gerçekleştirmenizi sağlar.

##  Özellikler

WAMS, tek bir araçta toplanmış çok sayıda güçlü özellik sunar:

- ** Sistem Bilgisi** - Donanım, işletim sistemi ve ağ hakkında detaylı bilgiler
- ** Güncelleştirme Yönetimi** - Windows güncelleştirmelerini yönetme
- ** Ağ Yönetimi** - IP yapılandırması, DNS, ping testleri ve Wi-Fi profil yönetimi
- ** Bakım ve Onarım** - Sistem dosyalarını onarma, disk kontrolü ve önbellek temizleme
- ** Performans ve Optimizasyon** - Sistem performansını izleme ve optimize etme
- ** Güvenlik ve Gizlilik** - Windows Defender, güvenlik duvarı ve BitLocker yönetimi
- ** Donanım ve Yazıcı Yönetimi** - Donanım aygıtları ve yazıcıların yönetimi
- ** Kapsamlı Raporlama** - HTML ve CSV formatında detaylı sistem raporları

##  Kurulum

### Gereksinimler

- Windows 10 veya Windows 11 işletim sistemi
- PowerShell 5.1 veya üzeri
- Yönetici hakları (bazı fonksiyonlar için gerekli)
- İnternet bağlantısı (modül kurulumu için)

### Kolay Kurulum

1. Bu repository'yi klonlayın veya ZIP olarak indirin:
   ```
   git clone https://github.com/SLW-Pure/WAMS.git
   ```

2. PowerShell konsolunu yönetici olarak açın:
   - Start menüsüne "PowerShell" yazın
   - PowerShell'e sağ tıklayın ve "Yönetici olarak çalıştır"ı seçin

3. Execution Policy'yi ayarlayın (gerekiyorsa):
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

4. WAMS betiğini çalıştırın:
   ```powershell
   .\Windows-Advanced-Management-Suite.ps1
   ```

5. İlk çalıştırmada "Gerekli Modülleri Kur" seçeneğini kullanarak gerekli PowerShell modüllerini yükleyin.

## Kullanım Kılavuzu

### Ana Menü Navigasyonu

WAMS ana menüsü, numaralandırılmış seçeneklerle kolay navigasyon sunar:

1. İstediğiniz fonksiyon için menü numarasını girin ve Enter tuşuna basın
2. Alt menülerde gezinmek için aynı yöntemi kullanın
3. Bir alt menüden ana menüye dönmek için genellikle son seçeneği (örneğin "Ana Menüye Dön") kullanabilirsiniz

### Temel Modüller

#### 1. Sistem Bilgisi

Sistem bilgisi modülü, bilgisayarınızın genel donanım ve yazılım durumunu hızlı bir şekilde görüntüler:

- İşletim sistemi bilgileri
- İşlemci ve bellek durumu
- Disk kullanımı
- Ağ bilgileri

#### 2. Güncelleştirme Yönetimi

Bu modül, Windows güncelleştirmelerini kontrol etmenizi ve yüklemenizi sağlar:

- Mevcut güncelleştirmeleri listeleme
- Tüm güncelleştirmeleri yükleme
- Belirli güncelleştirmeleri seçip yükleme
- Windows Store uygulamalarını güncelleme

#### 3. Ağ Yönetimi

Ağ yönetimi modülüyle ağ bağlantılarınızı detaylı şekilde yönetebilirsiniz:

- IP yapılandırması görüntüleme 
- DNS önbelleğini temizleme
- Ping ve traceroute testleri
- Ağ adaptörlerini yeniden başlatma
- Wi-Fi profil şifrelerini görüntüleme

#### 4. Bakım ve Onarım

Sistem bakımı ve onarımı için çeşitli araçlar sunar:

- Sistem dosyalarını tarama (SFC)
- Disk kontrolü (CHKDSK)
- Windows image onarımı (DISM)
- Geçici dosyaları temizleme
- Güvenli mod seçenekleri

#### 5. Performans ve Optimizasyon

Sistem performansını izleyip optimize etmenizi sağlar:

- CPU ve bellek kullanımını görüntüleme
- Çalışan süreçleri yönetme
- Disk performansını analiz etme
- Windows animasyonlarını devre dışı bırakma
- Güç planını optimize etme

#### 6. Güvenlik ve Gizlilik

Güvenlik ayarlarını yönetmenize olanak tanır:

- Windows Defender durumunu görüntüleme
- Güvenlik duvarı yapılandırması
- BitLocker şifreleme durumu
- Gizlilik ayarları yönetimi
- Kullanıcı hesapları güvenliği

#### 7. Donanım ve Yazıcı Yönetimi

Donanım aygıtları ve yazıcıları yönetmenizi sağlar:

- Donanım aygıtlarını listeleme
- Sürücüleri güncelleme
- Yazıcı durumunu görüntüleme
- Yazıcı kuyruğunu temizleme
- Sorun gidericileri çalıştırma

#### 8. Sistem Raporlama

Detaylı sistem raporları oluşturmanızı sağlar:

- Temel sistem raporu
- Donanım detaylı raporu
- Yazılım envanteri
- Güvenlik durumu raporu
- Disk kullanım raporu
- Performans raporu
- Olay günlüğü raporu

###  Yönetici Hakları

WAMS, bazı fonksiyonlar için yönetici hakları gerektirir. Bu fonksiyonlar menülerde "(Yönetici)" etiketi ile işaretlenmiştir. Çalıştırma sırasında yönetici haklarına sahip olmadığınız tespit edilirse, WAMS size yönetici olarak yeniden başlatma seçeneği sunacaktır.

##  İpuçları ve En İyi Uygulamalar

- **Düzenli Bakım**: Sistemin optimal performansta çalışması için haftalık bakım rutinleri oluşturun
- **Raporları Arşivleme**: Oluşturduğunuz sistem raporlarını düzenli olarak arşivleyin
- **Güvenlik Kontrolü**: Güvenlik duvarı ve Windows Defender durumunu düzenli olarak kontrol edin
- **Yedekleme**: Herhangi bir önemli sistem değişikliği yapmadan önce yedek almayı unutmayın
- **Otomatik Güncelleştirmeler**: Güvenlik açıklarını önlemek için güncelleştirmeleri düzenli olarak uygulayın

##  Sorun Giderme

### Yaygın Sorunlar

1. **Modül Yükleme Hataları**:
   - İnternet bağlantınızı kontrol edin
   - PowerShell'i yönetici olarak çalıştırın
   - Manuel olarak modülü yükleyin: `Install-Module -Name ModuleName -Force -Scope CurrentUser`

2. **Execution Policy Hataları**:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

3. **Yönetici Hakları Gerekiyor Hatası**:
   - PowerShell'i "Yönetici olarak çalıştır" seçeneğiyle başlatın

4. **Yavaş Performans**:
   - Büyük sistemlerde bazı raporlama işlemleri zaman alabilir, lütfen sabırlı olun

### Hata Bildirim

Bir hata bulduysanız veya öneriniz varsa, lütfen [GitHub Issues](https://github.com/yourusername/windows-advanced-management-suite/issues) bölümünden bildirimde bulunun.

## 📜 Lisans

Bu proje [MIT Lisansı](LICENSE) altında lisanslanmıştır. Detaylar için LICENSE dosyasına bakın.

## 🙏 Katkıda Bulunanlar

- [Adınız](https://github.com/slaweallx) - Geliştirici

## 📞 İletişim

Sorularınız veya geri bildirimleriniz için:
- GitHub: [github.com/slaweallx](https://github.com/slaweallx)
- E-posta: sys@rootali.net

---

⭐ Bu projeye yıldız vererek desteğinizi gösterebilirsiniz!
