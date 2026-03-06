# 🛡️ CyberShield: Password Integrity & Leak Analyzer

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.30+-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-K--Anonymity-blueviolet?style=for-the-badge&logo=hackthebox&logoColor=white)

**Şifrenizin gerçekten ne kadar güvenli olduğunu öğrenin.**

*Veri sızıntısı kontrolü · Güvenlik skoru · Brute-force simülasyonu*

</div>

---


---

## 🚀 Özellikler

### 🔍 Veri Sızıntısı Kontrolü (Have I Been Pwned)
- **K-Anonymity** yöntemiyle şifreniz asla düz metin olarak sunucuya gönderilmez
- SHA-1 hash'inin yalnızca ilk 5 karakteri API'ye iletilir
- Tam eşleşme tamamen **yerel cihazda** kontrol edilir
- Şifrenizin kaç kez veri ihlallerinde görüldüğü raporlanır

### 📊 Güvenlik Skoru (zxcvbn)
- 0-4 arası karmaşıklık skoru
- Entropi değeri ve kırılma süresi tahmini
- Türkçe geri bildirim ve iyileştirme önerileri
- Kullanılan karakter türlerinin analizi

### ⚡ Brute-Force Kırılma Simülasyonu
| Senaryo | Hız |
|---------|-----|
| 🖥️ Standart PC | 10.000 deneme/sn |
| 🎮 GPU Kümesi | 100 milyar deneme/sn |

### Modern Arayüz
- Renkli ilerleme çubukları ve metrik kartları
- Güvenli şifre oluşturma ipuçları (sidebar)
- K-Anonymity açıklaması

---

##  Kurulum

### Gereksinimler
- Python 3.8 veya üzeri
- İnternet bağlantısı (HIBP API için)

### Adımlar

```bash
# 1. Repoyu klonlayın
git clone https://github.com/eneskavakk/cybershield.git
cd cybershield

# 2. Bağımlılıkları yükleyin
pip install -r requirements.txt

# 3. Uygulamayı başlatın
streamlit run app.py
```

Uygulama varsayılan olarak `http://localhost:8501` adresinde açılacaktır.

---

## Proje Yapısı

```
cybershield/
├── app.py              # Ana Streamlit uygulaması
├── requirements.txt    # Python bağımlılıkları
└── README.md           # Bu dosya
```

---

##  Güvenlik & Gizlilik

> **Şifreniz asla düz metin olarak kaydedilmez, loglanmaz veya sunucuya gönderilmez.**

Bu uygulama [K-Anonymity](https://en.wikipedia.org/wiki/K-anonymity) modelini kullanır:

1. Şifrenin **SHA-1 hash'i** hesaplanır
2. Hash'in yalnızca **ilk 5 karakteri** HIBP API'ye gönderilir
3. API, bu ön-ek ile eşleşen yüzlerce hash döndürür
4. Tam eşleşme **sizin cihazınızda** kontrol edilir

Bu sayede ne HIBP sunucusu ne de ağı dinleyen bir saldırgan şifrenizi öğrenemez.

---

## ⚙️ Kullanılan Teknolojiler

| Teknoloji | Amaç |
|-----------|-------|
| [Streamlit](https://streamlit.io/) | Web arayüzü framework'ü |
| [requests](https://docs.python-requests.org/) | HTTP istekleri (HIBP API) |
| [zxcvbn](https://github.com/dwolfhuis/zxcvbn-python) | Şifre güvenlik analizi |
| [Have I Been Pwned](https://haveibeenpwned.com/) | Veri sızıntısı veritabanı |

---

## ⚠️ Hata Yönetimi

Uygulama aşağıdaki senaryoları `try-except` blokları ile yönetir:

- ⏱️ **Timeout** – API yanıt vermezse kullanıcı bilgilendirilir
- 🚦 **Rate Limit (429)** – Çok fazla istek gönderimleri yakalanır
- 🔌 **Bağlantı Hatası** – İnternet kesintisi durumları ele alınır
- ❌ **Genel Hatalar** – Beklenmeyen durumlar kullanıcıya gösterilir

API başarısız olsa bile yerel analiz (zxcvbn + brute-force) çalışmaya devam eder.

---



---

<div align="center">

**🛡️ CyberShield** ile şifrelerinizi güvende tutun.

*Bu uygulama yalnızca eğitim ve farkındalık amaçlıdır.*

</div>
