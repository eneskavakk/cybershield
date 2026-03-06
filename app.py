"""
CyberShield: Password Integrity & Leak Analyzer
================================================
Kullanıcının girdiği şifrenin güvenliğini analiz eder ve
Have I Been Pwned API ile sızdırılıp sızdırılmadığını kontrol eder.

GÜVENLİK NOTU: Şifreler asla düz metin olarak kaydedilmez veya loglanmaz.
HIBP sorguları K-Anonymity yöntemiyle yapılır.
"""

import hashlib
import math
import string
import streamlit as st
import requests
from zxcvbn import zxcvbn


# ─────────────────────────────────────────────
# Sayfa Yapılandırması
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="CyberShield – Password Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────
# Özel CSS Stilleri
# ─────────────────────────────────────────────
st.markdown(
    """
    <style>
    /* ── Genel Arka Plan ── */
    .stApp {
        background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
    }

    /* ── Başlık Stili ── */
    .main-title {
        text-align: center;
        background: linear-gradient(90deg, #00f2fe, #4facfe, #00f2fe);
        background-size: 200% auto;
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        animation: shine 3s linear infinite;
        font-size: 2.8rem;
        font-weight: 800;
        margin-bottom: 0;
        letter-spacing: 2px;
    }
    @keyframes shine {
        to { background-position: 200% center; }
    }

    .sub-title {
        text-align: center;
        color: #8892b0;
        font-size: 1.05rem;
        margin-top: -8px;
        margin-bottom: 30px;
    }

    /* ── Kart Stili ── */
    .cyber-card {
        background: rgba(255,255,255,0.04);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 16px;
        padding: 24px;
        margin-bottom: 20px;
        backdrop-filter: blur(12px);
    }
    .cyber-card h3 {
        margin-top: 0;
        color: #ccd6f6;
    }

    /* ── Skor Göstergesi ── */
    .score-badge {
        display: inline-block;
        padding: 6px 20px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 1rem;
        letter-spacing: 1px;
    }
    .score-0 { background: #ff4757; color: #fff; }
    .score-1 { background: #ff6348; color: #fff; }
    .score-2 { background: #ffa502; color: #1a1a2e; }
    .score-3 { background: #2ed573; color: #1a1a2e; }
    .score-4 { background: #1dd1a1; color: #1a1a2e; }

    /* ── Uyarı Kutuları ── */
    .leak-danger {
        background: rgba(255,71,87,0.15);
        border-left: 4px solid #ff4757;
        padding: 16px 20px;
        border-radius: 8px;
        color: #ff6b81;
        font-size: 1.05rem;
    }
    .leak-safe {
        background: rgba(46,213,115,0.12);
        border-left: 4px solid #2ed573;
        padding: 16px 20px;
        border-radius: 8px;
        color: #7bed9f;
        font-size: 1.05rem;
    }

    /* ── Sidebar ── */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #1a1a2e 0%, #16213e 100%);
    }
    section[data-testid="stSidebar"] .stMarkdown h1,
    section[data-testid="stSidebar"] .stMarkdown h2,
    section[data-testid="stSidebar"] .stMarkdown h3 {
        color: #4facfe;
    }

    /* ── Metrik Kutucukları ── */
    [data-testid="stMetric"] {
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 12px;
        padding: 12px 16px;
    }

    /* ── İlerleme Çubuğu ── */
    .stProgress > div > div {
        border-radius: 8px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ─────────────────────────────────────────────
# Yardımcı Fonksiyonlar
# ─────────────────────────────────────────────

def check_hibp(password: str) -> dict:
    """
    Have I Been Pwned API ile K-Anonymity yöntemini kullanarak
    şifrenin sızdırılıp sızdırılmadığını kontrol eder.

    Şifrenin SHA-1 hash'inin yalnızca ilk 5 karakteri API'ye gönderilir.
    Geri kalan kısım lokal olarak eşleştirilir. Şifre asla düz metin
    olarak ağ üzerinden iletilmez.
    """
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    try:
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "CyberShield-PasswordAnalyzer"},
            timeout=10,
        )
        response.raise_for_status()

        for line in response.text.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix.strip() == suffix:
                return {"found": True, "count": int(count.strip()), "error": None}

        return {"found": False, "count": 0, "error": None}

    except requests.exceptions.Timeout:
        return {"found": None, "count": 0, "error": "⏱️ API isteği zaman aşımına uğradı. Lütfen tekrar deneyin."}
    except requests.exceptions.ConnectionError:
        return {"found": None, "count": 0, "error": "🔌 Bağlantı hatası. İnternet bağlantınızı kontrol edin."}
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 429:
            return {"found": None, "count": 0, "error": "🚦 Çok fazla istek gönderildi (Rate Limit). Biraz bekleyip tekrar deneyin."}
        return {"found": None, "count": 0, "error": f"🌐 HTTP Hatası: {e}"}
    except Exception as e:
        return {"found": None, "count": 0, "error": f"❌ Beklenmeyen hata: {e}"}


def analyze_password(password: str) -> dict:
    """zxcvbn ile şifre gücünü analiz eder."""
    return zxcvbn(password)


def format_time(seconds: float) -> str:
    """Saniye cinsinden süreyi okunabilir formata çevirir."""
    if seconds < 1:
        return "< 1 saniye"
    if seconds < 60:
        return f"{seconds:.1f} saniye"
    if seconds < 3600:
        return f"{seconds / 60:.1f} dakika"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} saat"
    if seconds < 86400 * 365:
        return f"{seconds / 86400:.1f} gün"
    if seconds < 86400 * 365 * 1000:
        return f"{seconds / (86400 * 365):.1f} yıl"
    if seconds < 86400 * 365 * 1e6:
        return f"{seconds / (86400 * 365 * 1000):.1f} bin yıl"
    if seconds < 86400 * 365 * 1e9:
        return f"{seconds / (86400 * 365 * 1e6):.1f} milyon yıl"
    return f"{seconds / (86400 * 365 * 1e9):.1f} milyar yıl"


def calculate_keyspace(password: str) -> int:
    """Şifrede kullanılan karakter sınıflarına göre anahtar uzayını hesaplar."""
    charset_size = 0
    if any(c in string.ascii_lowercase for c in password):
        charset_size += 26
    if any(c in string.ascii_uppercase for c in password):
        charset_size += 26
    if any(c in string.digits for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += 32
    # Diğer Unicode karakterler
    if any(ord(c) > 127 for c in password):
        charset_size += 100

    if charset_size == 0:
        charset_size = 26  # Fallback

    return charset_size ** len(password)


def brute_force_time(keyspace: int, rate: float) -> float:
    """Verilen anahtar uzayı ve deneme hızına göre kırılma süresini (saniye) hesaplar."""
    return keyspace / rate


def get_score_label(score: int) -> tuple:
    """Skor değerine göre etiket ve renk döndürür."""
    labels = {
        0: ("Çok Zayıf", "score-0"),
        1: ("Zayıf", "score-1"),
        2: ("Orta", "score-2"),
        3: ("Güçlü", "score-3"),
        4: ("Çok Güçlü", "score-4"),
    }
    return labels.get(score, ("Bilinmiyor", "score-0"))


def get_char_classes(password: str) -> list:
    """Şifrede kullanılan karakter sınıflarını döndürür."""
    classes = []
    if any(c in string.ascii_lowercase for c in password):
        classes.append("🔤 Küçük harf")
    if any(c in string.ascii_uppercase for c in password):
        classes.append("🔠 Büyük harf")
    if any(c in string.digits for c in password):
        classes.append("🔢 Rakam")
    if any(c in string.punctuation for c in password):
        classes.append("🔣 Özel karakter")
    if any(ord(c) > 127 for c in password):
        classes.append("🌐 Unicode karakter")
    return classes


# ─────────────────────────────────────────────
# zxcvbn Türkçe Çeviri Sözlüğü
# ─────────────────────────────────────────────
ZXCVBN_TR = {
    # ── Uyarılar (warnings) ──
    "Straight rows of keys are easy to guess.": "Klavyede düz sıralı tuşlar kolayca tahmin edilebilir.",
    "Short keyboard patterns are easy to guess.": "Kısa klavye desenleri kolayca tahmin edilebilir.",
    "Use a longer keyboard pattern with more turns.": "Daha uzun ve dönüşlü bir klavye deseni kullanın.",
    "Repeats like \"aaa\" are easy to guess.": '"aaa" gibi tekrarlar kolayca tahmin edilebilir.',
    "Repeats like \"abcabcabc\" are only slightly harder to guess than \"abc\".": '"abcabcabc" gibi tekrarlar "abc"den sadece biraz daha zordur.',
    "Sequences like \"abc\" or \"6543\" are easy to guess.": '"abc" veya "6543" gibi diziler kolayca tahmin edilebilir.',
    "Recent years are easy to guess.": "Yakın yıllar kolayca tahmin edilebilir.",
    "Dates are often easy to guess.": "Tarihler genellikle kolayca tahmin edilebilir.",
    "This is a top-10 common password.": "Bu, en çok kullanılan ilk 10 şifreden biri.",
    "This is a top-100 common password.": "Bu, en çok kullanılan ilk 100 şifreden biri.",
    "This is a very common password.": "Bu çok yaygın kullanılan bir şifre.",
    "This is similar to a commonly used password.": "Bu, yaygın kullanılan bir şifreye benziyor.",
    "A word by itself is easy to guess.": "Tek başına bir kelime kolayca tahmin edilebilir.",
    "Names and surnames by themselves are easy to guess.": "İsim ve soy isimler kolayca tahmin edilebilir.",
    "Common names and surnames are easy to guess.": "Yaygın isim ve soy isimler kolayca tahmin edilebilir.",
    "This is a commonly used password.": "Bu yaygın olarak kullanılan bir şifre.",

    # ── Öneriler (suggestions) ──
    "Use a few words, avoid common phrases.": "Birkaç kelime kullanın, yaygın ifadelerden kaçının.",
    "No need for symbols, digits, or uppercase letters.": "Sembol, rakam veya büyük harf zorunlu değil.",
    "Add another word or two. Uncommon words are better.": "Bir veya iki kelime daha ekleyin. Nadir kelimeler daha iyidir.",
    "Capitalization doesn't help very much.": "Büyük harf kullanımı çok fazla yardımcı olmuyor.",
    "All-uppercase is almost as easy to guess as all-lowercase.": "Tamamı büyük harf, tamamı küçük harf kadar kolay tahmin edilebilir.",
    "Reversed words aren't much harder to guess.": "Ters çevrilmiş kelimeler tahmin etmeyi pek zorlaştırmaz.",
    "Predictable substitutions like '@' instead of 'a' don't help very much.": "'a' yerine '@' gibi tahmin edilebilir değişiklikler pek yardımcı olmaz.",
    "Add a word or two. Uncommon words are better.": "Bir veya iki kelime ekleyin. Nadir kelimeler daha iyidir.",
    "Avoid repeated words and characters.": "Tekrarlanan kelime ve karakterlerden kaçının.",
    "Avoid sequences.": "Sıralı dizilerden kaçının.",
    "Avoid recent years.": "Yakın yıllardan kaçının.",
    "Avoid years that are associated with you.": "Sizinle ilişkili yıllardan kaçının.",
    "Avoid dates and years that are associated with you.": "Sizinle ilişkili tarih ve yıllardan kaçının.",
}


def translate_zxcvbn(text: str) -> str:
    """zxcvbn İngilizce geri bildirimini Türkçeye çevirir."""
    return ZXCVBN_TR.get(text, text)


# ─────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ CyberShield")
    st.markdown("---")

    st.markdown("### 💡 Güçlü Şifre İpuçları")
    st.markdown(
        """
        1. **Passphrase kullanın** – Rastgele 4-5 kelimelik
           ifadeler (ör: `doğru at pil zımba`) hem güçlü
           hem de hatırlaması kolaydır.

        2. **En az 12+ karakter** – Uzun şifreler
           brute-force saldırılarını zorlaştırır.

        3. **Karışık karakter türleri** – Büyük/küçük harf,
           rakam ve özel karakterler (`!@#$%`) kullanın.

        4. **Kişisel bilgilerden kaçının** – Doğum tarihi,
           isim veya sık kullanılan kelimeler tahmin
           edilebilir.

        5. **Her hesap için farklı şifre** – Bir hesap
           sızarsa diğerleri güvende kalır.

        6. **Parola yöneticisi kullanın** – Bitwarden,
           KeePass gibi araçlarla şifreleri güvenle saklayın.
        """
    )

    st.markdown("---")
    st.markdown("### 🔐 K-Anonymity Nedir?")
    st.markdown(
        """
        Şifreniz **asla** düz metin veya tam hash olarak
        sunucuya gönderilmez.

        1. Şifrenin SHA-1 hash'i hesaplanır
        2. Hash'in yalnızca **ilk 5 karakteri** API'ye gönderilir
        3. API, bu ön-ek ile eşleşen **yüzlerce** hash döndürür
        4. Tam eşleşme **sizin cihazınızda** kontrol edilir

        Böylece şifreniz sunucuya hiç ulaşmaz! 🎯
        """
    )

    st.markdown("---")
    st.markdown(
        """
        <div style="text-align:center; color:#5a6785; font-size:0.8rem;">
            CyberShield v1.0 · Şifreler sunucuya gönderilmez<br>
            Powered by <b>Have I Been Pwned</b> & <b>zxcvbn</b>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ─────────────────────────────────────────────
# Ana İçerik
# ─────────────────────────────────────────────
st.markdown('<h1 class="main-title">🛡️ CyberShield</h1>', unsafe_allow_html=True)
st.markdown(
    '<p class="sub-title">Password Integrity & Leak Analyzer</p>',
    unsafe_allow_html=True,
)

# Şifre Girişi
password = st.text_input(
    "🔑 Analiz etmek istediğiniz şifreyi girin",
    type="password",
    placeholder="Şifrenizi buraya yazın…",
    help="Şifreniz asla düz metin olarak kaydedilmez veya loglanmaz.",
)

if password:
    # ─── Analiz Başlat ───
    analysis = analyze_password(password)
    score = analysis["score"]
    label, css_class = get_score_label(score)
    char_classes = get_char_classes(password)

    st.markdown("---")

    # ══════════════════════════════════════════
    # BÖLÜM 1: Güvenlik Skoru
    # ══════════════════════════════════════════
    st.markdown(
        '<div class="cyber-card"><h3>📊 Güvenlik Skoru</h3>',
        unsafe_allow_html=True,
    )

    col_score, col_details = st.columns([1, 2])

    with col_score:
        st.markdown(
            f'<div style="text-align:center;margin-top:8px;">'
            f'<span style="font-size:4rem;font-weight:800;color:#ccd6f6;">{score}</span>'
            f'<span style="font-size:1.5rem;color:#5a6785;"> / 4</span><br>'
            f'<span class="score-badge {css_class}">{label}</span>'
            f"</div>",
            unsafe_allow_html=True,
        )

    with col_details:
        # İlerleme çubuğu
        progress_value = (score + 1) / 5
        st.progress(progress_value)

        # Metrikler
        m1, m2, m3 = st.columns(3)
        m1.metric("📏 Uzunluk", f"{len(password)} karakter")
        m2.metric("🧮 Entropi", f"{analysis['guesses_log10']:.1f} bit")
        m3.metric(
            "⏳ Kırılma Süresi",
            analysis["crack_times_display"]["offline_slow_hashing_1e4_per_second"],
        )

        # Karakter sınıfları
        if char_classes:
            st.markdown("**Kullanılan karakter türleri:** " + " · ".join(char_classes))

    # zxcvbn geri bildirimleri (Türkçe çeviri ile)
    feedback = analysis.get("feedback", {})
    warning = feedback.get("warning", "")
    suggestions = feedback.get("suggestions", [])

    if warning or suggestions:
        st.markdown("---")
        st.markdown("**💬 Öneriler:**")
        if warning:
            st.warning(f"⚠️ {translate_zxcvbn(warning)}")
        for s in suggestions:
            st.info(f"💡 {translate_zxcvbn(s)}")

    st.markdown("</div>", unsafe_allow_html=True)

    # ══════════════════════════════════════════
    # BÖLÜM 2: Sızıntı Kontrolü (HIBP)
    # ══════════════════════════════════════════
    st.markdown(
        '<div class="cyber-card"><h3>🔍 Veri Sızıntısı Kontrolü</h3>',
        unsafe_allow_html=True,
    )

    with st.spinner("Have I Been Pwned veritabanı kontrol ediliyor..."):
        hibp_result = check_hibp(password)

    if hibp_result["error"]:
        st.error(hibp_result["error"])
    elif hibp_result["found"]:
        count = hibp_result["count"]
        st.markdown(
            f'<div class="leak-danger">'
            f"🚨 <b>Bu şifre sızdırılmış veritabanlarında bulundu!</b><br>"
            f"Toplam <b>{count:,}</b> kez veri ihlallerinde görüldü."
            f"</div>",
            unsafe_allow_html=True,
        )
        st.markdown(
            "> ⚠️ Bu şifreyi kullanıyorsanız **derhal değiştirmeniz** şiddetle önerilir."
        )
    else:
        st.markdown(
            '<div class="leak-safe">'
            "✅ <b>Bu şifre bilinen veri sızıntılarında bulunamadı.</b><br>"
            "Ancak bu, şifrenin %100 güvenli olduğu anlamına gelmez."
            "</div>",
            unsafe_allow_html=True,
        )

    st.markdown("</div>", unsafe_allow_html=True)

    # ══════════════════════════════════════════
    # BÖLÜM 3: Brute-Force Simülasyonu
    # ══════════════════════════════════════════
    st.markdown(
        '<div class="cyber-card"><h3>⚡ Brute-Force Kırılma Simülasyonu</h3>',
        unsafe_allow_html=True,
    )

    keyspace = calculate_keyspace(password)

    # Senaryolar
    PC_RATE = 10_000               # 10 bin deneme/sn
    GPU_RATE = 100_000_000_000     # 100 milyar deneme/sn

    pc_time = brute_force_time(keyspace, PC_RATE)
    gpu_time = brute_force_time(keyspace, GPU_RATE)

    col_pc, col_gpu = st.columns(2)

    with col_pc:
        st.markdown(
            """
            <div style="text-align:center;">
                <span style="font-size:2.5rem;">🖥️</span><br>
                <b style="color:#ccd6f6;">Standart PC</b><br>
                <span style="color:#5a6785;">10.000 deneme/sn</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.metric("Tahmini Süre", format_time(pc_time))

        # Güvenlik barı (PC)
        if pc_time < 3600:
            pc_bar = 0.05
        elif pc_time < 86400 * 30:
            pc_bar = 0.25
        elif pc_time < 86400 * 365:
            pc_bar = 0.5
        elif pc_time < 86400 * 365 * 1000:
            pc_bar = 0.75
        else:
            pc_bar = 1.0
        st.progress(pc_bar)

    with col_gpu:
        st.markdown(
            """
            <div style="text-align:center;">
                <span style="font-size:2.5rem;">🎮</span><br>
                <b style="color:#ccd6f6;">GPU Kümesi</b><br>
                <span style="color:#5a6785;">100 milyar deneme/sn</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.metric("Tahmini Süre", format_time(gpu_time))

        # Güvenlik barı (GPU)
        if gpu_time < 3600:
            gpu_bar = 0.05
        elif gpu_time < 86400 * 30:
            gpu_bar = 0.25
        elif gpu_time < 86400 * 365:
            gpu_bar = 0.5
        elif gpu_time < 86400 * 365 * 1000:
            gpu_bar = 0.75
        else:
            gpu_bar = 1.0
        st.progress(gpu_bar)

    # Anahtar uzayı detayları
    st.markdown("---")
    ks1, ks2 = st.columns(2)
    ks1.metric("🔑 Anahtar Uzayı (Keyspace)", f"{keyspace:.2e}")
    entropy_bits = math.log2(keyspace) if keyspace > 0 else 0
    ks2.metric("📐 Entropi", f"{entropy_bits:.1f} bit")

    st.markdown("</div>", unsafe_allow_html=True)

    # ══════════════════════════════════════════
    # Alt Bilgi
    # ══════════════════════════════════════════
    st.markdown("---")
    st.markdown(
        """
        <div style="text-align:center; color:#5a6785; font-size:0.85rem; padding:16px 0;">
            🔒 Şifreniz cihazınızdan hiçbir zaman düz metin olarak çıkmaz.
            HIBP sorguları <b>K-Anonymity</b> yöntemiyle gerçekleştirilir.<br>
            Bu uygulama yalnızca eğitim ve farkındalık amaçlıdır.
        </div>
        """,
        unsafe_allow_html=True,
    )

else:
    # Şifre girilmediğinde gösterilecek alan
    st.markdown("---")
    st.markdown(
        """
        <div style="text-align:center; padding:60px 20px;">
            <span style="font-size:5rem;">🔐</span><br><br>
            <h3 style="color:#ccd6f6;">Şifrenizi analiz etmeye başlayın</h3>
            <p style="color:#5a6785; max-width:500px; margin:auto;">
                Yukarıdaki alana bir şifre girerek güvenlik skorunu,
                veri sızıntısı durumunu ve brute-force kırılma süresini öğrenin.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
