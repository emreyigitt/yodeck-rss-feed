#!/usr/bin/env python3
"""
Günlük RSS Feed Üretici
- Google Ads & Marketing
- Yapay Zeka (AI)
- SEO
- Google Haberleri
Günde 15 haber, filtrelenmiş ve profesyonel.
"""

import feedparser
import datetime
import hashlib
import re
import html
from xml.etree.ElementTree import Element, SubElement, tostring, indent

# ─── RSS Kaynakları ───
FEEDS = {
    "Yapay Zeka": [
        "https://news.google.com/rss/search?q=yapay+zeka+OR+artificial+intelligence&hl=tr&gl=TR&ceid=TR:tr",
        "https://news.google.com/rss/search?q=AI+technology+news&hl=en&gl=US&ceid=US:en",
    ],
    "Google Ads & Marketing": [
        "https://news.google.com/rss/search?q=google+ads+marketing&hl=tr&gl=TR&ceid=TR:tr",
        "https://news.google.com/rss/search?q=digital+marketing+google+ads&hl=en&gl=US&ceid=US:en",
    ],
    "SEO": [
        "https://news.google.com/rss/search?q=SEO+arama+motoru+optimizasyonu&hl=tr&gl=TR&ceid=TR:tr",
        "https://news.google.com/rss/search?q=SEO+search+engine+optimization+news&hl=en&gl=US&ceid=US:en",
    ],
    "Google Haberleri": [
        "https://news.google.com/rss/search?q=Google+update+news&hl=tr&gl=TR&ceid=TR:tr",
        "https://news.google.com/rss/search?q=Google+company+news+update&hl=en&gl=US&ceid=US:en",
    ],
}

# ─── Kategori açıklamaları (zengin içerik için) ───
CATEGORY_CONTEXT = {
    "Yapay Zeka": "Bu gelişme, yapay zeka teknolojilerinin hızla ilerlemesiyle birlikte sektörde önemli bir değişim sinyali veriyor. AI alanındaki yenilikler, iş dünyasından sağlığa kadar pek çok sektörü doğrudan etkiliyor.",
    "Google Ads & Marketing": "Dijital reklamcılık dünyasında sürekli gelişen stratejiler ve araçlar, markaların hedef kitlelerine daha etkili ulaşmasını sağlıyor. Google Ads ekosistemindeki güncellemeler, pazarlamacılar için yeni fırsatlar sunuyor.",
    "SEO": "Arama motoru optimizasyonu sürekli değişen algoritma güncellemeleriyle şekilleniyor. Web sitelerinin organik görünürlüğü için en güncel SEO stratejilerini takip etmek kritik önem taşıyor.",
    "Google Haberleri": "Google'ın ürün ve hizmetlerindeki güncellemeler, milyarlarca kullanıcıyı ve işletmeyi doğrudan etkiliyor. Teknoloji dünyasının en büyük oyuncusundan gelen her yenilik, dijital ekosistemin geleceğini şekillendiriyor.",
}

# ─── Filtreleme: İstenmeyen kelimeler ───
BLOCKED_KEYWORDS = [
    "kumar", "bahis", "casino", "sex", "porno", "dedikodu",
    "magazin", "astroloji", "burç", "falcı", "şok eden",
    "inanılmaz", "aldatan", "skandal", "çıplak", "yasak",
    "gambling", "porn", "nsfw", "scandal", "shocking",
    "clickbait", "lottery", "horoscope",
]

# ─── Güvenilir kaynak önceliği ───
TRUSTED_SOURCES = [
    "techcrunch", "theverge", "arstechnica", "wired", "reuters",
    "bloomberg", "searchengineland", "searchenginejournal", "moz.com",
    "semrush", "ahrefs", "hubspot", "nytimes", "bbc", "cnn",
    "webrazzi", "shiftdelete", "donanimhaber", "chip.com.tr",
    "marketingturkiye", "digitalage", "google.com/blog",
    "blog.google", "developers.google", "support.google",
]


def is_blocked(title: str, summary: str = "") -> bool:
    text = (title + " " + summary).lower()
    return any(kw in text for kw in BLOCKED_KEYWORDS)


def trust_score(link: str) -> int:
    link_lower = link.lower()
    for i, src in enumerate(TRUSTED_SOURCES):
        if src in link_lower:
            return len(TRUSTED_SOURCES) - i
    return 0


def clean_html(raw: str) -> str:
    clean = re.sub(r"<[^>]+>", "", raw)
    return html.unescape(clean).strip()


def extract_source(link: str) -> str:
    """URL'den kaynak adını çıkar."""
    try:
        from urllib.parse import urlparse
        domain = urlparse(link).netloc
        domain = domain.replace("www.", "")
        parts = domain.split(".")
        if len(parts) >= 2:
            return parts[-2].capitalize()
        return domain.capitalize()
    except:
        return ""


def build_rich_description(title: str, summary: str, category: str, link: str) -> str:
    """Zengin ve bilgi verici açıklama oluştur."""
    source = extract_source(link)
    context = CATEGORY_CONTEXT.get(category, "")
    
    # Özet varsa kullan, yoksa kategori bağlamını ekle
    if summary and len(summary) > 50:
        desc = f"📌 {category} | Kaynak: {source}\n\n{summary}"
    else:
        desc = f"📌 {category} | Kaynak: {source}\n\n{title}. {context}"
    
    # Açıklamayı zenginleştir
    if len(desc) < 200:
        desc += f"\n\n💡 {context}"
    
    return desc[:600]


def fetch_all_entries() -> list:
    all_entries = []
    seen_titles = set()

    for category, urls in FEEDS.items():
        for url in urls:
            try:
                feed = feedparser.parse(url)
                for entry in feed.entries:
                    title = clean_html(entry.get("title", ""))
                    summary = clean_html(entry.get("summary", ""))
                    link = entry.get("link", "")

                    if len(title) < 10:
                        continue

                    if is_blocked(title, summary):
                        continue

                    title_hash = hashlib.md5(
                        title.lower()[:50].encode()
                    ).hexdigest()
                    if title_hash in seen_titles:
                        continue
                    seen_titles.add(title_hash)

                    pub_date = entry.get("published_parsed")
                    if pub_date:
                        pub_dt = datetime.datetime(*pub_date[:6])
                    else:
                        pub_dt = datetime.datetime.now()

                    # Zengin açıklama oluştur
                    rich_desc = build_rich_description(title, summary, category, link)

                    all_entries.append(
                        {
                            "title": title,
                            "summary": rich_desc,
                            "link": link,
                            "category": category,
                            "pub_dt": pub_dt,
                            "trust": trust_score(link),
                            "source": extract_source(link),
                        }
                    )
            except Exception as e:
                print(f"Hata ({category}): {e}")

    return all_entries


def select_top_entries(entries: list, total: int = 15) -> list:
    categories = list(FEEDS.keys())
    per_category = total // len(categories)
    remainder = total % len(categories)

    selected = []

    for i, cat in enumerate(categories):
        cat_entries = [e for e in entries if e["category"] == cat]
        cat_entries.sort(key=lambda x: (-x["trust"], -x["pub_dt"].timestamp()))
        count = per_category + (1 if i < remainder else 0)
        selected.extend(cat_entries[:count])

    selected.sort(key=lambda x: -x["pub_dt"].timestamp())
    return selected[:total]


def generate_rss_xml(entries: list) -> str:
    rss = Element("rss", version="2.0")
    rss.set("xmlns:atom", "http://www.w3.org/2005/Atom")

    channel = SubElement(rss, "channel")
    SubElement(channel, "title").text = "Dijital Dünya - Günlük Haberler"
    SubElement(channel, "description").text = (
        "Yapay Zeka, Google Ads, SEO ve Google haberleri - Günlük 15 seçme haber"
    )
    SubElement(channel, "language").text = "tr"
    SubElement(channel, "generator").text = "Custom RSS Aggregator"
    SubElement(channel, "ttl").text = "1440"

    CATEGORY_EMOJI = {
        "Yapay Zeka": "🤖",
        "Google Ads & Marketing": "📢",
        "SEO": "🔍",
        "Google Haberleri": "🔵",
    }

    for entry in entries:
        item = SubElement(channel, "item")
        emoji = CATEGORY_EMOJI.get(entry["category"], "📰")
        SubElement(item, "title").text = f'{emoji} {entry["title"]}'
        SubElement(item, "link").text = entry["link"]
        SubElement(item, "description").text = entry["summary"]
        SubElement(item, "category").text = entry["category"]
        # pubDate kasıtlı olarak eklenmedi - saat bilgisi gösterilmeyecek
        SubElement(item, "guid", isPermaLink="false").text = hashlib.md5(
            entry["link"].encode()
        ).hexdigest()

    indent(rss, space="  ")
    xml_str = '<?xml version="1.0" encoding="UTF-8"?>\n' + tostring(
        rss, encoding="unicode"
    )
    return xml_str


def main():
    print("📡 RSS haberleri çekiliyor...")
    entries = fetch_all_entries()
    print(f"  → Toplam {len(entries)} haber bulundu")

    print("🔍 Filtreleniyor ve seçiliyor...")
    top_entries = select_top_entries(entries, total=15)
    print(f"  → {len(top_entries)} haber seçildi")

    for e in top_entries:
        print(f'  [{e["category"]}] {e["title"][:60]}...')

    print("📝 RSS XML oluşturuluyor...")
    xml_content = generate_rss_xml(top_entries)

    with open("docs/feed.xml", "w", encoding="utf-8") as f:
        f.write(xml_content)

    print("✅ docs/feed.xml başarıyla oluşturuldu!")


if __name__ == "__main__":
    main()
