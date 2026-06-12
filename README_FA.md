# 🛡️ TorShield-IR — پلتفرم هوشمند بریج‌های Tor برای ایران

> جمع‌آوری خودکار، آزمایش چندلایه، و رتبه‌بندی بریج‌های Tor با تمرکز ویژه بر دور زدن سانسور هوشمند ایران (SIAM/DPI).

---

## 📋 فهرست مطالب

- [معرفی](#معرفی)
- [ویژگی‌های پیشرفته](#ویژگی‌های-پیشرفته)
- [راهنمای نصب](#راهنمای-نصب)
- [نحوه استفاده](#نحوه-استفاده)
- [راهنمای ایران](#راهنمای-ایران)
- [معماری سیستم](#معماری-سیستم)
- [توضیح فایل‌های خروجی](#توضیح-فایل‌های-خروجی)
- [رازها و تنظیمات](#رازها-و-تنظیمات)

---

## معرفی

TorShield-IR یک پلتفرم تمام‌خودکار جمع‌آوری و آزمایش بریج‌های Tor است که به طور خاص برای شرایط فیلترینگ ایران طراحی شده است.

این سیستم چند کار اصلی انجام می‌دهد:

- **جمع‌آوری** بریج از منابع متعدد (bridges.torproject.org، MOAT API بدون CAPTCHA، بریج‌های ثابت داخلی)
- **آزمایش ۸ لایه‌ای** شامل: TCP دسترسی‌پذیری، فیلتر ASN ایران، ریسک fingerprint TLS، ریسک پورت، داده‌های OONI از پروب‌های ایرانی، تحلیل زمانی ۹۰ روزه، اعتبارسنجی CDN front، و تأیید اختیاری RIPE Atlas
- **رتبه‌بندی** هر بریج بر اساس امتیاز ترکیبی (۰ تا ۱) برای اثربخشی در ایران
- **انتشار خودکار** نتایج هر ساعت از طریق GitHub Actions

---

## ویژگی‌های پیشرفته

### زبان‌های برنامه‌نویسی

این پروژه از سه زبان به صورت یکپارچه استفاده می‌کند:

**Python 3.11+** برای جمع‌آوری، همبسته‌سازی OONI، و نوشتن نتایج — asyncio، aiohttp، Rich، و BeautifulSoup.

**Go 1.22+** برای آزمایش موازی با همزمانی بالا — ۱۰۰ worker goroutine، مدیریت context، و HTTP server داخلی برای تبادل داده با Python.

**Rust 1.78+** برای پروب دست دادن (handshake) پروتکل‌های Pluggable Transport — tokio async runtime، serde برای JSON، و امنیت حافظه بدون GC.

### منابع جمع‌آوری

**MOAT API** مهم‌ترین افزودنی است. این API بدون CAPTCHA کار می‌کند و بریج‌های بهینه‌شده برای کد کشور `ir` را برمی‌گرداند — دقیقاً همان مکانیزمی که Tor Browser داخلی استفاده می‌کند.

**bridges.torproject.org** با retry هوشمند (backoff نمایی)، چرخش User-Agent، و تأخیر تصادفی بین درخواست‌ها برای جلوگیری از CAPTCHA.

**بریج‌های ثابت** شامل دو Snowflake رسمی Tor Browser 13+ و دو meek-lite (Azure و Amazon CDN).

### سیستم امتیازدهی ایران

فرمول امتیاز ترکیبی:
```
composite = 0.35 × tcp_reachable + 0.40 × ooni_factor + 0.25 × ripe_factor
```

امتیاز بالای ۰.۵ به معنی احتمال بالای کارکرد در ایران است.

### ضد فیلترینگ هوشمند (Anti-Smart-DPI)

سیستم SIAM ایران از روش‌های زیر استفاده می‌کند:
- **JA3 fingerprinting**: شناسایی TLS ClientHello مشخصه Tor (هش `e7d705a3286e19ea42f587b344ee6865`)
- **IP blocking**: مسدود کردن IPهای شناخته‌شده relay/bridge Tor
- **Port blocking**: پورت‌های ۹۰۰۱، ۹۰۳۰، ۹۰۵۰ به طور سیستماتیک مسدود می‌شوند
- **Statistical traffic analysis**: تشخیص الگوهای ترافیک غیرعادی با ML

TorShield-IR در برابر این روش‌ها موارد زیر را انجام می‌دهد:
- بریج‌های دارای پورت ۴۴۳ را اولویت می‌دهد (HTTPS ایران نمی‌تواند آن را مسدود کند)
- بریج‌های Snowflake (WebRTC) را به عنوان بهترین گزینه رتبه‌بندی می‌کند
- بریج‌های WebTunnel با CDN front (Cloudflare، Fastly) را شناسایی می‌کند
- بریج‌هایی با ASN ایرانی را به عنوان `iran_asn_blocked` علامت می‌زند (نشانه honeypot)
- بریج‌هایی که بیش از ۲ بار در ۳۰ روز مسدود شده‌اند را به عنوان `iran_frequently_blocked` علامت می‌زند

---

## راهنمای نصب

### پیش‌نیازها

- Python 3.10 یا بالاتر (3.11 توصیه می‌شود)
- Go 1.22+ (اختیاری، برای iran_tester و probe_scheduler)
- Rust 1.78+ / Cargo (اختیاری، برای bridge-probe)
- Git

### نصب خودکار

```bash
# کلون کردن مخزن
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
cd YOUR_REPO

# اجرای نصب‌کننده (Python + Go + Rust اگر موجود باشند)
bash install.sh

# یا فقط Python:
bash install.sh --no-go --no-rust
```

### نصب دستی (بدون Go و Rust)

```bash
python3 -m venv .venv
source .venv/bin/activate          # Linux/Mac
# یا: .venv\Scripts\activate       # Windows

pip install -r requirements.txt
mkdir -p bridge export data docs
```

---

## نحوه استفاده

### اجرای کامل pipeline

```bash
# همه مراحل به ترتیب:
python main.py --mode all

# یا هر مرحله جداگانه:
python main.py --mode collect    # جمع‌آوری بریج‌ها
python main.py --mode test       # آزمایش اتصال
python main.py --mode score      # محاسبه امتیاز ایران
python main.py --mode export     # نوشتن فایل‌های خروجی
```

### اجرای TorShield-IR کامل (نیاز به Go و Rust)

```bash
# ۱. جمع‌آوری
python scraper.py

# ۲. آزمایش ۸ لایه‌ای (Go)
./iran_tester \
  --input bridge/bridge_list_for_testing.json \
  --output bridge/iran_results.json \
  --workers 100 --timeout 8s

# ۳. پروب PT handshake (Rust)
cat bridge/bridge_list_for_testing.json \
  | ./bridge-probe/target/release/bridge-probe \
  > data/pt_results.json

# ۴. همبسته‌سازی OONI
python ooni_correlator.py

# ۵. نوشتن نتایج نهایی
python results_writer.py
```

### بررسی وضعیت شبکه ایران (اجرا از داخل ایران)

```bash
python main.py --detect-iran
```

این دستور تشخیص می‌دهد که آیا اینترنت بین‌الملل قطع است (شبکه ملی فعال) و بهترین استراتژی را توصیه می‌کند.

---

## راهنمای ایران

### هنگام قطع اینترنت (شبکه ملی فعال)

وقتی اینترنت بین‌الملل قطع می‌شود، اکثر بریج‌های معمولی کار نمی‌کنند زیرا IP آن‌ها بین‌المللی است. در این حالت:

**۱. از Snowflake استفاده کنید** — بریج‌های Snowflake از WebRTC و CDN Fastly استفاده می‌کنند. حتی در برخی قطعی‌ها، این کانال‌ها قابل دسترس هستند.

```
bridge/iran_likely_working_snowflake.txt
export/iran_cut_pack.txt
```

**۲. WebTunnel با CDN front** — این بریج‌ها ترافیک HTTPS عادی به CDN تقلید می‌کنند. اگر CDN مربوطه (Cloudflare، Fastly، Azure) edge node در ایران داشته باشد، کار می‌کنند.

**۳. meek-lite (آخرین راه‌حل)** — کند اما CDN-fronted. Azure CDN به طور تاریخی در ایران کمتر مسدود می‌شود.

### در شرایط فیلترینگ معمول

```
# بهترین گزینه‌ها:
bridge/iran_likely_working_all.txt    ← تأیید شده توسط OONI از ایران
bridge/iran_likely_working_obfs4.txt  ← obfs4 با امتیاز بالا
export/iran_pack.txt                  ← ۱۰۰ بریج برتر با امتیاز ایران
```

### راهنمای ترانسپورت برای ایران

| ترانسپورت | مقاومت DPI | شبکه ملی | سرعت | توصیه |
|-----------|-----------|----------|------|-------|
| Snowflake | ⭐⭐⭐⭐⭐ | ✅ | متوسط | **بله** |
| WebTunnel | ⭐⭐⭐⭐⭐ | ✅ (CDN) | سریع | **بله** |
| obfs4 | ⭐⭐⭐⭐ | ❌ | سریع | **بله** |
| meek-lite | ⭐⭐⭐⭐ | ✅ (Azure) | کند | پشتیبان |
| Vanilla | ⭐ | ❌ | سریع | خیر |

### نصب در Tor Browser

۱. Tor Browser را باز کنید
۲. به **Settings → Connection** بروید
۳. روی **"Add a Bridge Manually"** کلیک کنید
۴. خطوط بریج را از فایل‌های خروجی این پروژه کپی کنید

### نصب در Orbot (Android)

۱. Orbot را باز کنید
۲. به تنظیمات بروید
۳. **"Use Bridges"** را فعال کنید
۴. نوع ترانسپورت را obfs4 یا Snowflake انتخاب کنید
۵. بریج‌های دلخواه را از فایل‌های این پروژه وارد کنید

---

## معماری سیستم

```
┌─────────────────────────────────────────────────────────┐
│              GitHub Actions (هر ساعت)                    │
│                                                         │
│  Python scraper.py   ──────────────────────────────────▶ bridge_list_for_testing.json
│       │                                                 │
│       ▼                                                 │
│  Go iran_tester      ── ۸ لایه آنالیز ──────────────▶ iran_results.json
│  (TCP·ASN·TLS·Port·                                     │
│   OONI·Temporal·CDN·RIPE)                               │
│       │                                                 │
│       ▼                                                 │
│  Rust bridge-probe   ── PT handshake ───────────────▶ pt_results.json
│  (obfs4·snowflake·                                      │
│   webtunnel)                                            │
│       │                                                 │
│       ▼                                                 │
│  Python ooni_correlator.py ────────────────────────▶ latest-results.json
│  (Composite score · Markdown report)                    │
│       │                                                 │
│       ▼                                                 │
│  Python results_writer.py ─────────────────────────▶ iran_likely_working_*.txt
│  (Categorised files · README · Telegram)                │
└─────────────────────────────────────────────────────────┘
```

---

## توضیح فایل‌های خروجی

| فایل | توضیح |
|------|-------|
| `bridge/iran_likely_working_all.txt` | همه بریج‌های تأیید شده OONI برای ایران |
| `bridge/iran_likely_working_obfs4.txt` | بریج‌های obfs4 کار کننده در ایران |
| `bridge/iran_likely_working_webtunnel.txt` | بریج‌های WebTunnel کار کننده |
| `bridge/iran_likely_working_snowflake.txt` | بریج‌های Snowflake |
| `bridge/iran_blocked.txt` | بریج‌های مسدود شده (برای اطلاعات) |
| `bridge/tested_global_obfs4.txt` | آزمایش‌شده TCP (ممکن است در ایران بلاک باشد) |
| `export/iran_pack.txt` | ۱۰۰ بریج برتر بر اساس امتیاز ایران |
| `export/iran_cut_pack.txt` | بریج‌های مقاوم در برابر قطع اینترنت |
| `data/latest-results.json` | نتایج کامل با امتیازات ترکیبی (JSON) |
| `docs/iran-bridge-status.md` | گزارش Markdown با جداول آماری |

---

## رازها و تنظیمات

فایل `.env` ایجاد کنید یا GitHub Secrets را تنظیم کنید:

| نام | ضروری | توضیح |
|-----|-------|-------|
| `TELEGRAM_BOT_TOKEN` | اختیاری | ارسال بریج‌ها به Telegram |
| `TELEGRAM_CHAT_ID` | اختیاری | شناسه کانال یا گروه Telegram |
| `TELEGRAM_UPLOAD` | اختیاری | `true` برای آپلود خودکار |
| `RIPE_ATLAS_API_KEY` | اختیاری | اندازه‌گیری از پروب‌های ایرانی |
| `RIPE_ATLAS_API_KEY` | اختیاری | بدون این کلید سیستم در حالت OONI-only کار می‌کند |
| `REPO_URL` | توصیه می‌شود | URL مخزن شما برای لینک‌های README |

---

## سلب مسئولیت

این پروژه برای اهداف آموزشی و آرشیوی ایجاد شده است. استفاده از بریج‌های Tor باید با رعایت قوانین محلی باشد.
