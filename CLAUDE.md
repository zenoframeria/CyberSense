# CyberSense — Project Summary & Code Review

## ภาพรวมโปรเจกต์

CyberSense เป็นระบบ AI ตรวจจับ SMS และ URL หลอกลวงภาษาไทย พัฒนาในลักษณะ Hackathon ใช้โมเดล WangchanBERTa fine-tuned บน Thai SMS dataset 700 ตัวอย่าง พร้อม rule-based XAI signals และ URL risk scoring system

| รายการ | รายละเอียด |
|--------|------------|
| **Stack** | FastAPI (Python) + WangchanBERTa (HuggingFace) + HTML/CSS/JS |
| **AI Model** | airesearch/wangchanberta-base-att-spm-uncased (fine-tuned) |
| **Dataset** | Thai SMS 700 ตัวอย่าง (`02_ai/Thai_sms_dataset_final_700_*.csv`) |
| **Endpoints** | `POST /analyze/sms`, `POST /scan/url`, `GET /health` |

---

## โครงสร้างไฟล์

```
Cybersense/
├── main.py                          # FastAPI server (75 lines, 3 endpoints)
├── url_scanner.py                   # URL risk scoring — 6 checks (363 lines)
├── 02_ai/
│   ├── sms_analyzer.py              # BERT inference + XAI pipeline (302 lines)
│   └── xai.py                       # Rule-based signal detection & highlighting (274 lines)
├── 01_frontend/
│   └── demo_v1.html                 # Mobile UI (2841 lines)
└── CLAUDE.md                        # This file
```

---

## แผนงานปรับปรุง (Code Review Findings)

### 🔴 Critical — ความปลอดภัย

**1. CORS Wildcard (`main.py:27`)** --> (Done/Fixed)
- ปัญหา: `allow_origins=["*"]` เปิดให้ทุก domain เรียก API ได้
- แนวทางแก้: whitelist เฉพาะ domain จริง เช่น `allow_origins=["https://yourdomain.com"]`

---

### 🟠 High — ความเสถียร & Error Handling

**2. ไม่มี try-except ใน API endpoints (`main.py:47-60`)** --> (Done/Fixed)
- ปัญหา: ถ้า model โหลดไม่ได้ หรือ WHOIS timeout → API crash พร้อม HTTP 500
- แนวทางแก้: ครอบ `analyze_sms()` และ `scan_url()` ด้วย try-except → return error dict แทน

**3. Bare except แบบ silent (`url_scanner.py:234`)** --> (Done/Fixed)
- ปัญหา: `except Exception: pass` กลืน error ทุกอย่างเงียบ ๆ debug ไม่ได้
- แนวทางแก้: `except Exception as e: logging.warning(...) ` + return fallback value

**4. Thread-unsafe model loading (`02_ai/sms_analyzer.py:212-223`)** --> (Done/Fixed)
- ปัญหา: Global `_tokenizer`, `_model` + lazy load ไม่มี lock → race condition บน concurrent requests
- แนวทางแก้: เพิ่ม `threading.Lock()` รอบ `_load_model()` หรือเปลี่ยนเป็น singleton class

**5. ไม่ validate input (`main.py`, `xai.py:160`)** --> (Done/Fixed)
- ปัญหา: `text=""` หรือ `sender=None` → crash ใน tokenizer และ `re.match()`
- แนวทางแก้: Pydantic `Field(min_length=1)` + `if not sender:` guard ใน `xai.py`

---

### 🟡 Medium — Clean Code & Performance

**6. Duplicate regex search (`02_ai/xai.py:93, 105, 117, 149`)** --> (Done/Fixed)
- ปัญหา: `re.search()` ถูกเรียก 2 ครั้งต่อ keyword — ครั้งแรก check, ครั้งสองเพื่อ `.group()`
- แนวทางแก้: `m = re.search(...); if m: use m.group()` — เรียกครั้งเดียว

**7. Magic numbers กระจัดกระจาย (`url_scanner.py`, `sms_analyzer.py`)** --> (Done/Fixed)
- ปัญหา: ค่าคะแนน 15, 25, 35, 70 และ threshold 75, 50 ฝังอยู่กลางโค้ด ไม่มี label
- แนวทางแก้: ประกาศ constants ที่ด้านบนไฟล์ เช่น `RISK_THRESHOLD_DANGER = 70`

**8. Repeated detection loops (`02_ai/xai.py:92-157`)** --> (Done/Fixed)
- ปัญหา: 5 loops โครงสร้างเหมือนกันทุกอัน (for keyword → re.search → append signal)
- แนวทางแก้: extract เป็น helper function `_check_signal(signal_type, keywords, text)`

**9. `scan_url()` ยาวเกินไป (`url_scanner.py:81-164`, 83 บรรทัด)** --> (Done/Fixed)
- ปัญหา: ฟังก์ชันเดียวทำหลาย responsibilities: normalize URL, รัน 6 checks, คำนวณ score, ตัดสิน verdict
- แนวทางแก้: แตกเป็น `_normalize_url()`, `_calculate_score()`, `_get_verdict()` แยกกัน

**10. Regex ไม่ pre-compile (`02_ai/xai.py:219-231`)** --> (Done/Fixed)
- ปัญหา: `re.finditer(keyword, ...)` ใน triple nested loop → compile ซ้ำทุก call
- แนวทางแก้: `re.compile()` ล่วงหน้าตอน module load และเก็บใน dict

**11. Unused import (`url_scanner.py:4`)** --> (Done/Fixed)
- ปัญหา: `import requests` ไม่ถูกใช้งาน (อาจเป็น PhishTank API ที่ยังไม่ implement)
- แนวทางแก้: ลบออก หรือเพิ่ม comment ว่า planned

---

### 🟢 Low — Clarity & Maintainability

**12. Dead/test code ใน production modules**
- `sms_analyzer.py:189, 196-197` — training code commented out
- `xai.py:174-196, 266-275` — hardcoded test SMS examples
- `url_scanner.py:360-364` — hardcoded test URL at bottom
- แนวทางแก้: ย้าย training code ไป `train.py`, test examples ไป `tests/`

**13. `print()` แทน logging (20+ จุดทั่วโปรเจกต์)**
- แนวทางแก้: ใช้ Python `logging` module พร้อมกำหนด level ให้เหมาะสม

**14. Hardcoded relative paths (`sms_analyzer.py:33, 211`)**
- ปัญหา: `"02_ai/cybersense_model"` crash ถ้ารันจาก directory อื่น
- แนวทางแก้: `os.path.join(os.path.dirname(__file__), "cybersense_model")`

**15. Risk score scale ไม่สม่ำเสมอ**
- ปัญหา: URL scanner คืนค่า 0-99 (`min(risk_score, 99)`), SMS analyzer คืนค่า 0-100
- แนวทางแก้: normalize ทั้งคู่เป็น 0-100

---

## สรุปตามไฟล์

| ไฟล์ | บรรทัด | คุณภาพ | จุดที่ต้องแก้ |
|------|--------|--------|--------------|
| `main.py` | 75 | ดี | CORS, error handling, input validation |
| `url_scanner.py` | 363 | พอใช้ | Magic numbers, bare except, function ยาว, unused import |
| `02_ai/sms_analyzer.py` | 302 | ดี | Thread safety, relative paths, dead code, print statements |
| `02_ai/xai.py` | 274 | พอใช้ | Duplicate regex, repeated loops, regex pre-compile |
| `01_frontend/demo_v1.html` | 2841 | — | ไม่ได้ review (UI code) |

---

## จุดแข็งของโปรเจกต์

- โครงสร้าง modules แยกชัดเจน (SMS, URL, XAI)
- มี Explainability — บอกเหตุผลการตัดสินใจ (urgency, brand impersonation ฯลฯ)
- FastAPI endpoints มี Pydantic model อยู่แล้ว
- Thai-specific tuning — keyword lists และ brand names ครอบคลุม
- Lazy loading โมเดล — ไม่โหลดซ้ำทุก request

---

## Verification Steps (เมื่อพร้อมแก้โค้ด)

1. `uvicorn main:app --reload` → ต้องไม่มี error
2. `POST /analyze/sms` ด้วย SMS ตัวอย่าง → ได้ผลถูกต้อง
3. `POST /scan/url` ด้วย URL ตัวอย่าง → ได้ผลถูกต้อง
4. `POST /analyze/sms` ด้วย body ว่าง → ได้ error message ไม่ crash
