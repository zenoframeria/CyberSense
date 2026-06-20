import re

# ============================================
# XAI: Rule-based Signal Detection
# built from our real SMS dataset
# ============================================

URGENCY_KEYWORDS = [
    "ด่วน", "รีบ",
    "ภายใน 24 ชม", "ภายใน 24 ชั่วโมง",
    "หมดเขต", "วันนี้เท่านั้น",
    "มิฉะนั้น", "จะถูกระงับ",
    "จะถูกดำเนินคดี", "รีบดำเนินการ",
    "ก่อนหมดเวลา", "เหลือ 30 วัน",
    "เหลือ 45 วัน", "จะหมดอายุ",
    "หมดอายุ!", "เร่งด่วน"
]

FAKE_URL_KEYWORDS = [
    r"cutt\.ly[^\s]*",     
    r"bit\.ly[^\s]*",       
    r"rls\.my[^\s]*",       
    "short.link",
    "faepass.cc",
    r"[^\s]*\.cc[/\s$]", 
    r"https?://[^\s]*\.cc[/\s]",
    r"[^\s]*-verify[^\s]*",
    r"[^\s]*-secure[^\s]*",
    r"https?://[^\s]*\.xyz[^\s]*",
    r"https?://[^\s]*\.top[^\s]*",
    r"https?://[^\s]*\.click[^\s]*",
]

IMPERSONATION_KEYWORDS = [
    "ไปรษณีย์ไทย", "กสิกรไทย", "kbank",
    "scb", "กรุงไทย", "ออมสิน",
    "ทรูมูฟ", "ดีแทค",
    "การไฟฟ้า", "ประกันสังคม",
    "กรมสรรพากร", "ตำรวจ", "ศาล", "ดีเอสไอ",
    "ihappyloan", "tidlor",
    "เอไอเอส", "ais"
]

# map brand keywords to their real sender IDs
# if sender matches → not impersonation
BRAND_SENDER_MAP = {
    "ไปรษณีย์ไทย": ["thailandpost", "thaipost"],
    "กสิกรไทย":    ["kbank", "kasikorn"],
    "kbank":        ["kbank", "kasikorn"],
    "scb":          ["scb", "scbeasy"],
    "กรุงไทย":     ["krungthai", "ktb"],
    "ออมสิน":      ["gsb"],
    "ทรูมูฟ":      ["true", "truemove", "truebill", "trueonline"],
    "ดีแทค":       ["dtac"],
    "เอไอเอส":     ["ais", "ais points", "aisplay", "gomo"],
    "ais":          ["ais", "ais points", "aisplay", "gomo"],
    "การไฟฟ้า":    ["pea", "mea"],
    "ประกันสังคม": ["sso"],
    "กรมสรรพากร":  ["rd"],
}

BAIT_KEYWORDS = [
    "ได้รับรางวัล", "ยินดีด้วย",
    "รับเงินคืน", "กดรับสิทธิ์",
    "โชคดี", "ได้รับสิทธิ์",
    "เงินสำรอง", "อนุมัติไว",
    "กู้เงิน", "สินเชื่อด่วน",
    "ผ่อนสด 0%", "โค้ดน้ำมันฟรี",
    "แถมโค้ด", "ไม่ต้องตรวจสภาพรถ"
]

GAMBLING_KEYWORDS = [
    "เวปตง", "เว็บตง", "เวปใหญ่",
    "แตกง่าย","เเตกง่าย", "บวกยับ", "ถอนหนัก",
    "ถอนไว", "ปั่นยังไงก็แตก",
    "ยุสใหม่", "สมัครยุสใหม่",
    "API แท้", "ระบบเสถียร",
    "ฝากไว", "สายซิ่ง",
    "มาสาดตัง", "เวปตsง",
    "เวปตSง"  # obfuscated spelling we saw
]

UNKNOWN_SENDER_PATTERN = r"^[0-9]{9,10}$"

_COMPILED = {
    kw: re.compile(kw, re.IGNORECASE)
    for kw in (
        URGENCY_KEYWORDS + FAKE_URL_KEYWORDS + IMPERSONATION_KEYWORDS
        + BAIT_KEYWORDS + GAMBLING_KEYWORDS
    )
}
_COMPILED[UNKNOWN_SENDER_PATTERN] = re.compile(UNKNOWN_SENDER_PATTERN)


def _check_signal(signal_type, keywords, text, kind, label, detail_template, strip_match=False):
    for keyword in keywords:
        m = _COMPILED[keyword].search(text)
        if m:
            matched = m.group().strip() if strip_match else m.group()
            return {"type": signal_type, "kind": kind, "label": label, "detail": detail_template.format(matched)}
    return None


def detect_signals(text, sender=""):
    # scan SMS for danger signals using rules
    # returns list of signals found (empty = safe)

    sender = sender or ""
    signals = []

    for s in [
        _check_signal("GAMBLING", GAMBLING_KEYWORDS, text, "bad", "เว็บพนันออนไลน์",          '"{}" เป็นสัญญาณเว็บพนันผิดกฎหมาย'),
        _check_signal("URGENCY",  URGENCY_KEYWORDS,  text, "bad", "สร้างความกดดันเรื่องเวลา", '"{}" เป็นกลยุทธ์เร่งรีบไม่ทันคิด'),
        _check_signal("FAKE_URL", FAKE_URL_KEYWORDS, text, "bad", "URL น่าสงสัย",             '"{}" ลิงก์ซ่อนปลายทางจริง ควรระวัง', True),
        _check_signal("BAIT",     BAIT_KEYWORDS,     text, "bad", "เหยื่อล่อด้วยผลประโยชน์",  '"{}" มักเป็นกลยุทธ์หลอกลวง'),
    ]:
        if s:
            signals.append(s)

    # check IMPERSONATION — pretending to be real organizations
    # now checks sender to avoid false alarms on legit SMS
    for keyword in IMPERSONATION_KEYWORDS:
        if _COMPILED[keyword].search(text):
            # check if sender is the real brand
            real_senders = BRAND_SENDER_MAP.get(keyword.lower(), [])
            sender_is_real = any(
                s in sender.lower()
                for s in real_senders
            )
            # only flag if sender doesn't match real brand
            if not sender_is_real:
                signals.append({
                    "type": "IMPERSONATION",
                    "kind": "warn",
                    "label": "แอบอ้างหน่วยงาน",
                    "detail": f'อ้างตัวเป็น "{keyword}" กรุณาตรวจสอบผู้ส่งจริง'
                })
            break

    # check UNKNOWN_SENDER — phone number instead of org name
    if sender and _COMPILED[UNKNOWN_SENDER_PATTERN].match(sender.strip()):
        signals.append({
            "type": "UNKNOWN_SENDER",
            "kind": "warn",
            "label": "เบอร์ไม่รู้จัก",
            "detail": f'ส่งจากเบอร์ "{sender}" ไม่ใช่ Sender ID องค์กร'
        })

    return signals

# ============================================
# XAI: Highlight suspicious words in text
# ============================================

# map each signal type to which keywords to scan
HIGHLIGHT_RULES = [
    ("FAKE_URL",      FAKE_URL_KEYWORDS),
    ("GAMBLING",      GAMBLING_KEYWORDS),
    ("URGENCY",       URGENCY_KEYWORDS),
    ("BAIT",          BAIT_KEYWORDS),
    ("IMPERSONATION", IMPERSONATION_KEYWORDS),
]

def highlight_text(text, sender=""):
    # find all suspicious words and their positions in text
    # returns list of chunks: each chunk has text + type (None = safe)
    
    # step 1: find all matches and mark their positions
    # format: { start_pos: (end_pos, signal_type) }
    marked = {}
    
    for signal_type, keywords in HIGHLIGHT_RULES:
        for keyword in keywords:
            for match in _COMPILED[keyword].finditer(text):
                start = match.start()
                end = match.end()
                if start not in marked:
                    # skip IMPERSONATION highlight if sender is real brand
                    if signal_type == "IMPERSONATION":
                        real_senders = BRAND_SENDER_MAP.get(keyword.lower(), [])
                        sender_is_real = any(s in sender.lower() for s in real_senders)
                        if sender_is_real:
                            continue
                    # Skip if this span overlaps an already-marked span
                    # (first rule wins -> FAKE_URL beats IMPERSONATION on same text)
                    overlaps = any(
                        start < e and s < end
                        for s, (e, _) in marked.items()
                )
                    if not overlaps:
                        marked[start] = (end, signal_type)
    # step 2: sort marks by position (left to right)
    sorted_marks = sorted(marked.items())

    # step 3: split text into chunks (highlighted + normal)
    chunks = []
    current_pos = 0

    for start, (end, signal_type) in sorted_marks:
        # add normal text before this highlight
        if current_pos < start:
            chunks.append({
                "text": text[current_pos:start],
                "type": None  # normal text, no highlight
            })
        # add highlighted chunk
        chunks.append({
            "text": text[start:end],
            "type": signal_type  # highlight this with a color
        })
        current_pos = end

    # add remaining normal text after last highlight
    if current_pos < len(text):
        chunks.append({
            "text": text[current_pos:],
            "type": None
        })

    return chunks


if __name__ == "__main__":
    test_cases = [
        # scam from real dataset
        ("เนื่องจากคุณมีคุณสมบัติดีเยี่ยมihappyloanได้มอบเงินสำรองสูงสุด฿50000 กดเพื่อถอน https://h5.ihappyloan.com/cashindex", "ihappyloan"),
        ("🍒 เว็บใหญ่ ใจถึง พึ่งได้ ไม่แตกยินดีคืนเงิน https://rls.my/xa1", "0898765432"),
        ("ประกันรถ XXX 6448 เหลือ 30 วัน! หมดเขต 28/05/2569 กดต่อผ่านแอปเลย https://tidlor.info/3OlfbWv", "tidlor"),
        ("🔥🔥ด่วน! ย้ายมาเวป USA เเตกง่าย คลิก cutt.ly/9xbb", "0812345678"),
        ("พัสดุของท่านถูกตีกลับ ติดต่อพนักงานขนส่ง faepass.cc", "unknown"),
        # legit from real dataset
        ("รหัส OTP เพื่อใช้งาน K PLUS=847293 หมดอายุใน 6 นาที กรุณาอย่าเปิดเผย", "KBank"),
        ("ขอบคุณที่ชำระค่าบริการ AIS หมายเลข 0812345678 จำนวน 349 บาท", "AIS"),
    ]

    for sms, sender in test_cases:
        print(f"\nSMS: {sms[:50]}...")
        print(f"Sender: {sender}")
        results = detect_signals(sms, sender)
        if results:
            for r in results:
                print(f"  [{r['type']}] {r['label']} → {r['detail']}")
        else:
            print("  ✅ ไม่พบสัญญาณอันตราย")
        print("---")

    test_sms = "ท่านมีพัสดุค้างที่ไปรษณีย์ไทย กรุณายืนยันที่อยู่ภายใน 24 ชม. คลิก: cutt.ly/9xbb"
    print("\nHighlight result:")
    chunks = highlight_text(test_sms)
    for chunk in chunks:
        if chunk["type"]:
            print(f"  🔴 [{chunk['type']}] '{chunk['text']}'")
        else:
            print(f"  ⬜ '{chunk['text']}'")