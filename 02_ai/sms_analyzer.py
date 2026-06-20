from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import threading
import logging
import os
from xai import detect_signals, highlight_text

MODEL_PATH = os.path.join(os.path.dirname(__file__), "cybersense_model")

# Risk score thresholds
RISK_THRESHOLD_SCAM = 80
RISK_THRESHOLD_SUSPICIOUS = 45

# Fallback risk scores for rule-based layer (bypasses model for OOD cases)
RISK_SCORE_UNKNOWN_WITH_LINK = 80
RISK_SCORE_UNKNOWN_WITH_FINANCIAL = 55
RISK_SCORE_UNKNOWN_SAFE = 15
RISK_SCORE_UNKNOWN_MIN = 45

_tokenizer = None
_model = None
_model_lock = threading.Lock()


def _load_model():
    global _tokenizer, _model
    if _tokenizer is None:
        with _model_lock:
            if _tokenizer is None:  # double-checked: re-verify inside lock
                logging.info("Loading model...")
                _tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
                _model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
                _model.eval()
                logging.info("Model ready!")


def predict(text, sender=""):
    _load_model() # ห้ามลบเด็ดขาด!

    if not sender or sender.lower() in ["unknown", "unknow", "null", "ทั่วไป"]:
        current_sender = "SMS" # ใช้คำว่า "SMS" แทนเพื่อลด Bias ของโมเดล
    else:
        current_sender = sender

    input_text = f"Sender: {current_sender} | {text}"

    assert _tokenizer is not None and _model is not None
    inputs = _tokenizer(input_text, return_tensors="pt", truncation=True, padding=True, max_length=128)
    with torch.no_grad():
        outputs = _model(**inputs)

    probs = torch.softmax(outputs.logits, dim=1)
    return int(probs[0][1].item() * 100)


# High-risk keywords สำหรับเลเยอร์ Rule-based (ดักหน้าโมเดล)
# แยกเป็นหมวด: การเงิน + ลิงก์ + บัญชี
FINANCIAL_RISK_KEYWORDS = [
    "โอนเงิน", "โอนตัง", "โอนตังค์", "โอนเข้า", "ขอตัง", "ขอตังค์",
    "ขอยืม", "ยืมเงิน", "โอนด่วน", "โอนให้หน่อย", "ช่วยโอน",
    "เลขบัญชี", "เลขที่บัญชี", "บัญชีธนาคาร", "พร้อมเพย์", "promptpay",
    "เบอร์พร้อมเพย์", "สแกนจ่าย", "qr", "กดรับเงิน", "รับโอน"
]


def analyze_sms(text, sender=""):
    # ===== Rule 0: แยก sender จากช่องเดียว (รูปแบบ "sender | text") =====
    # ทำก่อนทุก logic เพื่อให้ rule-based layer เห็น sender ด้วย
    if "|" in text and not sender:
        parts = text.split("|", 1)
        sender = parts[0].strip()
        text = parts[1].strip()

    # ===== Rule 1: ถ้าไม่มี sender ให้ default เป็น "unknown" =====
    if not sender or not sender.strip():
        sender = "unknown"

    # 3. จัดการกรณี "unknown"/"unknow" → มองเป็นค่าว่างเพื่อเข้า Zero Trust
    if sender.lower() in ["unknown", "unknow", "null", "ทั่วไป"]:
        sender = ""

    is_unknown_sender = not sender or sender.strip() == ""

    # ===== Rule 2: Rule-based Fallback Layer (ดักหน้าโมเดล) =====
    # ตรวจ keyword ความเสี่ยงสูง "ก่อน" ปล่อยให้โมเดลเดา
    text_lower = text.lower()
    has_link = any(link in text_lower for link in ["http", "https", "www.", ".com", ".ly", ".cc", ".xyz", ".top", ".click", "คลิก", "👉"])
    has_financial_risk = any(kw in text_lower for kw in FINANCIAL_RISK_KEYWORDS)
    has_high_risk = has_link or has_financial_risk

    safe_words = ["แม่", "พ่อ", "ลูก", "พี่", "น้อง", "แฟน", "เพื่อน", "กินข้าว", "ค่าข้าว", "กลับบ้าน", "ตื่นยัง", "รักนะ", "คิดถึง", "ถึงแล้ว"]
    has_safe_word = any(word in text for word in safe_words)

    # ถ้า unknown + high-risk → ข้ามโมเดลไปเลย ตัดเป็น SUSPICIOUS ทันที
    # ไม่ปล่อยให้โมเดลเดาสุ่ม เพราะเคสนี้อยู่นอก Dataset (OOD)
    fallback_triggered = False
    if is_unknown_sender and has_high_risk:
        fallback_triggered = True
        # ลิงก์เสี่ยงกว่าการขอเงินเปล่าๆ → ให้คะแนนต่างกัน
        if has_link:
            risk_score = RISK_SCORE_UNKNOWN_WITH_LINK
        else:
            risk_score = RISK_SCORE_UNKNOWN_WITH_FINANCIAL
    else:
        # เคสปกติ: ปล่อยให้โมเดลทำงาน
        risk_score = predict(text, sender)

        # Zero Trust เดิม: unknown ที่ไม่ติด keyword เสี่ยง
        if is_unknown_sender:
            if has_safe_word and not has_link:
                risk_score = RISK_SCORE_UNKNOWN_SAFE
            else:
                risk_score = max(risk_score, RISK_SCORE_UNKNOWN_MIN)

    # 5. สรุป Label
    if risk_score >= RISK_THRESHOLD_SCAM: label = "SCAM"
    elif risk_score >= RISK_THRESHOLD_SUSPICIOUS: label = "SUSPICIOUS"
    else: label = "LEGIT"

    signals = detect_signals(text, sender)
    highlights = highlight_text(text, sender)

    # แอบเติม Warning ใน Signals
    if is_unknown_sender and label in ["SUSPICIOUS", "SCAM"]:
        signals.append({"type": "sender_warning", "label": "⚠️ ไม่พบผู้ส่งที่ยืนยันได้ โปรดระวัง"})

    # เพิ่ม signal บอกว่า rule-based ทำงาน (โปร่งใส/อธิบายได้)
    if fallback_triggered:
        reason = "พบลิงก์น่าสงสัย" if has_link else "พบการขอเงิน/ข้อมูลบัญชี"
        signals.append({
            "type": "rule_fallback",
            "label": f"🛡️ ระบบตรวจจับกฎ: {reason} จากผู้ส่งไม่ทราบที่มา"
        })

    return {
        "risk": risk_score,
        "label": label,
        "signals": signals,
        "highlights": highlights
    }


if __name__ == "__main__":
    test_sms = "ท่านมีพัสดุค้างที่ไปรษณีย์ไทย กรุณายืนยันที่อยู่ภายใน 24 ชม. คลิก: cutt.ly/9xbb"

    result = analyze_sms(test_sms, "ไปรษณีย์ไทย")

    print(f"Risk: {result['risk']}%")
    print(f"Label: {result['label']}")
    print(f"\nSignals ({len(result['signals'])} found):")
    for s in result['signals']:
        print(f"  [{s['type']}] {s['label']}")
    print(f"\nHighlights ({len(result['highlights'])} chunks):")
    for h in result['highlights']:
        if h['type']:
            print(f"  🔴 [{h['type']}] '{h['text']}'")
