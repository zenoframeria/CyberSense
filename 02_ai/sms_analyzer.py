# ============================================
# STEP 1: Import libraries we need
# ============================================

import pandas as pd  
# pandas = our tool for reading CSV files, like Excel but in Python

from transformers import (
    AutoTokenizer,           
    # AutoTokenizer = converts Thai text → numbers that AI can understand
    AutoModelForSequenceClassification,  
    # AutoModel... = loads WangchanBERTa with a classification head on top
    TrainingArguments,       
    # TrainingArguments = settings for training (how many rounds, speed, etc.)
    Trainer                  
    # Trainer = the thing that actually runs the training loop for us
)

import torch  
# torch = the engine that powers all AI calculations (needs GPU/CPU)

from sklearn.model_selection import train_test_split  
# train_test_split = splits our 700 rows into train set and test set

from sklearn.metrics import accuracy_score, f1_score  
# accuracy_score, f1_score = tools to measure how good our model is

# ============================================
# STEP 2: Load our dataset
# ============================================

# read CSV file into a table (like opening Excel)
df = pd.read_csv("02_ai/Thai_sms_dataset_final_700_(last_version-CSV).csv")

# combine Sender + Text so model sees who sent it too
# example: "KBank: รหัส OTP ของคุณคือ xxxxxx"
df["input_text"] = "Sender: " + df["Sender"] + " | " + df["Text"]

print(f"Dataset loaded! Total rows: {len(df)}")
print(f"Scam (1): {df['Label'].sum()} | Legit (0): {len(df) - df['Label'].sum()}")

# ============================================
# STEP 3: Load WangchanBERTa tokenizer
# ============================================

MODEL_NAME = "airesearch/wangchanberta-base-att-spm-uncased"
# this is the exact name on HuggingFace, like an app ID

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
# from_pretrained = download model from HuggingFace (first time only, then cached)

print("Tokenizer loaded!")

# ============================================
# STEP 4: Load WangchanBERTa Model
# ============================================

model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_NAME,
    # num_labels = how many classes we want to classify
    # 2 = scam (1) or legit (0)
    num_labels=2
)

print("Model loaded!")

# ============================================
# STEP 5: Prepare data for training
# ============================================

# split dataset: 80% train, 20% test
# random_state=42 means we always get the same split (reproducible)
train_texts, test_texts, train_labels, test_labels = train_test_split(
    df["input_text"].tolist(),  # our combined Sender + Text column
    df["Label"].tolist(),       # our 0/1 labels
    test_size=0.2,              # 20% goes to test set
    random_state=42             # same split every time we run
)

print(f"Train: {len(train_texts)} rows | Test: {len(test_texts)} rows")

# ============================================
# STEP 6: Tokenize — convert text to numbers
# ============================================

# tokenizer converts Thai text → numbers that model understands
# truncation=True = cut text if too long (model has max input limit)
# padding=True = add padding so all inputs are same length
# max_length=128 = max tokens per SMS (SMS are short, 128 is enough)
train_encodings = tokenizer(
    train_texts,
    truncation=True,
    padding=True,
    max_length=128
)

test_encodings = tokenizer(
    test_texts,
    truncation=True,
    padding=True,
    max_length=128
)

print("Tokenization done!")

# ============================================
# STEP 7: Create Dataset class for HuggingFace Trainer
# ============================================

# HuggingFace Trainer needs data in a specific format
# we create a custom Dataset class to wrap our data
class SMSDataset(torch.utils.data.Dataset):
    
    def __init__(self, encodings, labels):
        # store encodings (numbers) and labels (0/1)
        self.encodings = encodings
        self.labels = labels

    def __getitem__(self, idx):
        # return one row at a time when Trainer asks for it
        item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
        item["labels"] = torch.tensor(self.labels[idx])
        return item

    def __len__(self):
        # tell Trainer how many rows we have
        return len(self.labels)

# wrap our train and test data into SMSDataset
train_dataset = SMSDataset(train_encodings, train_labels)
test_dataset = SMSDataset(test_encodings, test_labels)

print(f"Dataset ready! Train: {len(train_dataset)} | Test: {len(test_dataset)}")

# ============================================
# STEP 8: Set training settings
# ============================================

training_args = TrainingArguments(
    output_dir="02_ai/model_output",  # where to save model checkpoints
    num_train_epochs=3,               # read dataset 3 times
    per_device_train_batch_size=16,   # process 16 rows at a time (fits RTX 3060)
    per_device_eval_batch_size=16,    # same for evaluation
    warmup_steps=50,                  # slowly increase learning rate at start
    weight_decay=0.01,                # prevent overfitting (memorizing too much)
    eval_strategy="epoch",            # check accuracy after each epoch
    save_strategy="epoch",            # save model after each epoch
    load_best_model_at_end=True,      # keep the best model, not the last one
    logging_dir="02_ai/logs",         # where to save training logs
)

# ============================================
# STEP 9: Define how to measure accuracy
# ============================================

def compute_metrics(eval_pred):
    # this function is called after each epoch to measure performance
    logits, labels = eval_pred
    predictions = logits.argmax(axis=-1)  # pick highest score as prediction
    
    acc = accuracy_score(labels, predictions)
    f1 = f1_score(labels, predictions, average="weighted")
    
    # add precision and recall separately so we can see them
    from sklearn.metrics import precision_score, recall_score
    precision = precision_score(labels, predictions, average="weighted")
    recall = recall_score(labels, predictions, average="weighted")
    
    return {
        "accuracy": acc,
        "f1": f1,
        "precision": precision,
        "recall": recall    # most important for scam detection!
    }

# ============================================
# STEP 10: Train the model!
# ============================================

trainer = Trainer(
    model=model,                        # our WangchanBERTa model
    args=training_args,                 # settings from step 8
    train_dataset=train_dataset,        # 560 rows to learn from
    eval_dataset=test_dataset,          # 140 rows to test on
    compute_metrics=compute_metrics,    # function to measure accuracy
)

print("Starting training... this might take a few minutes!")
# trainer.train()

# ============================================
# STEP 11: Save the trained model
# ============================================

# save model and tokenizer so we can use it later without retraining
# model.save_pretrained("02_ai/cybersense_model")
# tokenizer.save_pretrained("02_ai/cybersense_model")

print("Model saved to 02_ai/cybersense_model!")
print("Training complete!")

# ============================================
# STEP 12: Load saved model for inference
# ============================================

from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import threading
from xai import detect_signals, highlight_text

# load model once and reuse — don't reload every time!
MODEL_PATH = "02_ai/cybersense_model"
_tokenizer = None
_model = None
_model_lock = threading.Lock()

def _load_model():
    global _tokenizer, _model
    if _tokenizer is None:
        with _model_lock:
            if _tokenizer is None:  # double-checked: re-verify inside lock
                print("Loading model...")
                _tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
                _model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
                _model.eval()
                print("Model ready!")

# ============================================
# STEP 13: Predict risk score from SMS text
# ============================================

def predict(text, sender=""):
    _load_model() # ห้ามลบเด็ดขาด!
    
    
    # 2. กันค่าว่าง/Unknown
    if not sender or sender.lower() in ["unknown", "unknow", "null", "ทั่วไป"]:
        current_sender = "SMS" # ใช้คำว่า "SMS" แทนเพื่อลด Bias ของโมเดล
    else:
        current_sender = sender
        
    input_text = f"Sender: {current_sender} | {text}"
    
    inputs = _tokenizer(input_text, return_tensors="pt", truncation=True, padding=True, max_length=128)
    with torch.no_grad():
        outputs = _model(**inputs)
    
    probs = torch.softmax(outputs.logits, dim=1)
    return int(probs[0][1].item() * 100)

# ============================================
# STEP 14: Main analyze function
# combines WangchanBERTa + XAI + Rule-based Fallback
# ============================================

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
            risk_score = 80   # SCAM: unknown + แนบลิงก์
        else:
            risk_score = 55   # SUSPICIOUS: unknown + ขอเงิน/บัญชี แต่ไม่มีลิงก์
    else:
        # เคสปกติ: ปล่อยให้โมเดลทำงาน
        risk_score = predict(text, sender)
        
        # Zero Trust เดิม: unknown ที่ไม่ติด keyword เสี่ยง
        if is_unknown_sender:
            if has_safe_word and not has_link:
                risk_score = 15  # ปลอดภัยจริง (เช่น "แม่ ถึงบ้านยัง")
            else:
                risk_score = max(risk_score, 45)  # ตรึงขั้นต่ำ SUSPICIOUS
    
    # 5. สรุป Label
    if risk_score >= 80: label = "SCAM"
    elif risk_score >= 45: label = "SUSPICIOUS"
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

# ============================================
# Test analyze_sms!
# ============================================

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