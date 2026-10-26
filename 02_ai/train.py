# ============================================
# train.py — Train CyberSense WangchanBERTa model
# Run: python 02_ai/train.py  (from project root)
# ============================================

import json
import logging
import os
import pandas as pd
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer
)
import torch
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    fbeta_score,
    confusion_matrix,
    classification_report,
)

logging.basicConfig(level=logging.INFO, format="%(message)s")

BASE_DIR = os.path.dirname(__file__)
DATASET_PATH = os.path.join(BASE_DIR, "Thai_sms_dataset_final_700_(last_version-CSV).csv")
OUTPUT_DIR = os.path.join(BASE_DIR, "model_output")
MODEL_DIR = os.path.join(BASE_DIR, "cybersense_model")
RESULTS_PATH = os.path.join(BASE_DIR, "results", "metrics.json")

MODEL_NAME = "airesearch/wangchanberta-base-att-spm-uncased"
SEED = 42

df = pd.read_csv(DATASET_PATH)
df["input_text"] = "Sender: " + df["Sender"] + " | " + df["Text"]

logging.info("Dataset loaded! Total rows: %d", len(df))
logging.info("Scam (1): %d | Legit (0): %d", df['Label'].sum(), len(df) - df['Label'].sum())

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
logging.info("Tokenizer loaded!")

model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2)
logging.info("Model loaded!")

# 70% train / 15% validation (เลือก best model) / 15% test (วัดผลจริง ไม่เคยเห็นตอนเทรน)
train_texts, temp_texts, train_labels, temp_labels = train_test_split(
    df["input_text"].tolist(),
    df["Label"].tolist(),
    test_size=0.3,
    stratify=df["Label"],
    random_state=SEED
)
val_texts, test_texts, val_labels, test_labels = train_test_split(
    temp_texts,
    temp_labels,
    test_size=0.5,
    stratify=temp_labels,
    random_state=SEED
)
logging.info("Train: %d | Val: %d | Test: %d", len(train_texts), len(val_texts), len(test_texts))

train_encodings = tokenizer(train_texts, truncation=True, padding=True, max_length=128)
val_encodings = tokenizer(val_texts, truncation=True, padding=True, max_length=128)
test_encodings = tokenizer(test_texts, truncation=True, padding=True, max_length=128)
logging.info("Tokenization done!")


class SMSDataset(torch.utils.data.Dataset):
    def __init__(self, encodings, labels):
        self.encodings = encodings
        self.labels = labels

    def __getitem__(self, idx):
        item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
        item["labels"] = torch.tensor(self.labels[idx])
        return item

    def __len__(self):
        return len(self.labels)


train_dataset = SMSDataset(train_encodings, train_labels)
val_dataset = SMSDataset(val_encodings, val_labels)
test_dataset = SMSDataset(test_encodings, test_labels)

training_args = TrainingArguments(
    output_dir=OUTPUT_DIR,
    num_train_epochs=5,
    per_device_train_batch_size=16,
    per_device_eval_batch_size=16,
    warmup_steps=50,
    weight_decay=0.01,
    eval_strategy="epoch",
    save_strategy="epoch",
    save_total_limit=1,
    load_best_model_at_end=True,
    # F2 ให้น้ำหนัก recall มากกว่า precision 2 เท่า → เน้นลด False Negative (ปล่อย scam หลุด)
    # แต่ยังไม่เลือกโมเดลที่ตอบ "scam" ทุกข้อความ (ซึ่ง recall = 1.0)
    metric_for_best_model="f2",
    greater_is_better=True,
    seed=SEED,
    logging_dir=os.path.join(BASE_DIR, "logs"),
)


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    predictions = logits.argmax(axis=-1)

    # pos_label=1 → วัดเฉพาะคลาส scam
    return {
        "accuracy": accuracy_score(labels, predictions),
        "precision": precision_score(labels, predictions, pos_label=1, zero_division=0),
        "recall": recall_score(labels, predictions, pos_label=1, zero_division=0),
        "f1": f1_score(labels, predictions, pos_label=1, zero_division=0),
        "f2": fbeta_score(labels, predictions, beta=2, pos_label=1, zero_division=0),
    }


trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=val_dataset,
    compute_metrics=compute_metrics,
)

logging.info("Starting training... this might take a few minutes!")
trainer.train()

# ===== Final evaluation on held-out test set =====
test_output = trainer.predict(test_dataset)
test_preds = test_output.predictions.argmax(axis=-1)
cm = confusion_matrix(test_labels, test_preds, labels=[0, 1])
tn, fp, fn, tp = cm.ravel()

results = {
    "test_size": len(test_labels),
    "metrics": {k: round(float(v), 4) for k, v in compute_metrics((test_output.predictions, test_labels)).items()},
    "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
}

logging.info("\n===== Test set results (%d messages) =====", len(test_labels))
logging.info(classification_report(test_labels, test_preds, target_names=["legit", "scam"], digits=4))
logging.info("Confusion matrix: TN=%d FP=%d FN=%d TP=%d", tn, fp, fn, tp)

os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
with open(RESULTS_PATH, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)
logging.info("Results saved to %s", RESULTS_PATH)

trainer.model.save_pretrained(MODEL_DIR)  # best checkpoint (loaded by load_best_model_at_end)
tokenizer.save_pretrained(MODEL_DIR)
logging.info("Model saved to %s", MODEL_DIR)
logging.info("Training complete!")
