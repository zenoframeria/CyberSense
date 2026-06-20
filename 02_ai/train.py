# ============================================
# train.py — Train CyberSense WangchanBERTa model
# Run: python 02_ai/train.py  (from project root)
# ============================================

import logging
import pandas as pd
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer
)
import torch
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score

logging.basicConfig(level=logging.INFO, format="%(message)s")

df = pd.read_csv("02_ai/Thai_sms_dataset_final_700_(last_version-CSV).csv")
df["input_text"] = "Sender: " + df["Sender"] + " | " + df["Text"]

logging.info("Dataset loaded! Total rows: %d", len(df))
logging.info("Scam (1): %d | Legit (0): %d", df['Label'].sum(), len(df) - df['Label'].sum())

MODEL_NAME = "airesearch/wangchanberta-base-att-spm-uncased"

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
logging.info("Tokenizer loaded!")

model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2)
logging.info("Model loaded!")

train_texts, test_texts, train_labels, test_labels = train_test_split(
    df["input_text"].tolist(),
    df["Label"].tolist(),
    test_size=0.2,
    random_state=42
)
logging.info("Train: %d rows | Test: %d rows", len(train_texts), len(test_texts))

train_encodings = tokenizer(train_texts, truncation=True, padding=True, max_length=128)
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
test_dataset = SMSDataset(test_encodings, test_labels)
logging.info("Dataset ready! Train: %d | Test: %d", len(train_dataset), len(test_dataset))

training_args = TrainingArguments(
    output_dir="02_ai/model_output",
    num_train_epochs=3,
    per_device_train_batch_size=16,
    per_device_eval_batch_size=16,
    warmup_steps=50,
    weight_decay=0.01,
    eval_strategy="epoch",
    save_strategy="epoch",
    load_best_model_at_end=True,
    logging_dir="02_ai/logs",
)


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    predictions = logits.argmax(axis=-1)

    from sklearn.metrics import precision_score, recall_score
    return {
        "accuracy": accuracy_score(labels, predictions),
        "f1": f1_score(labels, predictions, average="weighted"),
        "precision": precision_score(labels, predictions, average="weighted"),
        "recall": recall_score(labels, predictions, average="weighted"),
    }


trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=test_dataset,
    compute_metrics=compute_metrics,
)

logging.info("Starting training... this might take a few minutes!")
trainer.train()

model.save_pretrained("02_ai/cybersense_model")
tokenizer.save_pretrained("02_ai/cybersense_model")
logging.info("Model saved to 02_ai/cybersense_model!")
logging.info("Training complete!")
