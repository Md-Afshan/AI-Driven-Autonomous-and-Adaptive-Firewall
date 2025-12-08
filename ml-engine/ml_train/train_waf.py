"""
Training script for WAF (Web Application Firewall) - SQL Injection Detection using 1D-CNN
"""
import os
import pickle
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, Conv1D, MaxPooling1D, Flatten, Dense, Dropout
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.model_selection import train_test_split
import logging
import pandas as pd

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'models')
DATASET_DIR = os.path.join(os.path.dirname(__file__), '..', 'models', 'dataset')
MAX_VOCAB_SIZE = 5000
MAX_SEQ_LENGTH = 200
EMBEDDING_DIM = 128
BATCH_SIZE = 32
EPOCHS = 20
VALIDATION_SPLIT = 0.2

# Ensure model directory exists
os.makedirs(MODEL_DIR, exist_ok=True)


def load_sql_injection_dataset():
    """
    Load SQL Injection dataset. Returns sample payloads for training.
    Prefer loading the original dataset from `ml-engine/models/dataset/Modified_SQL_Dataset.csv`.
    If the file is not found, fall back to a small synthetic sample set.
    """
    logger.info("Loading SQL Injection dataset...")
    # Try to load original dataset
    dataset_path = os.path.join(DATASET_DIR, 'Modified_SQL_Dataset.csv')
    if os.path.exists(dataset_path):
        try:
            df = pd.read_csv(dataset_path, encoding='utf-8', engine='python')
            # Expecting columns: Query, Label
            if 'Query' in df.columns and 'Label' in df.columns:
                payloads = df['Query'].astype(str).tolist()
                labels = df['Label'].apply(lambda x: 1 if str(x).strip() in ['1', 'attack', 'malicious'] else 0).values
                logger.info(f"Loaded {len(payloads)} samples from {dataset_path}")
                return payloads, labels
            else:
                logger.warning(f"Dataset file found but missing expected columns: {dataset_path}")
        except Exception as e:
            logger.warning(f"Failed to read dataset {dataset_path}: {e}")

    # Fallback synthetic dataset
    # Sample SQL injection payloads for training
    sql_payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin' --",
        "' OR 'a'='a",
        "1' UNION SELECT NULL--",
        "'; DROP TABLE users--",
        "1' AND '1'='1",
        "' OR 'x'='x",
        "admin' OR '1'='1",
        "' UNION SELECT name FROM users--",
    ] * 50  # Repeat for more samples
    
    # Safe payloads for negative samples
    safe_payloads = [
        "SELECT * FROM users",
        "INSERT INTO orders VALUES",
        "UPDATE products SET price",
        "DELETE FROM logs",
        "CREATE TABLE customers",
        "ALTER TABLE products ADD column",
        "SELECT COUNT(*) FROM sales",
        "INSERT INTO audit_log",
        "SELECT user_id, name FROM accounts",
        "UPDATE inventory SET quantity",
    ] * 50
    
    # Combine and create labels (1 = SQL injection, 0 = safe)
    payloads = sql_payloads + safe_payloads
    labels = np.array([1] * len(sql_payloads) + [0] * len(safe_payloads))
    logger.info(f"Using synthetic dataset with {len(payloads)} samples")
    return payloads, labels


def create_tokenizer(payloads):
    """Create and fit tokenizer on payloads"""
    logger.info("Creating tokenizer...")
    tokenizer = Tokenizer(num_words=MAX_VOCAB_SIZE, char_level=False)
    tokenizer.fit_on_texts(payloads)
    logger.info(f"Tokenizer created with {len(tokenizer.word_index)} unique tokens")
    return tokenizer


def preprocess_payloads(payloads, tokenizer):
    """Tokenize and pad sequences"""
    logger.info("Preprocessing payloads...")
    sequences = tokenizer.texts_to_sequences(payloads)
    padded_sequences = pad_sequences(sequences, maxlen=MAX_SEQ_LENGTH, padding='post')
    logger.info(f"Padded sequences shape: {padded_sequences.shape}")
    return padded_sequences


def build_1d_cnn_model(vocab_size):
    """Build 1D CNN model for sequence classification"""
    logger.info("Building 1D-CNN model...")
    
    model = Sequential([
        Embedding(input_dim=vocab_size + 1, output_dim=EMBEDDING_DIM, input_length=MAX_SEQ_LENGTH),
        Conv1D(filters=64, kernel_size=5, activation='relu'),
        MaxPooling1D(pool_size=2),
        Conv1D(filters=128, kernel_size=5, activation='relu'),
        MaxPooling1D(pool_size=2),
        Flatten(),
        Dense(256, activation='relu'),
        Dropout(0.5),
        Dense(128, activation='relu'),
        Dropout(0.3),
        Dense(1, activation='sigmoid')  # Binary classification
    ])
    
    model.compile(
        optimizer='adam',
        loss='binary_crossentropy',
        metrics=['accuracy']
    )
    
    logger.info("Model summary:")
    model.summary()
    return model


def train_waf_model():
    """Main training function"""
    logger.info("Starting WAF model training...")
    
    # Load dataset
    payloads, labels = load_sql_injection_dataset()
    
    # Create tokenizer
    tokenizer = create_tokenizer(payloads)
    
    # Preprocess
    X = preprocess_payloads(payloads, tokenizer)
    y = labels
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    
    logger.info(f"Train set: {X_train.shape}, Test set: {X_test.shape}")
    
    # Build and train model
    model = build_1d_cnn_model(len(tokenizer.word_index))
    
    history = model.fit(
        X_train, y_train,
        validation_split=VALIDATION_SPLIT,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        verbose=1
    )
    
    # Evaluate
    test_loss, test_accuracy = model.evaluate(X_test, y_test, verbose=0)
    logger.info(f"Test Accuracy: {test_accuracy:.4f}, Test Loss: {test_loss:.4f}")
    
    # Save model and tokenizer
    model_path = os.path.join(MODEL_DIR, 'waf_cnn.h5')
    tokenizer_path = os.path.join(MODEL_DIR, 'tokenizer.pkl')
    
    model.save(model_path)
    logger.info(f"Model saved to {model_path}")
    
    with open(tokenizer_path, 'wb') as f:
        pickle.dump(tokenizer, f)
    logger.info(f"Tokenizer saved to {tokenizer_path}")
    
    return model, tokenizer, history


if __name__ == '__main__':
    train_waf_model()
    logger.info("WAF training completed!")
