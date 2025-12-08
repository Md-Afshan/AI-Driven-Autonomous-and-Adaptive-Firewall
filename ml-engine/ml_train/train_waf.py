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
import warnings
warnings.filterwarnings('ignore', category=UserWarning)

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


def load_sql_injection_dataset(sample_size=None):
    """
    Load SQL Injection dataset. Returns sample payloads for training.
    Prefer loading the original dataset from `ml-engine/models/dataset/Modified_SQL_Dataset.csv`.
    If the file is not found, fall back to a small synthetic sample set.
    
    Args:
        sample_size: Optional limit on number of samples to load (for quick testing)
    """
    logger.info("Loading SQL Injection dataset...")
    # Try to load original dataset
    dataset_path = os.path.join(DATASET_DIR, 'Modified_SQL_Dataset.csv')
    if os.path.exists(dataset_path):
        try:
            df = pd.read_csv(dataset_path, encoding='utf-8', engine='python')
            # Expecting columns: Query, Label
            if 'Query' in df.columns and 'Label' in df.columns:
                # Apply sample_size if provided
                if sample_size and sample_size > 0:
                    df = df.sample(n=min(sample_size, len(df)), random_state=42)
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
    
    # Apply sample_size if provided
    if sample_size and sample_size > 0:
        indices = np.random.choice(len(payloads), size=min(sample_size, len(payloads)), replace=False)
        payloads = [payloads[i] for i in indices]
        labels = labels[indices]
        logger.info(f"Sampled down to {len(payloads)} samples")
    
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


def build_1d_cnn_model(vocab_size, reduced=False):
    """Build 1D CNN model for sequence classification
    
    Args:
        vocab_size: Size of vocabulary
        reduced: If True, use a smaller model for quick testing
    """
    logger.info("Building 1D-CNN model...")
    
    if reduced:
        # Smaller model for quick testing
        model = Sequential([
            Embedding(input_dim=vocab_size + 1, output_dim=64),
            Conv1D(32, 5, activation='relu'),
            MaxPooling1D(5),
            Flatten(),
            Dense(32, activation='relu'),
            Dropout(0.3),
            Dense(1, activation='sigmoid')
        ])
    else:
        # Full model
        model = Sequential([
            Embedding(input_dim=vocab_size + 1, output_dim=EMBEDDING_DIM),
            Conv1D(128, 5, activation='relu'),
            MaxPooling1D(5),
            Conv1D(64, 5, activation='relu'),
            MaxPooling1D(5),
            Flatten(),
            Dense(128, activation='relu'),
            Dropout(0.5),
            Dense(1, activation='sigmoid')
        ])
    
    model.compile(
        optimizer='adam',
        loss='binary_crossentropy',
        metrics=['accuracy']
    )
    
    logger.info("Model summary:")
    model.summary()
    return model


def train_waf_model(sample_size=None):
    """Main training function

    Args:
        sample_size: Optional limit on dataset size for quick testing
    """
    logger.info("Starting WAF model training...")
    
    # Load dataset
    payloads, labels = load_sql_injection_dataset(sample_size=sample_size)
    
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
    reduced = sample_size is not None and sample_size > 0 and sample_size < 1000
    model = build_1d_cnn_model(len(tokenizer.word_index), reduced=reduced)
    
    # Reduce epochs for sample training
    epochs = 3 if sample_size and sample_size > 0 else EPOCHS
    logger.info(f"Training for {epochs} epochs...")
    
    history = model.fit(
        X_train, y_train,
        validation_split=VALIDATION_SPLIT,
        epochs=epochs,
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


def train_waf_sample(sample_size: int):
    """Convenience wrapper for sample-size runs from train_manager"""
    return train_waf_model(sample_size=sample_size)


if __name__ == '__main__':
    train_waf_model()
    logger.info("WAF training completed!")
