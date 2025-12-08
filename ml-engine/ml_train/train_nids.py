"""
Training script for NIDS (Network Intrusion Detection System) - DDoS Detection using Random Forest
"""
import os
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'models')
DATASET_DIR = os.path.join(os.path.dirname(__file__), '..', 'models', 'dataset')
N_ESTIMATORS = 100
RANDOM_STATE = 42
TEST_SIZE = 0.2

# Ensure model directory exists
os.makedirs(MODEL_DIR, exist_ok=True)


def load_nsl_kdd_dataset():
    """
    Load NSL-KDD dataset (KDDTrain+.csv) if available; otherwise generate synthetic network flow data.
    When loading KDDTrain+.csv we perform simple preprocessing:
      - treat second-last column as label (normal vs attack)
      - drop `service` column to limit dimensionality
      - one-hot encode `protocol_type` and `flag`
    """
    logger.info("Loading NSL-KDD dataset...")
    # Try to load original KDD dataset
    dataset_path = os.path.join(DATASET_DIR, 'KDDTrain+.csv')
    if os.path.exists(dataset_path):
        try:
            df = pd.read_csv(dataset_path, header=None)
            # label is typically the second-last column
            label_col = df.shape[1] - 2
            labels = df.iloc[:, label_col].astype(str).apply(lambda x: 0 if x.strip().lower() == 'normal' else 1)

            # Drop `service` column (index 2) to limit cardinality
            drop_cols = [2]
            # Keep protocol_type (index 1) and flag (index 3) as categorical
            cat_cols = [1, 3]

            # Numeric feature columns: all except categorical, label, and final difficulty/count column
            drop_cols += [label_col, df.shape[1] - 1]
            numeric_cols = [i for i in range(df.shape[1]) if i not in cat_cols + drop_cols]

            numeric_df = df.iloc[:, numeric_cols].apply(pd.to_numeric, errors='coerce').fillna(0)
            cat_df = pd.get_dummies(df.iloc[:, cat_cols].astype(str), prefix=['proto', 'flag'])

            X = pd.concat([numeric_df.reset_index(drop=True), cat_df.reset_index(drop=True)], axis=1).values
            y = labels.values.astype(int)

            logger.info(f"Loaded KDD dataset with {X.shape[0]} samples and {X.shape[1]} features")
            return X, y
        except Exception as e:
            logger.warning(f"Failed to load KDD dataset {dataset_path}: {e}")

    # Fallback: generate synthetic network flow features
    np.random.seed(RANDOM_STATE)
    n_samples = 2000

    # Normal traffic features
    normal_traffic = np.random.normal(
        loc=[100, 0.5, 1024, 50, 100, 10],
        scale=[20, 0.1, 512, 10, 20, 5],
        size=(n_samples // 2, 6)
    )

    # DDoS traffic features (high packet count, high rate, small packet size)
    ddos_traffic = np.random.normal(
        loc=[500, 0.95, 64, 200, 500, 50],
        scale=[100, 0.05, 32, 30, 100, 10],
        size=(n_samples // 2, 6)
    )

    # Combine and create labels
    X = np.vstack([normal_traffic, ddos_traffic])
    y = np.array([0] * (n_samples // 2) + [1] * (n_samples // 2))

    # Shuffle
    shuffle_idx = np.random.permutation(n_samples)
    X = X[shuffle_idx]
    y = y[shuffle_idx]

    logger.info(f"Using synthetic dataset with {n_samples} samples (Normal: {(y==0).sum()}, DDoS: {(y==1).sum()})")
    return X, y


def create_scaler(X):
    """Create and fit StandardScaler"""
    logger.info("Creating StandardScaler...")
    scaler = StandardScaler()
    scaler.fit(X)
    logger.info("StandardScaler created and fitted")
    return scaler


def scale_features(X, scaler):
    """Scale features using fitted scaler"""
    logger.info("Scaling features...")
    X_scaled = scaler.transform(X)
    logger.info(f"Scaled features shape: {X_scaled.shape}")
    return X_scaled


def build_random_forest_model():
    """Build Random Forest classifier"""
    logger.info("Building Random Forest model...")
    
    model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        verbose=1
    )
    
    logger.info("Random Forest model created")
    return model


def train_nids_model():
    """Main training function"""
    logger.info("Starting NIDS model training...")
    
    # Load dataset
    X, y = load_nsl_kdd_dataset()
    
    # Create scaler
    scaler = create_scaler(X)
    
    # Scale features
    X_scaled = scale_features(X, scaler)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    
    logger.info(f"Train set: {X_train.shape}, Test set: {X_test.shape}")
    
    # Build and train model
    model = build_random_forest_model()
    
    logger.info("Training Random Forest model...")
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    logger.info(f"\nAccuracy: {accuracy:.4f}")
    logger.info("\nClassification Report:")
    logger.info(classification_report(y_test, y_pred, target_names=['Normal', 'DDoS']))
    logger.info("\nConfusion Matrix:")
    logger.info(confusion_matrix(y_test, y_pred))
    
    # Feature importance
    logger.info("\nFeature Importance:")
    feature_names = ['packet_count', 'packet_rate', 'avg_packet_size', 'flow_duration', 'bytes_sent', 'protocol_variety']
    for name, importance in zip(feature_names, model.feature_importances_):
        logger.info(f"  {name}: {importance:.4f}")
    
    # Save model and scaler
    model_path = os.path.join(MODEL_DIR, 'nids_rf.pkl')
    scaler_path = os.path.join(MODEL_DIR, 'scaler.pkl')
    
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    logger.info(f"Model saved to {model_path}")
    
    with open(scaler_path, 'wb') as f:
        pickle.dump(scaler, f)
    logger.info(f"Scaler saved to {scaler_path}")
    
    return model, scaler


if __name__ == '__main__':
    train_nids_model()
    logger.info("NIDS training completed!")
