"""
Train a simple TensorFlow Keras model to classify SYN flood vs normal based on simulated features.
Generates synthetic dataset (for lab), trains model, and saves to `./model`.

Features: packet_rate, syn_ack_ratio, cpu_load, conn_table_size
Label: 1 (attack) / 0 (normal)

Run: python train_model.py
"""
import os
import numpy as np
import pandas as pd
from tensorflow import keras
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'model')
os.makedirs(MODEL_DIR, exist_ok=True)

KDD_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'models', 'dataset', 'KDDTrain+.csv'))


def load_kdd_dataset(nrows=None):
    """Load KDDTrain+ CSV (no header) and extract numeric features and binary labels.
    If `nrows` is provided, reads that many rows for faster tests.
    """
    # Column names for KDD dataset (41 features)
    colnames = [
        'duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent',
        'hot','num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root','num_file_creations',
        'num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count','srv_count',
        'serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate',
        'dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate'
    ]
    names = colnames + ['label', 'difficulty']
    print('Loading KDD dataset from', KDD_PATH, 'nrows=', nrows)
    df = pd.read_csv(KDD_PATH, names=names, header=None, nrows=nrows)
    # map label to binary: normal -> 0, others -> 1
    df['binary_label'] = df['label'].apply(lambda x: 0 if str(x).strip() == 'normal' else 1)
    # select numeric features only
    numeric_cols = [c for c in colnames if c not in ('protocol_type','service','flag')]
    # ensure numeric
    X = df[numeric_cols].apply(pd.to_numeric, errors='coerce').fillna(0).values
    y = df['binary_label'].values
    return X, y


def generate_synthetic_data(n=20000, attack_ratio=0.3, seed=42):
    np.random.seed(seed)
    rows = []
    for i in range(n):
        if np.random.rand() < attack_ratio:
            # attack sample
            packet_rate = np.random.normal(15000, 4000)
            syn_ack_ratio = np.random.uniform(10, 100)
            cpu_load = np.random.uniform(50, 95)
            conn_table_size = np.random.normal(20000, 5000)
            label = 1
        else:
            packet_rate = np.random.normal(2000, 800)
            syn_ack_ratio = np.random.uniform(0.5, 2.0)
            cpu_load = np.random.uniform(5, 40)
            conn_table_size = np.random.normal(2000, 800)
            label = 0
        rows.append((packet_rate, syn_ack_ratio, cpu_load, conn_table_size, label))
    df = pd.DataFrame(rows, columns=['packet_rate','syn_ack_ratio','cpu_load','conn_table_size','label'])
    # clip
    df['packet_rate'] = df['packet_rate'].clip(0)
    df['conn_table_size'] = df['conn_table_size'].clip(0)
    return df


def build_model(input_shape):
    model = keras.Sequential([
        keras.layers.Input(shape=(input_shape,)),
        keras.layers.Dense(64, activation='relu'),
        keras.layers.Dropout(0.2),
        keras.layers.Dense(32, activation='relu'),
        keras.layers.Dense(1, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model


def train_and_save(use_kdd=True, nrows=None, epochs=10, batch_size=256):
    # Train telemetry model (4-feature) — synthetic if KDD not used for these features
    print('Training telemetry (4-feature) model...')
    df = generate_synthetic_data(n=20000)
    X_tel = df[['packet_rate','syn_ack_ratio','cpu_load','conn_table_size']].values
    y_tel = df['label'].values

    scaler = StandardScaler()
    X_tel = scaler.fit_transform(X_tel)
    X_train, X_test, y_train, y_test = train_test_split(X_tel, y_tel, test_size=0.2, random_state=42)
    model = build_model(X_train.shape[1])
    model.fit(X_train, y_train, validation_data=(X_test, y_test), epochs=epochs, batch_size=batch_size)
    save_path = os.path.join(MODEL_DIR, 'tf_detector')
    model_file = save_path + '.keras'
    model.save(model_file)
    import joblib
    joblib.dump(scaler, os.path.join(MODEL_DIR, 'scaler.joblib'))
    print('Telemetry model and scaler saved to', model_file)

    # Train KDD model if requested and KDD dataset exists
    if use_kdd and os.path.exists(KDD_PATH):
        print('Training KDD model from', KDD_PATH)
        X_kdd, y_kdd = load_kdd_dataset(nrows=nrows)
        scaler_kdd = StandardScaler()
        X_kdd = scaler_kdd.fit_transform(X_kdd)
        X_tr, X_te, y_tr, y_te = train_test_split(X_kdd, y_kdd, test_size=0.2, random_state=42)
        model_kdd = build_model(X_tr.shape[1])
        model_kdd.fit(X_tr, y_tr, validation_data=(X_te, y_te), epochs=max(2, epochs//2), batch_size=batch_size)
        kdd_path = os.path.join(MODEL_DIR, 'kdd_detector.keras')
        model_kdd.save(kdd_path)
        joblib.dump(scaler_kdd, os.path.join(MODEL_DIR, 'scaler_kdd.joblib'))
        print('KDD model saved to', kdd_path)

    # Train SQL-injection model if Modified_SQL_Dataset.csv exists
    sql_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'models', 'dataset', 'Modified_SQL_Dataset.csv'))
    if os.path.exists(sql_path):
        print('Training SQL-injection model from', sql_path)
        sdf = pd.read_csv(sql_path)
        # basic feature extraction from query string
        def featurize_query(q: str):
            if pd.isna(q):
                q = ''
            s = str(q)
            length = len(s)
            non_alnum = sum(1 for ch in s if not ch.isalnum() and not ch.isspace())
            quotes = s.count("'") + s.count('"')
            digits = sum(c.isdigit() for c in s)
            keywords = sum(1 for k in ['select','union','insert','sleep','drop','exec','waitfor'] if k in s.lower())
            avg_tok_len = 0.0
            toks = [t for t in ''.join(ch if ch.isalnum() else ' ' for ch in s).split()]
            if toks:
                avg_tok_len = sum(len(t) for t in toks)/len(toks)
            return [length, non_alnum, quotes, digits, keywords, avg_tok_len]

        feats = sdf['Query'].apply(featurize_query).tolist()
        X_sql = np.array(feats, dtype=float)
        y_sql = sdf['Label'].astype(int).values
        scaler_sql = StandardScaler()
        X_sql = scaler_sql.fit_transform(X_sql)
        X_tr, X_te, y_tr, y_te = train_test_split(X_sql, y_sql, test_size=0.2, random_state=42)
        model_sql = build_model(X_tr.shape[1])
        model_sql.fit(X_tr, y_tr, validation_data=(X_te, y_te), epochs=max(2, epochs//2), batch_size=256)
        sql_model_path = os.path.join(MODEL_DIR, 'sql_detector.keras')
        model_sql.save(sql_model_path)
        joblib.dump(scaler_sql, os.path.join(MODEL_DIR, 'scaler_sql.joblib'))
        print('SQL model saved to', sql_model_path)


if __name__ == '__main__':
    # allow overriding rows/epochs via env vars for quick tests
    nrows = os.getenv('TRAIN_ROWS')
    if nrows:
        nrows = int(nrows)
    epochs = int(os.getenv('TRAIN_EPOCHS', '5'))
    # default to using KDD dataset when available
    train_and_save(use_kdd=True, nrows=nrows, epochs=epochs)
