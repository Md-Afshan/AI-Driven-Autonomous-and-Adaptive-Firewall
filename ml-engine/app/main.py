from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
import asyncio
import uvicorn
from rl_agent.agent_worker import AgentWorker
import os
import numpy as np
from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
import asyncio
import uvicorn
from rl_agent.agent_worker import AgentWorker
import os
import numpy as np
from tensorflow import keras
from typing import Dict, List
import glob
import joblib
from datetime import datetime

app = FastAPI(title="ML Engine Receiver")

class Alert(BaseModel):
    type: str
    ip: str
    metrics: dict = {}

# Simple in-process queue and worker
queue = asyncio.Queue()
worker = None
MODEL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'model'))
os.makedirs(MODEL_DIR, exist_ok=True)
_MODEL = None
_SCALER = None
_ACTIVE_MODEL = None
_MODEL_KDD = None
_SCALER_KDD = None
_MODEL_SQL = None
_SCALER_SQL = None
_PPO_MODEL = None


def discover_models() -> List[str]:
    pattern = os.path.join(MODEL_DIR, '*.keras')
    files = glob.glob(pattern)
    files_sorted = sorted(files, key=os.path.getmtime, reverse=True)
    return files_sorted


def load_model(name: str = None):
    global _MODEL, _SCALER, _ACTIVE_MODEL
    try:
        if name:
            model_path = os.path.join(MODEL_DIR, name)
        else:
            models = discover_models()
            if not models:
                print('No models found in', MODEL_DIR)
                _MODEL = None
                _SCALER = None
                _ACTIVE_MODEL = None
                return
            model_path = models[0]
        print('Loading model from', model_path)
        _MODEL = keras.models.load_model(model_path)
        scaler_path = os.path.join(MODEL_DIR, 'scaler.joblib')
        if os.path.exists(scaler_path):
            _SCALER = joblib.load(scaler_path)
            # Ensure scaler is compatible with the prediction input shape used by the API
            try:
                n_in = getattr(_SCALER, 'n_features_in_', None)
                if n_in is not None and n_in != 4:
                    print(f'Scaler expects {n_in} features; API prediction uses 4. Ignoring scaler.')
                    _SCALER = None
            except Exception:
                _SCALER = None
        else:
            _SCALER = None
        _ACTIVE_MODEL = os.path.basename(model_path)
        # persist active marker
        with open(os.path.join(MODEL_DIR, 'active_model.txt'), 'w') as f:
            f.write(_ACTIVE_MODEL)
        print('Model loaded, active=', _ACTIVE_MODEL)
    except Exception as e:
        print('Failed to load model:', e)
        _MODEL = None
        _SCALER = None
        _ACTIVE_MODEL = None
    # attempt to load KDD model + scaler
    try:
        kdd_path = os.path.join(MODEL_DIR, 'kdd_detector.keras')
        scaler_kdd_path = os.path.join(MODEL_DIR, 'scaler_kdd.joblib')
        global _MODEL_KDD, _SCALER_KDD
        if os.path.exists(kdd_path):
            try:
                _MODEL_KDD = keras.models.load_model(kdd_path)
                if os.path.exists(scaler_kdd_path):
                    _SCALER_KDD = joblib.load(scaler_kdd_path)
                else:
                    _SCALER_KDD = None
                print('KDD model loaded')
            except Exception as e:
                print('Failed to load KDD model:', e)
                _MODEL_KDD = None
                _SCALER_KDD = None
        else:
            _MODEL_KDD = None
            _SCALER_KDD = None
    except Exception:
        _MODEL_KDD = None
        _SCALER_KDD = None
    # attempt to load SQL model + scaler
    try:
        sql_path = os.path.join(MODEL_DIR, 'sql_detector.keras')
        scaler_sql_path = os.path.join(MODEL_DIR, 'scaler_sql.joblib')
        global _MODEL_SQL, _SCALER_SQL
        if os.path.exists(sql_path):
            try:
                _MODEL_SQL = keras.models.load_model(sql_path)
                if os.path.exists(scaler_sql_path):
                    _SCALER_SQL = joblib.load(scaler_sql_path)
                else:
                    _SCALER_SQL = None
                print('SQL model loaded')
            except Exception as e:
                print('Failed to load SQL model:', e)
                _MODEL_SQL = None
                _SCALER_SQL = None
        else:
            _MODEL_SQL = None
            _SCALER_SQL = None
    except Exception:
        _MODEL_SQL = None
        _SCALER_SQL = None
    # attempt to load PPO model (stable-baselines3)
    try:
        from stable_baselines3 import PPO as SB3PPO
        ppo_candidate = os.path.join(MODEL_DIR, 'ppo_network_final')
        ppo_zip = ppo_candidate + '.zip'
        global _PPO_MODEL
        if os.path.exists(ppo_zip):
            try:
                _PPO_MODEL = SB3PPO.load(ppo_candidate)
                print('PPO model loaded from', ppo_zip)
            except Exception as e:
                print('Failed to load PPO model:', e)
                _PPO_MODEL = None
        else:
            _PPO_MODEL = None
    except Exception as e:
        # stable-baselines3 may not be installed in the environment
        print('stable-baselines3 not available or failed to load PPO model:', e)
        _PPO_MODEL = None


@app.on_event('startup')
async def startup_event_model():
    # if previously selected active model exists, load it
    active_marker = os.path.join(MODEL_DIR, 'active_model.txt')
    if os.path.exists(active_marker):
        try:
            with open(active_marker, 'r') as f:
                name = f.read().strip()
            if name:
                load_model(name=name)
                return
        except Exception:
            pass
    load_model()


@app.on_event('startup')
async def startup_event():
    # Create the AgentWorker lazily and handle PermissionError when running as non-root.
    global worker
    try:
        worker = AgentWorker()
    except PermissionError as e:
        print('WARNING: AgentWorker failed to instantiate, FirewallController requires root - running without firewall control:', e)
        worker = None
    app.state.task = asyncio.create_task(queue_consumer())


@app.on_event('shutdown')
async def shutdown_event():
    app.state.task.cancel()


async def queue_consumer():
    while True:
        alert = await queue.get()
        try:
            # call the agent worker sync method in threadpool if available
            if worker is not None:
                await asyncio.get_event_loop().run_in_executor(None, worker.handle_alert, alert)
            else:
                # No worker available in this environment; skip handling alerts but mark as processed
                print('No AgentWorker available; skipping alert handling')
        except Exception as e:
            print('worker error', e)
        finally:
            queue.task_done()


@app.post('/alerts')
async def receive_alert(alert: Alert, background: BackgroundTasks):
    # Enqueue alert for processing by agent worker
    await queue.put({'type': alert.type, 'ip': alert.ip, 'metrics': alert.metrics})
    return {"status": "queued"}


@app.post('/predict')
async def predict(payload: Dict):
    """Predict attack probability from features.
    Expected payload: {"packet_rate":..., "syn_ack_ratio":..., "cpu_load":..., "conn_table_size":...}
    """
    if _MODEL is None:
        raise HTTPException(status_code=503, detail='Model not loaded')
    features = np.array([[payload.get('packet_rate', 0), payload.get('syn_ack_ratio', 0), payload.get('cpu_load', 0), payload.get('conn_table_size', 0)]], dtype=float)
    # Ensure model input shape is compatible with the API's 4-feature vector
    try:
        model_input_shape = _MODEL.input_shape
    except Exception:
        model_input_shape = None
    if model_input_shape is not None:
        # model_input_shape may be like (None, 4) or (None, 38)
        expected = None
        if isinstance(model_input_shape, (list, tuple)):
            # handle Sequential models where input_shape can be tuple
            if isinstance(model_input_shape, tuple):
                expected = model_input_shape[-1]
            elif isinstance(model_input_shape, list) and len(model_input_shape) > 0:
                expected = model_input_shape[0][-1]
        if expected is not None and expected != features.shape[1]:
            raise HTTPException(status_code=400, detail=f'Model expects {expected} features; API provides {features.shape[1]}. Use compatible model or retrain.')
    if _SCALER is not None:
        features = _SCALER.transform(features)
    prob = float(_MODEL.predict(features)[0][0])
    return {"probability": prob}


@app.post('/predict_kdd')
async def predict_kdd(body: Dict):
    """Predict using the KDD-trained model. Expects {'features': [f1,f2,...]} where the feature vector
    matches the numeric KDD features (38 values as used during training).
    """
    if _MODEL_KDD is None:
        raise HTTPException(status_code=503, detail='KDD model not loaded')
    features = body.get('features')
    if features is None:
        raise HTTPException(status_code=400, detail='features list required')
    arr = np.array(features, dtype=float)
    if arr.ndim == 1:
        arr = arr.reshape(1, -1)
    # validate shape
    try:
        expected = _MODEL_KDD.input_shape[-1]
    except Exception:
        expected = None
    if expected is not None and arr.shape[1] != expected:
        raise HTTPException(status_code=400, detail=f'KDD model expects {expected} features; received {arr.shape[1]}')
    if _SCALER_KDD is not None:
        arr = _SCALER_KDD.transform(arr)
    prob = float(_MODEL_KDD.predict(arr)[0][0])
    return {'probability': prob}


@app.post('/predict_sql')
async def predict_sql(body: Dict):
    """Predict SQL-injection probability from a query string: {'query': 'SELECT ...'}"""
    if _MODEL_SQL is None:
        raise HTTPException(status_code=503, detail='SQL model not loaded')
    q = body.get('query')
    if not q:
        raise HTTPException(status_code=400, detail='query required')
    # featurize (same logic as training)
    def featurize_query(qs: str):
        s = str(qs)
        length = len(s)
        non_alnum = sum(1 for ch in s if not ch.isalnum() and not ch.isspace())
        quotes = s.count("'") + s.count('"')
        digits = sum(c.isdigit() for c in s)
        keywords = sum(1 for k in ['select','union','insert','sleep','drop','exec','waitfor'] if k in s.lower())
        toks = [t for t in ''.join(ch if ch.isalnum() else ' ' for ch in s).split()]
        avg_tok_len = 0.0
        if toks:
            avg_tok_len = sum(len(t) for t in toks)/len(toks)
        return np.array([[length, non_alnum, quotes, digits, keywords, avg_tok_len]], dtype=float)

    feat = featurize_query(q)
    if _SCALER_SQL is not None:
        feat = _SCALER_SQL.transform(feat)
    prob = float(_MODEL_SQL.predict(feat)[0][0])
    return {'probability': prob}


@app.post('/act')
async def act(body: Dict):
    """Return an action from the RL policy. Accepts either:
    - {'features':[f1,f2,f3,f4]} OR
    - {'packet_rate':..,'syn_ack_ratio':..,'cpu_load':..,'conn_table_size':..}
    Returns: {'action': int, 'deterministic': bool}
    """
    if _PPO_MODEL is None:
        raise HTTPException(status_code=503, detail='PPO model not loaded')
    # build observation
    if 'features' in body:
        obs = body['features']
    else:
        obs = [body.get('packet_rate', 0), body.get('syn_ack_ratio', 0), body.get('cpu_load', 0), body.get('conn_table_size', 0)]
    import numpy as _np
    arr = _np.array(obs, dtype=float)
    if arr.ndim == 1:
        arr = arr.reshape(1, -1)
    try:
        action, _states = _PPO_MODEL.predict(arr, deterministic=True)
    except Exception:
        # try non-deterministic
        action, _states = _PPO_MODEL.predict(arr, deterministic=False)
        return {'action': int(action[0]) if hasattr(action, '__len__') else int(action), 'deterministic': False}
    return {'action': int(action[0]) if hasattr(action, '__len__') else int(action), 'deterministic': True}


@app.get('/models')
async def list_models():
    files = discover_models()
    out = []
    for f in files:
        info = {'name': os.path.basename(f), 'path': f, 'mtime': datetime.fromtimestamp(os.path.getmtime(f)).isoformat()}
        out.append(info)
    return out


@app.get('/models/active')
async def get_active_model():
    return {"active_model": _ACTIVE_MODEL}


@app.post('/models/select')
async def select_model(body: Dict):
    name = body.get('name')
    if not name:
        raise HTTPException(status_code=400, detail='name required')
    path = os.path.join(MODEL_DIR, name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail='model not found')
    load_model(name=name)
    return {"status": "selected", "name": name}

# Conditionally register the upload endpoint only if multipart support is available
try:
    from fastapi import UploadFile, File

    @app.post('/models/upload')
    async def upload_model(file: UploadFile = File(...)):
        # Accept an uploaded .keras file and save into MODEL_DIR
        if not file.filename.endswith('.keras') and not file.filename.endswith('.h5'):
            raise HTTPException(status_code=400, detail='only .keras or .h5 supported')
        dest = os.path.join(MODEL_DIR, file.filename)
        with open(dest, 'wb') as f:
            content = await file.read()
            f.write(content)
        # Optionally load it immediately
        try:
            load_model(name=file.filename)
        except Exception as e:
            print('upload model load failed:', e)
        return {"status": "uploaded", "name": file.filename}
except Exception:
    @app.post('/models/upload')
    async def upload_model_unavailable():
        raise HTTPException(status_code=501, detail='python-multipart not installed; install with `pip install python-multipart` to enable uploads')


@app.post('/train')
async def train_endpoint(background: BackgroundTasks):
    # Trigger training job in background - run the train script
    def run_train():
        import subprocess, sys, os
        cwd = os.path.join(os.path.dirname(__file__), '..')
        subprocess.run([sys.executable, os.path.join(cwd, 'ml_train', 'train_model.py')], check=True)
        load_model()
    background.add_task(run_train)
    return {"status": "training_started"}


if __name__ == '__main__':
    uvicorn.run('app.main:app', host='0.0.0.0', port=5001, log_level='info')
