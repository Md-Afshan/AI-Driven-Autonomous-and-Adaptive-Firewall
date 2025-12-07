from fastapi import FastAPI, HTTPException, Header, Request, BackgroundTasks
from pydantic import BaseModel
import os
import requests
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="Autonomous AI Firewall API")

ML_ENGINE_BASE = os.getenv('ML_ENGINE_BASE', 'http://127.0.0.1:5001')
ML_ENGINE_ALERTS = ML_ENGINE_BASE.rstrip('/') + '/alerts'
API_KEY = os.getenv('API_KEY', 'secret-token')

class Alert(BaseModel):
    type: str
    ip: str
    metrics: dict = {}


# In-memory stores for UI visibility (ephemeral)
action_history = []  # list of dicts {ts, action, ip}
test_runs = {}  # job_id -> result dict


def forward_alert(alert: dict):
    try:
        requests.post(ML_ENGINE_ALERTS, json=alert, timeout=2)
    except Exception as e:
        print('Failed to forward alert to ML engine', e)


@app.get('/ml/status')
async def ml_status():
    """Return basic ML engine status (active model) by proxying to ML /models/active."""
    try:
        target = ML_ENGINE_BASE.rstrip('/') + '/models/active'
        r = requests.get(target, timeout=2)
        return r.json()
    except Exception as e:
        return {"status": "unreachable", "error": str(e)}


@app.post('/ml/act')
async def ml_act(body: dict):
    """Proxy an /act request to the ML engine and return its response."""
    try:
        target = ML_ENGINE_BASE.rstrip('/') + '/act'
        r = requests.post(target, json=body, timeout=3)
        return r.json()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f'ML engine unreachable: {e}')

@app.post('/alerts')
async def receive_alert(alert: Alert, x_api_key: str | None = Header(None)):
    # Basic API key check (stub) for SaaS operator auth
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail='Invalid API key')
    print(f"Received alert: {alert}")
    # forward to ML Engine
    forward_alert(alert.dict())
    return {"status":"accepted"}

@app.post('/action/{action}')
async def take_action(action: int, ip: str, request: Request):
    # Expose action API for operator or ML engine to call enforcement
    # action: 0 nothing,1 rate-limit,2 enable-syncookies,3 hard-block
    x_api_key = request.headers.get('x-api-key')
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail='Invalid API key')
    # record action in history for UI
    try:
        import datetime
        action_history.append({'ts': datetime.datetime.utcnow().isoformat()+'Z', 'action': int(action), 'ip': ip})
        # keep history bounded
        if len(action_history) > 500:
            del action_history[0:len(action_history)-500]
    except Exception:
        pass
    return {"status":"ok","action":action,"ip":ip}


@app.get('/actions')
async def get_actions(limit: int = 100):
    """Return recent actions reported to the dashboard."""
    return list(reversed(action_history[-limit:]))


@app.get('/logs')
async def get_logs(filename: str = 'ml-engine.log', lines: int = 200):
    """Return the last `lines` lines from a log file under ../logs.
    Note: for local dev only."""
    base = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'logs'))
    path = os.path.abspath(os.path.join(base, filename))
    if not path.startswith(base) or not os.path.exists(path):
        raise HTTPException(status_code=404, detail='log not found')
    # read last lines efficiently
    with open(path, 'rb') as f:
        try:
            f.seek(0, os.SEEK_END)
            end = f.tell()
            size = 8192
            data = b''
            while end > 0 and data.count(b'\n') <= lines:
                read_size = min(size, end)
                f.seek(end - read_size)
                data = f.read(read_size) + data
                end -= read_size
            text = data.decode(errors='replace')
            last = '\n'.join(text.splitlines()[-lines:])
            return { 'file': filename, 'lines': last }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


@app.post('/run/test')
async def run_test(background: BackgroundTasks):
    """Start an automated test run which sends a set of alerts and queries the ML engine.
    Results are stored in-memory and can be retrieved with GET /run/test/{job_id}.
    """
    import uuid
    job_id = str(uuid.uuid4())
    test_runs[job_id] = {'status':'running', 'results': []}

    def _run_job(jid):
        try:
            # send a few alerts and call ML endpoints to collect responses
            samples = []
            for i in range(5):
                samples.append({'type':'normal','ip':f'10.0.0.{100+i}','metrics':{'packet_rate':50,'syn_count':2,'cpu':0.2}})
            for i in range(5):
                samples.append({'type':'syn_flood','ip':f'10.0.1.{200+i}','metrics':{'packet_rate':20000,'syn_count':800,'cpu':0.95}})
            for s in samples:
                # forward to ML via dashboard forward_alert
                forward_alert(s)
                # query act and predict for visibility
                try:
                    a = requests.post(ML_ENGINE_BASE.rstrip('/') + '/act', json={ 'packet_rate': s['metrics']['packet_rate'], 'syn_ack_ratio': s['metrics'].get('syn_count',0), 'cpu_load': s['metrics']['cpu'], 'conn_table_size': s['metrics'].get('conn_table_size',0)}, timeout=3)
                    p = requests.post(ML_ENGINE_BASE.rstrip('/') + '/predict', json={ 'packet_rate': s['metrics']['packet_rate'], 'syn_ack_ratio': s['metrics'].get('syn_count',0), 'cpu_load': s['metrics']['cpu'], 'conn_table_size': s['metrics'].get('conn_table_size',0)}, timeout=3)
                    test_runs[jid]['results'].append({'sample':s, 'act': a.json() if a.ok else {'error': 'act failed'}, 'pred': p.json() if p.ok else {'error':'predict failed'}})
                except Exception as e:
                    test_runs[jid]['results'].append({'sample':s, 'error': str(e)})
            test_runs[jid]['status'] = 'completed'
        except Exception as e:
            test_runs[jid]['status'] = 'failed'
            test_runs[jid]['error'] = str(e)

    background.add_task(_run_job, job_id)
    return {'job_id': job_id}


@app.get('/run/test/{job_id}')
async def get_test(job_id: str):
    if job_id not in test_runs:
        raise HTTPException(status_code=404, detail='job not found')
    return test_runs[job_id]


# Serve a minimal static UI so a user can send alerts from a browser
STATIC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'static'))
if os.path.isdir(STATIC_DIR):
    app.mount('/static', StaticFiles(directory=STATIC_DIR), name='static')


@app.get('/')
async def index():
    idx = os.path.join(STATIC_DIR, 'index.html')
    if os.path.exists(idx):
        return FileResponse(idx, media_type='text/html')
    return {"status": "dashboard running"}
