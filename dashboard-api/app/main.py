from fastapi import FastAPI, HTTPException, Header, Request, WebSocket, WebSocketDisconnect, BackgroundTasks
import socket
import gzip
import threading
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import Optional, List
import os
import json
import requests
from datetime import datetime
import asyncio
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Autonomous AI Firewall - Real-Time Live Ops Dashboard")

ML_ENGINE_BASE = os.getenv('ML_ENGINE_BASE', 'http://127.0.0.1:5001')
ML_PER_PACKET_ENABLED = os.getenv('ML_PER_PACKET_ENABLED', 'true').lower() in ('1', 'true', 'yes')
ML_SQL_THRESHOLD = float(os.getenv('ML_SQL_THRESHOLD', '0.7'))
ML_ENGINE_ALERTS = ML_ENGINE_BASE.rstrip('/') + '/alerts'
API_KEY = os.getenv('API_KEY', 'secret-token')
API_KEYS_JSON = os.getenv('API_KEYS_JSON', '')
API_KEYS = {}
if API_KEYS_JSON:
    try:
        API_KEYS = json.loads(API_KEYS_JSON)
    except Exception:
        logger.warning('Invalid JSON for API_KEYS_JSON. Expecting JSON mapping key->role')
ML_FORWARD_ENABLED = os.getenv('ML_FORWARD_ENABLED', 'true').lower() in ('1', 'true', 'yes')
ALERTS_LOG_FILE = os.path.join(os.path.dirname(__file__), '..', '..', 'logs', 'alerts.jsonl')
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), '..', 'templates')

# Ensure logs directory exists
os.makedirs(os.path.dirname(ALERTS_LOG_FILE), exist_ok=True)
os.makedirs(TEMPLATES_DIR, exist_ok=True)

# UDP sink configuration - optional receiver for agent UDP traffic
ENABLE_UDP_SINK = os.getenv('ENABLE_UDP_SINK', 'false').lower() in ('1', 'true', 'yes')
UDP_BIND_HOST = os.getenv('UDP_BIND_HOST', '0.0.0.0')
UDP_BIND_PORT = int(os.getenv('UDP_BIND_PORT', '9999'))


class Alert(BaseModel):
    """Legacy alert model for backward compatibility"""
    type: str
    ip: str
    metrics: dict = {}


class SaaSAlert(BaseModel):
    """New comprehensive alert model for SaaS Firewall"""
    source_ip: str = Field(..., description="Source IP address of the attack")
    destination_ip: str = Field(..., description="Destination IP address")
    attack_type: str = Field(..., description="Type of attack (e.g., 'SQL Injection', 'DDoS', 'Benign')")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Confidence score (0.0-1.0)")
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    payload_sample: Optional[str] = Field(None, description="Sample of malicious payload (optional)")


# In-memory stores
active_connections: List[WebSocket] = []
action_history = []
test_runs = {}
alerts_history = []
live_stats = {
    "total_packets": 0,
    "threats_blocked": 0,
    "benign_allowed": 0
}


class ConnectionManager:
    """Manage WebSocket connections for broadcasting"""
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"Client connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        logger.info(f"Client disconnected. Total connections: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients"""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Error sending message: {e}")
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for conn in disconnected:
            self.disconnect(conn)


alerts_manager = ConnectionManager()
packet_manager = ConnectionManager()


def get_role_for_key(key: str | None) -> Optional[str]:
    """Return role for a given API key. Returns None if not authorized."""
    if not key:
        return None
    if key == API_KEY:
        return 'admin'
    return API_KEYS.get(key)


def require_role_for_request(key: str | None, roles: List[str]):
    role = get_role_for_key(key)
    if role not in roles:
        raise HTTPException(status_code=401, detail='Invalid API key')


def forward_alert(alert: dict):
    if not ML_FORWARD_ENABLED:
        logger.debug('ML forwarding disabled by configuration')
        return
    try:
        requests.post(ML_ENGINE_ALERTS, json=alert, timeout=2)
    except Exception as e:
        logger.debug(f'Failed to forward alert to ML engine (suppressed): {e}')


@app.get('/')
async def get_dashboard(request: Request):
    """Serve the live ops dashboard. Supports compact view via `?view=compact`."""
    view = request.query_params.get('view', '').lower()
    if view == 'compact':
        index_path = os.path.join(TEMPLATES_DIR, 'index_compact.html')
    else:
        index_path = os.path.join(TEMPLATES_DIR, 'index.html')

    if os.path.exists(index_path):
        with open(index_path, 'r') as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Dashboard not found</h1>")


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """WebSocket endpoint streaming high-priority alerts to dashboard"""
    api_key = websocket.query_params.get('api_key') or websocket.headers.get('x-api-key')
    role = get_role_for_key(api_key)
    if role not in ('admin', 'viewer'):
        await websocket.close(code=1008)
        return
    await alerts_manager.connect(websocket)
    try:
        # Send current stats to new connection
        await websocket.send_json({
            "type": "initial_stats",
            "data": live_stats
        })
        # Keep connection alive
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        alerts_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket alerts error: {e}")
        try:
            alerts_manager.disconnect(websocket)
        except:
            pass


def _start_udp_listener(loop):
    """Start a UDP listener that broadcasts incoming JSON packets to packet_manager."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((UDP_BIND_HOST, UDP_BIND_PORT))
    logger.info(f"UDP sink listening on {UDP_BIND_HOST}:{UDP_BIND_PORT}")
    while True:
        try:
            data, addr = sock.recvfrom(65536)
            if not data:
                continue
            # try parse JSON; if not, try gunzip
            try:
                payload = json.loads(data)
            except Exception:
                try:
                    decoded = gzip.decompress(data)
                    payload = json.loads(decoded)
                except Exception as e:
                    logger.debug(f"Invalid UDP payload from {addr}: {e}")
                    continue

            # If batch list
            if isinstance(payload, list):
                for p in payload:
                    asyncio.run_coroutine_threadsafe(packet_manager.broadcast({'type':'packet','data':p}), loop)
            else:
                asyncio.run_coroutine_threadsafe(packet_manager.broadcast({'type':'packet','data':payload}), loop)
        except Exception as e:
            logger.debug(f"UDP sink error: {e}")


@app.on_event('startup')
async def start_background_services():
    # Start UDP sink
    if ENABLE_UDP_SINK:
        loop = asyncio.get_event_loop()
        t = threading.Thread(target=_start_udp_listener, args=(loop,), daemon=True)
        t.start()
        logger.info('Started UDP sink thread')


@app.on_event('shutdown')
async def stop_background_services():
    # No explicit stop mechanism for UDP thread (daemon). In future we can signal to stop.
    logger.info('Shutting down background services')


@app.websocket("/ws/packet-stream")
async def websocket_packets(websocket: WebSocket):
    """WebSocket endpoint streaming all packet metadata to Traffic Monitor"""
    api_key = websocket.query_params.get('api_key') or websocket.headers.get('x-api-key')
    role = get_role_for_key(api_key)
    if role not in ('admin', 'viewer'):
        await websocket.close(code=1008)
        return
    await packet_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        packet_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket packet-stream error: {e}")
        try:
            packet_manager.disconnect(websocket)
        except:
            pass


# Backwards compatibility endpoint
@app.websocket("/ws/live-feed")
async def websocket_live_alias(websocket: WebSocket):
    api_key = websocket.query_params.get('api_key') or websocket.headers.get('x-api-key')
    role = get_role_for_key(api_key)
    if role not in ('admin', 'viewer'):
        await websocket.close(code=1008)
        return
    await alerts_manager.connect(websocket)
    try:
        await websocket.send_json({"type": "initial_stats", "data": live_stats})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        alerts_manager.disconnect(websocket)


@app.websocket("/ws/traffic")
async def websocket_traffic(websocket: WebSocket):
    """Alias WebSocket endpoint for live traffic / packet stream."""
    api_key = websocket.query_params.get('api_key') or websocket.headers.get('x-api-key')
    role = get_role_for_key(api_key)
    if role not in ('admin', 'viewer'):
        await websocket.close(code=1008)
        return
    await packet_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        packet_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket traffic error: {e}")
        try:
            packet_manager.disconnect(websocket)
        except:
            pass


@app.post('/log-packet')
async def log_packet(request: Request, x_api_key: str | None = Header(None)):
    """Log a single packet from an agent in near real-time.
    Agents should POST the JSON payload: {timestamp, source_ip, destination_ip, protocol, length, verdict, [payload_sample]}
    This will be broadcast to live websocket clients under 'packet' type.
    """
    require_role_for_request(x_api_key, ['agent', 'admin'])
    try:
        body = await request.json()
        # Minimal validation
        if 'timestamp' not in body or 'source_ip' not in body or 'destination_ip' not in body:
            raise ValueError('Missing required fields')
        # Broadcast immediately to traffic websocket clients
        await packet_manager.broadcast({'type': 'packet', 'data': body})
        # Update stats
        live_stats['total_packets'] = live_stats.get('total_packets', 0) + 1
        return {'status': 'accepted'}
    except Exception as e:
        logger.error(f'Failed to log packet: {e}')
        raise HTTPException(status_code=400, detail=str(e))


@app.get('/ml/status')
async def ml_status():
    """Return basic ML engine status"""
    try:
        target = ML_ENGINE_BASE.rstrip('/') + '/models/active'
        r = requests.get(target, timeout=2)
        j = r.json()
        # Normalize to a simple status object so the frontend can easily read it
        if isinstance(j, dict) and 'active_model' in j:
            return {'status': 'ok', 'active_model': j.get('active_model')}
        # Fallback: if the endpoint returned something else, still mark 'ok'
        return {'status': 'ok', 'detail': j}
    except Exception as e:
        return {"status": "unreachable", "error": str(e)}


@app.post('/ml/act')
async def ml_act(body: dict):
    """Proxy an /act request to the ML engine"""
    try:
        target = ML_ENGINE_BASE.rstrip('/') + '/act'
        r = requests.post(target, json=body, timeout=3)
        return r.json()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f'ML engine unreachable: {e}')


@app.post('/traffic')
async def receive_traffic(request: Request, x_api_key: str | None = Header(None)):
    """Receive raw packet metadata from agents and broadcast to packet stream"""
    require_role_for_request(x_api_key, ['agent', 'admin'])

    def _predict_sql_local(payload_sample):
        try:
            target = ML_ENGINE_BASE.rstrip('/') + '/predict_sql'
            r = requests.post(target, json={'query': payload_sample}, timeout=2)
            if r.status_code == 200 and 'probability' in r.json():
                return float(r.json()['probability'])
        except Exception:
            return None
        return None

    try:
        body = await request.json()
        # minimal validation
        expected_keys = {'timestamp', 'source_ip', 'destination_ip', 'protocol', 'length', 'verdict'}
        if not expected_keys.issubset(set(body.keys())):
            # Accept partial but still broadcast
            logger.debug('Traffic payload missing some fields; broadcasting what is present')

        # Enrich with ML analysis (if enabled) — run in threadpool to avoid blocking event loop
        if ML_PER_PACKET_ENABLED and 'payload_sample' in body and body.get('payload_sample'):
            def _predict_sql(payload_sample):
                try:
                    target = ML_ENGINE_BASE.rstrip('/') + '/predict_sql'
                    r = requests.post(target, json={'query': payload_sample}, timeout=2)
                    if r.status_code == 200 and 'probability' in r.json():
                        return float(r.json()['probability'])
                except Exception:
                    return None
                return None
            try:
                loop = asyncio.get_running_loop()
                prob = await loop.run_in_executor(None, _predict_sql, body['payload_sample'])
                if prob is not None:
                    body['ml_sql_prob'] = prob
                    if prob >= ML_SQL_THRESHOLD:
                        # auto-generate an alert for high confidence SQL-injection
                        alert_obj = SaaSAlert(
                            source_ip=body.get('source_ip', ''),
                            destination_ip=body.get('destination_ip', ''),
                            attack_type='SQL Injection',
                            confidence_score=prob,
                            timestamp=datetime.utcnow().isoformat() + 'Z',
                            payload_sample=body.get('payload_sample')[:200]
                        )
                        # Broadcast as an alert (and send to ML engine) - best-effort
                        await alerts_manager.broadcast({
                            'type': 'alert',
                            'data': alert_obj.dict(),
                            'stats': live_stats
                        })
            except Exception as e:
                logger.debug(f'Per-packet ML analysis failed: {e}')
        elif ML_PER_PACKET_ENABLED and ('payload' in body and body.get('payload')):
            # Some agents may send payload (field 'payload'). Use it to infer SQL probability.
            try:
                loop = asyncio.get_running_loop()
                prob = await loop.run_in_executor(None, _predict_sql_local, body.get('payload'))
                if prob is not None:
                    body['ml_sql_prob'] = prob
                    if prob >= ML_SQL_THRESHOLD:
                        alert_obj = SaaSAlert(
                            source_ip=body.get('source_ip', ''),
                            destination_ip=body.get('destination_ip', ''),
                            attack_type='SQL Injection',
                            confidence_score=prob,
                            timestamp=datetime.utcnow().isoformat() + 'Z',
                            payload_sample=str(body.get('payload'))[:200]
                        )
                        await alerts_manager.broadcast({
                            'type': 'alert',
                            'data': alert_obj.dict(),
                            'stats': live_stats
                        })
            except Exception as e:
                logger.debug(f'Per-packet ML analysis failed: {e}')

        # Update stats and Broadcast to packet stream clients
        live_stats['total_packets'] = live_stats.get('total_packets', 0) + 1
        await packet_manager.broadcast({
            'type': 'packet',
            'data': body
        })

        return { 'status': 'accepted' }
    except Exception as e:
        logger.error(f"Error processing traffic payload: {e}")
        raise HTTPException(status_code=400, detail=f'Invalid traffic format: {str(e)}')


@app.post('/alerts')
async def receive_alert(request: Request, x_api_key: str | None = Header(None)):
    """
    Receive alerts from the SaaS Firewall enforcer.
    Broadcasts them to WebSocket clients in real-time.
    """
    require_role_for_request(x_api_key, ['agent', 'admin'])
    
    try:
        body = await request.json()
        
        if 'source_ip' in body and 'destination_ip' in body and 'attack_type' in body:
            alert = SaaSAlert(**body)
            
            # Log to file (JSONL format)
            try:
                with open(ALERTS_LOG_FILE, 'a') as f:
                    f.write(json.dumps({
                        'timestamp': datetime.utcnow().isoformat() + 'Z',
                        'alert': alert.dict()
                    }) + '\n')
            except Exception as e:
                logger.error(f'Failed to log alert to file: {e}')
            
            # Store in memory
            alerts_history.append(alert.dict())
            if len(alerts_history) > 1000:
                alerts_history.pop(0)
            
            # Update stats
            live_stats["total_packets"] += 1
            if alert.attack_type == "Benign":
                live_stats["benign_allowed"] += 1
            else:
                live_stats["threats_blocked"] += 1
            
            logger.info(f"Alert received: {alert.attack_type} from {alert.source_ip}")
            
            # Broadcast to Alerts WebSocket clients
            broadcast_data = {
                "type": "alert",
                "data": alert.dict(),
                "stats": live_stats
            }
            await alerts_manager.broadcast(broadcast_data)
            
            # Forward to ML Engine if enabled (fire-and-forget)
            if ML_FORWARD_ENABLED:
                try:
                    # use background task to avoid blocking
                    BackgroundTasks().add_task(forward_alert, alert.dict())
                except Exception:
                    logger.debug('Failed to schedule ML forward task')
            
            return {
                "status": "accepted",
                "alert_type": "saas",
                "source_ip": alert.source_ip,
                "attack_type": alert.attack_type
            }
        else:
            legacy_alert = Alert(**body)
            logger.info(f"Received legacy alert: {legacy_alert}")
            return {"status": "accepted", "alert_type": "legacy"}
    
    except Exception as e:
        logger.error(f"Error processing alert: {e}")
        raise HTTPException(status_code=400, detail=f'Invalid alert format: {str(e)}')


@app.post('/traffic/batch')
async def receive_traffic_batch(request: Request, x_api_key: str | None = Header(None)):
    """Receive compressed (gzip) batched traffic payloads (JSON array) or plain JSON array."""
    require_role_for_request(x_api_key, ['agent', 'admin'])
    try:
        raw = await request.body()
        if not raw:
            raise ValueError('Empty body')
        # Try loading as JSON; if not, attempt gzip decompression
        try:
            payload = json.loads(raw)
        except Exception:
            try:
                decoded = gzip.decompress(raw)
                payload = json.loads(decoded)
            except Exception as e:
                logger.error(f'Failed to decode batch payload: {e}')
                raise HTTPException(status_code=400, detail=f'Invalid batch payload: {e}')

        if not isinstance(payload, list):
            raise HTTPException(status_code=400, detail='Batch payload must be a JSON array')

        for p in payload:
            try:
                if ML_PER_PACKET_ENABLED and p.get('payload_sample'):
                    # run prediction in threadpool
                    def _predict_sql(payload_sample):
                        try:
                            target = ML_ENGINE_BASE.rstrip('/') + '/predict_sql'
                            r = requests.post(target, json={'query': payload_sample}, timeout=2)
                            if r.status_code == 200 and 'probability' in r.json():
                                return float(r.json()['probability'])
                        except Exception:
                            return None
                        return None
                    try:
                        loop = asyncio.get_running_loop()
                        prob = await loop.run_in_executor(None, _predict_sql, p.get('payload_sample'))
                        if prob is not None:
                            p['ml_sql_prob'] = prob
                            if prob >= ML_SQL_THRESHOLD:
                                alert_obj = SaaSAlert(
                                    source_ip=p.get('source_ip', ''),
                                    destination_ip=p.get('destination_ip', ''),
                                    attack_type='SQL Injection',
                                    confidence_score=prob,
                                    timestamp=datetime.utcnow().isoformat() + 'Z',
                                    payload_sample=p.get('payload_sample')[:200]
                                )
                                await alerts_manager.broadcast({'type': 'alert', 'data': alert_obj.dict(), 'stats': live_stats})
                    except Exception:
                        pass
                elif ML_PER_PACKET_ENABLED and p.get('payload'):
                    # Some agents may send 'payload' instead of 'payload_sample' in batches
                    def _predict_sql_local_batch(payload_sample):
                        try:
                            target = ML_ENGINE_BASE.rstrip('/') + '/predict_sql'
                            r = requests.post(target, json={'query': payload_sample}, timeout=2)
                            if r.status_code == 200 and 'probability' in r.json():
                                return float(r.json()['probability'])
                        except Exception:
                            return None
                        return None
                    try:
                        loop = asyncio.get_running_loop()
                        prob = await loop.run_in_executor(None, _predict_sql_local_batch, p.get('payload'))
                        if prob is not None:
                            p['ml_sql_prob'] = prob
                            if prob >= ML_SQL_THRESHOLD:
                                alert_obj = SaaSAlert(
                                    source_ip=p.get('source_ip', ''),
                                    destination_ip=p.get('destination_ip', ''),
                                    attack_type='SQL Injection',
                                    confidence_score=prob,
                                    timestamp=datetime.utcnow().isoformat() + 'Z',
                                    payload_sample=str(p.get('payload'))[:200]
                                )
                                await alerts_manager.broadcast({'type': 'alert', 'data': alert_obj.dict(), 'stats': live_stats})
                    except Exception:
                        pass
                # Update stats for each packet
                live_stats['total_packets'] = live_stats.get('total_packets', 0) + 1
                await packet_manager.broadcast({'type': 'packet', 'data': p})
            except Exception:
                # swallow per-packet errors
                continue

        return {'status': 'accepted', 'count': len(payload)}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f'Error processing traffic batch: {e}')
        raise HTTPException(status_code=400, detail=f'Invalid traffic batch: {str(e)}')


@app.post('/action/{action}')
async def take_action(action: int, ip: str, request: Request):
    """Expose action API for enforcement"""
    x_api_key = request.headers.get('x-api-key')
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail='Invalid API key')
    
    try:
        action_history.append({
            'ts': datetime.utcnow().isoformat() + 'Z',
            'action': int(action),
            'ip': ip
        })
        if len(action_history) > 500:
            del action_history[0:len(action_history)-500]
        
        # Broadcast action to dashboard
        await alerts_manager.broadcast({
            "type": "action",
            "data": {"action": action, "ip": ip, "timestamp": datetime.utcnow().isoformat()}
        })
        
        return {"status": "action_recorded", "action": action, "ip": ip}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get('/alerts')
async def get_alerts(limit: int = 100):
    """Retrieve stored alerts"""
    return alerts_history[-limit:]


@app.get('/alerts/stats')
async def get_stats():
    """Return attack statistics"""
    stats = {
        "total": len(alerts_history),
        "by_attack_type": {},
        "avg_confidence": 0.0
    }
    
    if alerts_history:
        total_confidence = 0
        for alert in alerts_history:
            attack_type = alert.get('attack_type', 'Unknown')
            stats['by_attack_type'][attack_type] = stats['by_attack_type'].get(attack_type, 0) + 1
            total_confidence += alert.get('confidence_score', 0)
        stats['avg_confidence'] = total_confidence / len(alerts_history)
    
    return stats


@app.get('/live-stats')
async def get_live_stats():
    """Return live operation statistics"""
    return live_stats


@app.post('/clear-alerts')
async def clear_alerts(request: Request):
    """Clear all alerts"""
    x_api_key = request.headers.get('x-api-key')
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail='Invalid API key')
    
    global alerts_history, live_stats
    alerts_history = []
    live_stats = {
        "total_packets": 0,
        "threats_blocked": 0,
        "benign_allowed": 0
    }
    
    await alerts_manager.broadcast({
        "type": "clear",
        "message": "Alerts cleared"
    })
    
    return {"status": "cleared"}


# Mount static files if they exist
static_dir = os.path.join(os.path.dirname(__file__), '..', 'static')
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


if __name__ == "__main__":
    import uvicorn
    # TLS config (optional). Provide SSL_CERTFILE and SSL_KEYFILE env vars to enable TLS.
    ssl_certfile = os.getenv('SSL_CERTFILE') or os.getenv('HTTPS_CERTFILE')
    ssl_keyfile = os.getenv('SSL_KEYFILE') or os.getenv('HTTPS_KEYFILE')
    if ssl_certfile and ssl_keyfile:
        logger.info('Starting with HTTPS/TLS')
        uvicorn.run(app, host="0.0.0.0", port=8000, ssl_certfile=ssl_certfile, ssl_keyfile=ssl_keyfile)
    else:
        uvicorn.run(app, host="0.0.0.0", port=8000)
