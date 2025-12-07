FROM python:3.11-slim
WORKDIR /opt/ml
COPY ./rl_agent ./rl_agent
COPY ./app ./app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","5001"]
