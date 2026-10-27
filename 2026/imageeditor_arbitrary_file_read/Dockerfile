FROM python:3.12-slim

WORKDIR /exploit

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY exploit.py .
COPY find_radeditors.py .

ENTRYPOINT ["python3", "exploit.py"]
