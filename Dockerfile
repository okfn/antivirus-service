FROM python:3.12-alpine

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py clamd_engine.py ./

RUN adduser -D -H -u 10001 antivirus \
    && mkdir /scans \
    && chown antivirus /scans
ENV TMP_DIR=/scans
ENV PYTHONDONTWRITEBYTECODE=1
VOLUME /scans
USER antivirus

EXPOSE 8000

# One worker: scan state lives in that process. Threads serve long uploads
# without blocking /health or the status checks.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "8", \
     "--access-logfile", "-", "app:create_app()"]
