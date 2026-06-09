#!/bin/bash
set -e

echo "=== Vulnerability Management System ==="
echo "Waiting for PostgreSQL to be ready..."

# Wait for PostgreSQL to be ready
max_retries=30
retries=0
while [ $retries -lt $max_retries ]; do
    if python -c "
import psycopg2
import os
try:
    conn = psycopg2.connect(os.environ.get('DATABASE_URL', ''))
    conn.close()
    print('PostgreSQL is ready!')
    exit(0)
except Exception as e:
    print(f'Waiting... ({e})')
    exit(1)
" 2>/dev/null; then
        break
    fi
    retries=$((retries + 1))
    sleep 2
done

if [ $retries -eq $max_retries ]; then
    echo "ERROR: PostgreSQL not ready after $max_retries attempts"
    exit 1
fi

echo "Initializing database tables..."
python -c "
import sys
sys.path.insert(0, '.')
from db.database import engine, Base
from db.models import Vulnerability, VulnAnalysis, VulnHistory, UploadLog
Base.metadata.create_all(bind=engine)
print('Database tables created successfully!')
"

echo "Starting application..."
exec uvicorn app:app --host 0.0.0.0 --port 8000 --workers 1
