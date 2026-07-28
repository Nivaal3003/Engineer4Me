FROM python:3.13-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        tesseract-ocr \
        tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .

RUN pip install --upgrade pip

RUN pip install \
    fastapi \
    "uvicorn[standard]" \
    sqlalchemy \
    "psycopg[binary]" \
    alembic \
    pydantic \
    python-dotenv \
    "pillow>=12.3.0" \
    "pytesseract>=0.3.13" \
    "defusedxml>=0.7.1,<1.0.0" \
    "openpyxl>=3.1.5,<4.0.0" \
    "pypdfium2>=5.3.0,<6.0.0" \
    "python-docx>=1.2.0,<2.0.0" \
    "xlrd>=2.0.1,<3.0.0" \
    pytest \
    httpx

COPY . .

ENV PYTHONPATH=/app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
