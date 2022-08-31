FROM python:3.10-alpine3.16

WORKDIR /src

COPY requirements.txt /src/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

ENV EXPORTER_LOG_LEVEL="INFO"

COPY exporter.py /src/exporter.py

CMD ["python", "/src/exporter.py"]