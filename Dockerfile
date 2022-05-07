FROM python:bullseye

COPY cvereader.py .
COPY requirements.txt .

RUN pip install -r requirements.txt

ENTRYPOINT ["python3", "cvereader.py"]
