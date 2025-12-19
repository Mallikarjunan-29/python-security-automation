################################
# BUILDER
################################
FROM python:3.11-slim AS builder
WORKDIR /app
COPY requirements.txt /app/
#RUN pip install --user --no-cache-dir -r requirements.txt
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt

################################
# RUNTIME
################################
FROM python:3.11-slim
WORKDIR /app

#COPY --from=builder /root/.local/lib/python3.11/site-packages /root/.local/lib/python3.11/site-packages
#COPY --from=builder /root/.local/bin /root/.local/bin
#COPY --from=builder /root/.local /root/.local
COPY --from=builder /install /usr/local

COPY ai_projects /app/ai_projects/
COPY src/ /app/src/
COPY test/unit_tests/ /app/unit_tests/
COPY test/flask_test.py /app/test/
COPY data/security_docs/ /app/data/security_docs/
COPY data/playbooks /app/data/playbooks/


ENV PATH=/usr/local/bin:$PATH

EXPOSE 5000

#CMD [ "python","test/flask_test.py" ]
CMD ["gunicorn", "-w","4","-b","0.0.0.0:5000","--access-logfile","-","--error-log","-","test.flask_test:app"]