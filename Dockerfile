FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY mo_port_scan ./mo_port_scan
RUN pip install --no-cache-dir .
ENTRYPOINT ["mo-port-scan"]
