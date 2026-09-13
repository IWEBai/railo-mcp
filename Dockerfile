FROM python:3.11-slim

WORKDIR /app

# Install package dependencies
COPY pyproject.toml README.md ./
COPY railo_mcp/ railo_mcp/

RUN pip install --no-cache-dir .

# Run as non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

ENTRYPOINT ["railo-mcp"]
