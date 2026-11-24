FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml LICENSE README.md ./
COPY innernet2 ./innernet2
RUN python -m pip install --no-cache-dir .
COPY deploy ./deploy
RUN groupadd -g 10001 innernet \
 && useradd -u 10001 -g 10001 --no-create-home innernet \
 && mkdir -p /var/lib/innernet /var/lib/innernet-lab \
 && chown -R 10001:10001 /var/lib/innernet /var/lib/innernet-lab
USER 10001:10001
EXPOSE 9400
CMD ["python", "-m", "deploy.coolify_node"]
