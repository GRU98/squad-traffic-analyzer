.PHONY: up down restart logs logs-app status rebuild clean venv test lint fmt

up:
	docker compose -f docker/docker-compose.yml up -d --build

down:
	docker compose -f docker/docker-compose.yml down

restart:
	docker compose -f docker/docker-compose.yml restart

logs:
	docker compose -f docker/docker-compose.yml logs -f

logs-app:
	docker compose -f docker/docker-compose.yml logs -f app

status:
	docker compose -f docker/docker-compose.yml ps

rebuild:
	docker compose -f docker/docker-compose.yml down
	docker compose -f docker/docker-compose.yml up -d --build

clean:
	docker compose -f docker/docker-compose.yml down -v

# --- Local development (uses .venv) ---
venv:
	python3 -m venv .venv
	.venv/bin/pip install -r requirements-dev.txt

test:
	.venv/bin/pytest -q

lint:
	.venv/bin/ruff check app tests
	.venv/bin/ruff format --check app tests

fmt:
	.venv/bin/ruff format app tests
	.venv/bin/ruff check --fix app tests
