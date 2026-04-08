.PHONY: up down dev test lint kibana install

up:
	docker compose up -d

down:
	docker compose down

dev:
	uvicorn siem.main:app --reload --host 0.0.0.0 --port 8000

test:
	pytest tests/ -v

lint:
	ruff check siem/ tests/

kibana:
	docker compose --profile debug up -d

install:
	pip install -e ".[dev]"
