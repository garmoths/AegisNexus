# Developer shortcuts. The app itself starts with ./run.sh.
VENV   := .venv/bin
PYTHON := $(VENV)/python

.PHONY: help setup dev run stop status test cov lint format typecheck check frontend migrate create-admin

help:            ## List targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

setup:           ## Create .venv, install deps, build the frontend
	./run.sh setup

dev: setup       ## Also install dev tools and git hooks
	$(PYTHON) -m pip install -q -r requirements-dev.txt
	$(VENV)/pre-commit install

run:             ## Start API, Redis, Celery worker and beat
	./run.sh

stop:            ## Stop all local services
	./run.sh stop

status:          ## Show local service status
	./run.sh status

test:            ## Run the backend test suite
	$(PYTHON) -m pytest -q

cov:             ## Run tests with a coverage report
	$(PYTHON) -m pytest -q --cov --cov-report=term

lint:            ## Ruff lint (backend) and ESLint (frontend)
	$(VENV)/ruff check .
	cd frontend-react && npm run lint

format:          ## Apply ruff autofixes
	$(VENV)/ruff check --fix .

typecheck:       ## mypy (backend) and tsc (frontend)
	$(PYTHON) -m mypy

frontend:        ## Production build of the React app
	cd frontend-react && npm run build

check: lint typecheck test frontend  ## Everything a PR must pass

migrate:         ## Apply database migrations
	$(VENV)/alembic upgrade head

create-admin:    ## Create an admin user and print its API key
	$(PYTHON) -m app.cli create-admin
