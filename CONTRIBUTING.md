# Contributing

Thanks for helping improve AegisNexus. Everything below runs locally; there is no hosted CI, so `make check` is the gate.

## Setup

```bash
./run.sh setup   # .venv, Python deps, npm deps, frontend build
make dev         # ruff, mypy, pytest-cov, pre-commit hooks
```

## Before you open a pull request

```bash
make check       # ruff + eslint, mypy + tsc, pytest + vitest, production frontend build
```

All of it must pass. New behaviour needs tests: services can be tested directly, and endpoints through `fastapi.testclient.TestClient(app)`. The test suite uses throw-away SQLite files built with the real migrations and never calls paid or external services. Mock them.

## Conventions

**Backend**
- Read configuration only through `app.config.get_settings()`. If you add a setting, also document it in `.env.example` (a test enforces this).
- Keep routers thin. Business logic belongs in `modules/<name>/service.py`, and request/response models in `schemas.py`. Services raise `app.errors.AppError` subclasses, never `HTTPException`.
- Bound every list endpoint (`Query(ge=1, le=...)`) and give it a `response_model` when the shape is stable.
- Use module loggers (`logging.getLogger(__name__)`), never `print`. Never log secrets, tokens, query strings or user-submitted content.
- Schema changes need a migration: `alembic revision --autogenerate -m "describe change"`, then review the generated file.
- Handlers that make blocking network calls are plain `def`, not `async def`.

**Frontend**
- TypeScript strict mode. API response types live in `src/lib/types.ts` and mirror the backend schemas.
- Use `errorMessage()` / `ApiError` from `src/lib/api.ts` to show server errors.

**Commits**
- Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`), one logical change per commit.

## Adding a security module

1. Create `modules/<name>/` with `router.py`, `service.py` and `schemas.py`.
2. Mount the router in `ROUTERS` in `app/main.py` under `/api/v2/<name>`.
3. Background work goes in `modules/<name>/celery_tasks.py`. Register it in `include=` in `app/celery_app.py` and add a beat entry if it is periodic.
4. Publish cross-module events through `modules.shared.events.publish(..., durable=True)` (transactional outbox).
5. Add tests and a row to the module table in `README.md`.
