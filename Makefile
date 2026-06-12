.PHONY: lint type test check

lint:
	ruff check .

type:
	mypy --strict logsentry

test:
	pytest -q

check: lint type test
