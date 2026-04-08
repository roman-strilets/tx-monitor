---
applyTo: "**"
---

# Project general guidelines
- run ```uvx ruff check``` after making changes to ensure code quality and consistency
- before running python code activate the virtual environment using venv/scripts/activate or use venv/scripts/python to run the code
- don't commit code to git. I will handle that on myself.
- for imports, use absolute imports instead of relative imports. For example, use `from services.analyzer.tasks import document_tasks` instead of `from .tasks import document_tasks`.
- don't use sys.path manipulation to import modules. Instead, ensure that your project structure allows for proper imports without modifying sys.path.
- for testing, use pytest and place your test files in a tests directory. Test files should be named with the pattern test_*.py.
- don't create alembic migration files. Only if the user asks you to. In that case, create the migration file using alembic and include the generated code in your response. Do not write the migration code manually.
- put import statements at the top of the file, after any module comments and docstrings, and before module globals and constants. don't put import statements inside functions or classes.