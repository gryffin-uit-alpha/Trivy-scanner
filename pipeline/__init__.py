"""Pipeline orchestration. Deliberately outside the ``trivy_report`` package.

Everything here is the *pipeline's* job under constitution Principle I: rendering
GitOps overlays, discovering image references, producing the manifest that
attributes each Trivy result to a repository, and driving Trivy itself. None of it
is importable from ``src/trivy_report`` and none of it ever will be — that
separation is what the import audit in
``tests/integration/test_no_runtime_dependencies.py`` protects.

These modules are packaged only so the test suite can import them. They are not
part of the distribution: ``pyproject.toml`` builds from ``src/`` only.
"""
