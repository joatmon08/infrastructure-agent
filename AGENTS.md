# AGENTS.md

This file provides guidance to agents when working with code in this repository.

- The active app surface here is the Python multi-agent pipeline under [`agents/`](agents/): [`orchestrator`](agents/orchestrator), [`module-writer`](agents/module-writer), [`test-writer`](agents/test-writer), [`pr-agent`](agents/pr-agent), plus shared libs [`github-client`](agents/github-client) and [`llm-client`](agents/llm-client).
- Every agent package pins [`requires-python = ">=3.14"`](agents/orchestrator/pyproject.toml:4); use `uv` per package rather than a repo-root virtualenv.
- Verified test command pattern: `uv run --directory agents/<pkg> pytest -q`. Single test file: `uv run --directory agents/<pkg> pytest -q tests/test_agent_executor.py`. Single test case: append `::TestClass::test_name` as supported by [`pytest`](agents/orchestrator/pyproject.toml:15).
- There is no central lint script/config yet; validation in code is package-local tests plus Terraform CLI checks invoked by the agents themselves.
- [`agents/run-local.sh`](agents/run-local.sh) is the only repo-level dev entrypoint: it runs [`uv sync --quiet`](agents/run-local.sh:42) inside each agent directory, starts specialists before the orchestrator, and writes logs to [`agents/logs/`](agents/logs/).
- [`pr-agent`](agents/pr-agent/agent_executor.py:71) is the canonical Terraform gate: `terraform init -backend=false -no-color`, `terraform fmt -check -recursive -no-color`, then `terraform test -no-color` inside the generated module directory.
- [`module-writer`](agents/module-writer/agent_executor.py:263) formats generated `.tf` content with `terraform fmt -`, then validates with `terraform init -backend=false -no-color` and `terraform validate -no-color` in a temp dir before committing.
- Module names are not raw user input: [`_build_module_name()`](agents/module-writer/agent_executor.py:64) normalizes to `terraform-<provider>-<name>` and strips duplicate `terraform-` / provider prefixes.
- Update flow is intentionally partial: [`orchestrator`](agents/orchestrator/agent_executor.py:143) only fetches [`main.tf`](agents/orchestrator/agent_executor.py:143), [`variables.tf`](agents/orchestrator/agent_executor.py:143), and [`outputs.tf`](agents/orchestrator/agent_executor.py:143) from `main` before asking [`module-writer`](agents/module-writer/agent_executor.py:233) to modify them.
- Test generation depends on branch state, not local files: [`test-writer`](agents/test-writer/agent_executor.py:77) reads module files from GitHub, writes exactly [`tests/main_unit_test.tftest.hcl`](agents/test-writer/agent_executor.py:123), and falls back to baked-in `mock_provider` examples if the Terraform MCP server is unavailable.
- Shared GitHub writes are file-by-file, not batched: [`commit_files()`](agents/github-client/github_client.py:48) calls `create_file`/`update_file` once per path, so partial branch updates are possible if a later file write fails.
- Import style in this codebase is simple and consistent: stdlib first, blank line, third-party imports, blank line, local package imports; see [`agents/module-writer/agent_executor.py`](agents/module-writer/agent_executor.py:9).
- Naming conventions discovered in code: helper constants are upper snake case (for example [`_PROVIDER_MAP`](agents/module-writer/agent_executor.py:33)), internal helpers use leading underscores (for example [`_parse_input()`](agents/test-writer/agent_executor.py:29)), and executor classes use `*Executor` suffixes.
- Error handling is message-first for A2A flows: executors usually catch failures and enqueue `error: ...` text back to the caller instead of raising; cancellation is uniformly unsupported via [`raise Exception("cancel not supported")`](agents/orchestrator/agent_executor.py:219).
- Network/security caveat from code: each agent server currently binds with [`uvicorn.run(... host="0.0.0.0")`](agents/orchestrator/__main__.py:63), despite README language implying localhost-only use.

