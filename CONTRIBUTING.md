# Contributing to MCP Security Scanner

Thank you for your interest in contributing to MCP Security Scanner! This document provides guidelines and instructions for getting started.

## Code of Conduct

We are committed to providing a welcoming and inclusive environment. By participating in this project, you agree to uphold the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/).

## Ways to Contribute

- **Report Bugs**: Found a false positive or missed vulnerability? [Open an issue](https://github.com/ogulcanaydogan/mcp-security-scanner/issues/new/choose)
- **Suggest Features**: Have an idea for a new detection rule or output format? [Start a discussion](https://github.com/ogulcanaydogan/mcp-security-scanner/discussions)
- **Write Code**: Implement new analyzers, improve existing ones, or fix bugs
- **Improve Documentation**: Help us make the docs clearer and more comprehensive
- **Test**: Run the scanner on real MCP servers and report findings
- **Share**: Tell others about the scanner and how you're using it

## Development Setup

### Prerequisites

- Python 3.11+
- Git
- Bash/Zsh (or equivalent shell)

### Setting Up Your Environment

1. **Fork the repository**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/mcp-security-scanner.git
   cd mcp-security-scanner
   git remote add upstream https://github.com/ogulcanaydogan/mcp-security-scanner.git
   ```

2. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install in development mode**:
   ```bash
   pip install -e .[dev]
   ```

4. **Verify setup**:
   ```bash
   mcp-scan --version
   pytest --version
   ruff --version
   ```

## Development Workflow

### 1. Create a Feature Branch

Always create a new branch for your work:

```bash
git checkout -b feature/my-new-detector
# or for bugs:
git checkout -b fix/false-positive-issue
```

Branch naming convention: `{type}/{description}` where type is `feature`, `fix`, `docs`, or `test`.

### 2. Write Code

Follow these guidelines:

- **Style**: Use `ruff` (enforced by CI)
  ```bash
  ruff check src tests --fix
  black src tests
  ```
  Current CI policy is pragmatic: annotation rules (`ANN*`) and async timeout naming rule (`ASYNC109`) are intentionally disabled in Ruff for now; strict typing is enforced with `mypy src`.

- **Types**: All functions must have type annotations (enforced by mypy)
  ```bash
  mypy src
  ```

- **Docstrings**: All public classes/functions must have docstrings:
  ```python
  def my_function(arg: str) -> int:
      """
      Brief description.

      Longer description if needed.

      Args:
          arg: What this argument does.

      Returns:
          What the function returns.

      Raises:
          ValueError: When this happens.
      """
      pass
  ```

### 3. Write Tests

- Add tests in `tests/` for any new code
- Maintain >80% coverage (checked by CI)
- Test both happy paths and edge cases

```bash
# Run tests locally
pytest
pytest -v  # verbose
pytest --cov=mcp_security_scanner  # with coverage
```
  CI uploads coverage via the Codecov CLI (not a GitHub Action wrapper), and any upload issue is treated as non-blocking. Test output suppresses only the known `BaseSubprocessTransport.__del__` unraisable warning pattern.

### 4. Update Documentation

- Update ROADMAP.md if adding new features
- Add docstrings to all public APIs
- Update README.md if adding new CLI commands or features

### 5. Commit

Write clear, descriptive commit messages:

```bash
git add .
git commit -m "Add static analyzer for dangerous functions

Implements detection of 10 dangerous patterns:
- eval, exec, __import__
- os.system, subprocess.call
- open() and pathlib.Path
- socket and requests
- os.getenv and os.environ
- SQL injection patterns

Also adds 15 unit tests with >95% coverage."
```

### 6. Push and Open a PR

```bash
git push origin feature/my-new-detector
```

Then open a pull request on GitHub. Provide:
- Description of what you changed
- Why you made the change
- Any new dependencies or breaking changes

## Creating New Analyzers

### Step 1: Create the Analyzer Class

Create a new file in `src/mcp_security_scanner/analyzers/{your_analyzer}.py`:

```python
from mcp_security_scanner.analyzers.base import BaseAnalyzer, Finding, Severity
from mcp_security_scanner.discovery import ToolDefinition

class MyCustomAnalyzer(BaseAnalyzer):
    """
    Detects [your vulnerability type].

    Examples:
        analyzer = MyCustomAnalyzer()
        findings = await analyzer.analyze(tools=tool_definitions)
    """

    def __init__(self):
        super().__init__(
            name="my_custom_analyzer",
            description="Detects [your vulnerability]"
        )

    async def analyze(self, **kwargs) -> list[Finding]:
        """
        Analyze tools for [your vulnerability].

        Args:
            tools: List of ToolDefinition objects to analyze.

        Returns:
            List of Finding objects.
        """
        tools = kwargs.get("tools", [])

        for tool in tools:
            # Your detection logic here
            if self._is_vulnerable(tool):
                self.add_finding(
                    severity=Severity.HIGH,
                    category="my_category",
                    title="My finding title",
                    description="Detailed explanation",
                    evidence=tool.description,
                    owasp_id="LLM01",  # or appropriate category
                    remediation="How to fix this",
                    tool_name=tool.name
                )

        return self.get_findings()

    def _is_vulnerable(self, tool: ToolDefinition) -> bool:
        """Check if tool matches your vulnerability pattern."""
        # Your check here
        return False
```

### Step 2: Create Tests

Create `tests/analyzers/test_my_custom_analyzer.py`:

```python
import pytest
from mcp_security_scanner.analyzers.my_custom_analyzer import MyCustomAnalyzer
from mcp_security_scanner.discovery import ToolDefinition
from mcp_security_scanner.analyzers.base import Severity

@pytest.fixture
def analyzer():
    return MyCustomAnalyzer()

@pytest.fixture
def vulnerable_tool():
    return ToolDefinition(
        name="dangerous_tool",
        description="This tool has the vulnerability",
        input_schema={},
    )

@pytest.mark.asyncio
async def test_detects_vulnerability(analyzer, vulnerable_tool):
    findings = await analyzer.analyze(tools=[vulnerable_tool])

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].tool_name == "dangerous_tool"

@pytest.mark.asyncio
async def test_ignores_safe_tools(analyzer):
    safe_tool = ToolDefinition(
        name="safe_tool",
        description="This tool is safe",
        input_schema={},
    )

    findings = await analyzer.analyze(tools=[safe_tool])
    assert len(findings) == 0
```

### Step 3: Integration

Update `src/mcp_security_scanner/cli.py` to use your analyzer:

```python
from mcp_security_scanner.analyzers.my_custom_analyzer import MyCustomAnalyzer

async def scan_tools(tools):
    analyzers = [
        # ... existing analyzers ...
        MyCustomAnalyzer(),
    ]

    for analyzer in analyzers:
        findings.extend(await analyzer.analyze(tools=tools))
```

## Reporting Bugs

When reporting a bug, include:

1. **Reproduction steps**: Exactly how to trigger the bug
2. **Expected behavior**: What should happen
3. **Actual behavior**: What actually happened
4. **Environment**:
   ```
   OS: macOS / Linux / Windows
   Python: 3.11 / 3.12 / 3.13
   Scanner version: x.y.z
   ```
5. **Logs or screenshots**: Helpful error messages or output

## Requesting Features

When suggesting a feature:

1. **Use case**: Why is this feature useful?
2. **Proposed solution**: How should it work?
3. **Alternatives**: Any other approaches you considered?

## Pull Request Process

1. Update `ROADMAP.md` if you're implementing a roadmap item
2. All tests must pass locally (`pytest`)
3. Code must be linted (`ruff check`, `black`)
4. Code must pass type checking (`mypy`)
5. Coverage must remain >80%
6. PR must be approved by a maintainer
7. Squash commits if requested by reviewer

## Recognition

We recognize all contributors! Once your PR is merged, we'll:

- Add you to [CONTRIBUTORS.md](CONTRIBUTORS.md)
- Mention you in release notes
- Credit you in the README

## Questions?

- Check the [FAQ](docs/faq.md)
- Read the [Architecture](docs/architecture.md) docs
- Ask in [Discussions](https://github.com/ogulcanaydogan/mcp-security-scanner/discussions)
- Email: dev@ogulcan.com

Thank you for contributing!
