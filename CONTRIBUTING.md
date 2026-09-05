# Contributing to ReconKit

First off, thank you for considering contributing to ReconKit!

## Getting Started

1. **Find an Issue:** Look for issues tagged `good first issue` or `help wanted` in the GitHub issue tracker.
2. **Discuss Before Building:** If you plan to add a major feature, please open an issue to discuss the design with the maintainers before writing code. This saves everyone time!

## Local Development Setup

We use standard Python libraries.

1. Create a virtual environment: `python -m venv venv`
2. Activate it: `source venv/bin/activate` (or `venv\Scripts\activate` on Windows)
3. Install development dependencies: `pip install pytest ruff`

## Pull Request Process

1. **Fork the Repo:** Create a fork and clone it locally.
2. **Branch Naming:** Create a branch for your feature or bug fix.
3. **Write Code & Tests:**
   - Ensure your code follows the existing style.
   - Run the linting tools before committing: `ruff check .`
   - Run tests before committing: `pytest`
4. **Submit a PR:**
   - Link any relevant issues.
   - Wait for CI checks (GitHub Actions) to pass.
5. **Code Review:** A maintainer will review your code.

## Coding Standards

### Backend (Python)
- We only use standard libraries for runtime dependencies.
- Format code using `ruff`.

Thank you for contributing!
