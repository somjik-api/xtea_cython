# Contributing to xtea_cython

Thank you for your interest in contributing!

## Development Setup

```bash
# Clone the repository
git clone https://github.com/somjik-api/xtea_cython.git
cd xtea_cython

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate  # Windows

# Install development dependencies
pip install -e ".[dev]"
pip install cython pytest

# Build the Cython extension
python setup.py build_ext --inplace

# Run tests
pytest tests/ -v
```

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=xtea_cython --cov-report=html

# Run specific test file
pytest tests/test_modes.py -v
```

## Code Style

- Follow PEP 8
- Use `flake8` for linting
- Add tests for new functionality

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`pytest tests/`)
6. Run linter (`flake8`)
7. Submit a pull request

## Security Issues

If you discover a security vulnerability, please email the maintainers directly instead of opening a public issue.
