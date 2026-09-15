# Contributing to ThreatLens AI

Thank you for your interest in contributing! This project was built as a hackathon submission for the Bob AI Hackathon (D2 — Defense & Aerospace Track).

## Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Follow the setup guide in [docs/setup-guide.md](docs/setup-guide.md)
4. Make your changes
5. Run the verification checks:
   ```bash
   python src/data/generate_alerts.py --seed 42 --output data/synthetic_alerts.json
   python src/run_pipeline.py --input data/synthetic_alerts.json --reset-db
   ```
6. Ensure all 3 verification checks PASS
7. Submit a pull request

## Code Style

- Python 3.11+ with type hints throughout
- Pydantic v2 for all data models
- Docstrings on all public functions and classes
- Keep each pipeline stage independently importable and testable

## Adding a New Source Parser

1. Add a new parser class to `src/pipeline/ingest.py` inheriting from `BaseParser`
2. Register it in `_PARSERS` dict
3. Add a corresponding generator function to `src/data/generate_alerts.py`
4. Update the source type enum in `src/schema.py`

## Security

- **Never commit `.env` or real credentials**
- Use `.env.example` for environment variable documentation
- All synthetic data must be clearly fictional

## License

This project is submitted under the Bob AI Hackathon terms. See hackathon guidelines for usage rights.
