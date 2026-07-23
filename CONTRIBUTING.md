# Contributing to VEILUX-NG

## Getting Started
```powershell
git clone https://github.com/yourusername/veilux-ng.git
cd veilux-ng
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
```

## Adding a New Feature
1. Create `veilux_ng/features/your_feature.py` inheriting from `BaseFeature`
2. Register it in `veilux_ng/core/compliance.py` with its NDPA legal basis
3. Add it to the dispatch table in `veilux_ng/core/engine.py`
4. Export it from `veilux_ng/features/__init__.py`
5. Write tests in `tests/unit/test_features/test_your_feature.py`
6. Document it in `docs/user_guide/features/your_feature.md`

## Code Standards
- Follow PEP 8
- Add type hints to all function signatures
- Write docstrings for all public methods
- All features must use **public data only** (NDPA 2023 Section 31)
- No API keys hardcoded — use `.env` via `config/settings.py`

## Running Tests
```powershell
python -m pytest tests/ -v
python -m pytest tests/unit/ -v          # unit only
python -m pytest tests/integration/ -v  # integration only
```

## Pull Request Checklist
- [ ] Tests pass
- [ ] Type hints added
- [ ] Docstrings updated
- [ ] NDPA compliance verified
- [ ] No hardcoded secrets
