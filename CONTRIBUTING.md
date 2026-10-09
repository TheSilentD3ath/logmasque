# Contributing to LogMasque

Thank you for helping. LogMasque handles sensitive data, so a few rules matter more here than in most projects.

## Ground rules

- **Synthetic data only.** Never put real logs, mail threads, names, addresses, phone numbers, customer domains or IP addresses into code, tests, issues or pull requests.
  - IP addresses come from the documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and `2001:db8::/32`.
  - Domains end in `.example`, `.invalid` or `.test`.
  - Names are obviously invented.
- **Patterns, not names.** Detection rules must work from patterns and context. A rule that only works because it lists a particular real name both leaks that name and fails for everyone else.
- **Standard library only.** LogMasque must keep running on locked-down machines from a single file. Adding a dependency needs a strong reason and a discussion in an issue first.
- **Compatibility.** The mapping-store container, the `.anonstore` format, the DPAPI entropy values and the placeholder shapes are persistent formats. Changing any of them strands existing stores and is not accepted without a migration path and tests.

## Development setup

```bash
git clone <your fork>
cd logmasque
python -m logmasque --help
python -m unittest discover -s tests
```

No installation is required. To try the console command, run `python -m pip install -e .` in a virtual environment.

## Tests

Every change needs tests. Run the whole suite before you open a pull request:

```bash
python -m unittest discover -s tests
```

`tests/test_no_real_data.py` compares the repository with the values your local mapping store has learned, and optionally with a private list. It reports file and line, never the value:

```bash
LOGMASQUE_PRIVATE_VALUES=/path/outside/the/repo/values.txt python -m unittest discover -s tests -p "test_no_real_data.py"
```

The list holds one value per line. Keep it outside the repository.

## Single-file build

The package in `logmasque/` is the source of truth. `LogMasque.py` is generated:

```bash
python scripts/build_single_file.py
```

Do not edit or commit the generated file.

## Pull requests

- Keep each pull request focused on one change and describe what it changes and why.
- Mention any effect on persistent formats or on detection behaviour.
- Update `README.md` and `CHANGELOG.md` when behaviour visible to users changes.

## Reporting security issues

Do not open a public issue for vulnerabilities. Follow [SECURITY.md](SECURITY.md).
