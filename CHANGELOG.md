# Changelog

All notable changes to this project are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - Unreleased

LogMasque is the public release of a tool that was previously used internally for support work. Formats and behaviour are carried over unchanged unless noted below.

### Added

- Collection of log files by day and log type from folders, files and ZIP archives, with SHA-256 deduplication, a local manifest, and folder, ZIP (LZMA) or 7z output.
- Masking of IPv4 and IPv6 addresses, domains, mailboxes, host labels and PTR records, with stable, reversible placeholders or irreversible redaction.
- Context-based detection of names, companies, phone numbers, streets, postcodes and cities, register entries and IBANs in free text such as mail threads.
- Own terms, own patterns and a "never replace" list, stored with the mapping.
- `check` command that counts remaining sensitive values without printing them.
- `store selftest` command that verifies the platform's store protection with a throwaway store.
- Browser interface on `127.0.0.1` with a live preview, protected by a session token and a Host header check.
- Self-contained single-file build `LogMasque.py`.
- `mask` as an alias for the `anonymize` command.
- `pyproject.toml` with a `logmasque` console command.

### Changed

- Renamed from the internal name to LogMasque: package `logmasque`, command `logmasque`, environment variables `LOGMASQUE_*`, log file `logmasque.log`.
- New Windows stores are protected with the DPAPI entropy value `LogMasque-Mapping-Store-v1` instead of the organization-specific value of the internal build.

### Compatibility

- The store container, the portable `.anonstore` format and all placeholder shapes are unchanged.
- Stores of the earlier PowerShell anonymizer open directly. Stores protected with any other entropy value open once that value is supplied in `LOGMASQUE_LEGACY_DPAPI_ENTROPY`, or after an export and import.
- An existing store keeps the entropy value it was written with. A store that cannot be opened is never overwritten by a normal save.
- The store folder keeps its name `Anonymize-Log`.
