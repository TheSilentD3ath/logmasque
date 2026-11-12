# Changelog

All notable changes to this project are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Log Investigator: the new **Untersuchen** tab indexes many log files into a local investigation and lets you search them and follow an address, account, device, Message-ID, queue file or session across all of them on one timeline. See [docs/investigator.md](docs/investigator.md).
  - Format detection and parsers for MDaemon event logs (sessions, partial transcripts, filter blocks, service restarts), MDaemon component logs, request logs, HTTP access logs, column-separated logs, ctime logs and a generic time-stamped reader. The rules were derived from MDaemon 26 logs.
  - Entity recognition with roles, normalized time stamps with per-file zone and clock correction, and marks for missing, broken or borrowed times.
  - Correlation in three levels (direct, strong, possible), with the basis of every link. Frequent, shared and system values are held back. Values and single links can be excluded by the reviewer.
  - Full-text search (SQLite FTS5 when available), combinable filters, a paged timeline with a time strip, event detail with the original lines, an entity explorer and a relationship graph.
  - Export of a selection for an outside analysis, masked with the mapping store. It shows a preview with marked places to review, is blocked while an original value of the events is still readable, and is never sent automatically.
  - Investigations are kept as SQLite files next to the mapping store. The originals are only read.
  - For large log sets: a quick scan of log types, sizes and time ranges; an import plan with priority files, which are searchable first, background files and a time window; parsing in helper processes; per-file statistics, so overview and time strip need no pass over all events; context lines read from the original file instead of a copy of every line in the index; event text compressed in blocks and a text index without a copy of the text, which makes the index about a quarter smaller.
  - Earlier copies of a growing log, such as the log of the current day collected twice, are recognized: only the longest copy is read, and it replaces an earlier copy in the index with its settings and review decisions.

### Fixed

- Text input on the Anonymize tab: after "Anonymisieren" the right pane shows the whole result instead of the first 200 lines of the preview; a note says what is shown, a meter under the input shows how many characters still fit (about 8 MB per request), and "Kopieren" always copies the complete result.
- The same mail address now gets the same placeholder whatever stands in front of it. Before, `User=` in a query string, a quote, a `|` or a path became part of the address, and each context produced a new placeholder.
- An IP address at the end of a sentence (`from 203.0.113.7.`) is masked.
- Web file names such as `favicon.ico`, `app.min.php` or `site.webmanifest.map` are no longer taken for domains.
- A name after a signature delimiter (`Regards,--Name`) and a name in a display name followed by the company (`"Name from Company" <address>`) are recognized.
- "Thanks Name," and its equivalents in other languages mark a first name, as "Hello Name," does.
- Numbers labelled `Toll-Free:`, `Local:`, `Direct:`, `Main:`, `Office:`, `Cell:`, `Hotline:` or `Switchboard:` are replaced as phone numbers; a date after such a label is not.
- Sentences glued together without a space, such as `Task 30927.Regards` or `this Feature.Mit`, are no longer taken for domains.
- A company name that follows a former line break no longer swallows the word before it or leaves its last letter behind; the original is stored exactly, so restoring gives back the same text.
- A company that signs right after the closing (`Mit freundlichen Grüßen` and then `Muster GmbH`) is masked as a company. Before, it was taken for a person, and the last letter of `GmbH` was left behind.
- After the closing, a name ends at a former line break. Before, in a pasted mail whose line breaks had become two blanks, the name was learned together with the company of the next line and stayed readable.
- A label word that an earlier version learned as a name, such as `Local`, stays in the store for restoring but is no longer replaced.
- An own term inside a mail address or a domain no longer keeps the address rule from masking the domain.

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
