# Log Investigator

The **Untersuchen** tab of LogMasque indexes log files from several systems, finds the identifiers in them and shows how events across the files belong together. It runs entirely on the local machine and never needs an outside service. The only output meant to leave the machine is the export for an outside analysis, which goes through the same masking as the rest of LogMasque. It is never sent automatically.

This page describes how the investigator works, what it can conclude and what it cannot, and how to extend it.

- [Workflow](#workflow)
- [Architecture](#architecture)
- [Log formats](#log-formats)
- [Entities](#entities)
- [Time](#time)
- [Correlation](#correlation)
- [Search, timeline, explorer and graph](#search-timeline-explorer-and-graph)
- [Export for an outside analysis](#export-for-an-outside-analysis)
- [Performance](#performance)
- [Extending](#extending)
- [Tests](#tests)
- [Limitations](#limitations)

## Workflow

1. **Create an investigation**, typically one per ticket. It is a single SQLite file in `investigations/` next to the mapping store and stays there until it is deleted in the interface.
2. **Add log files or folders.** A quick scan comes first and reads only the first and last 64 KB of every file. It shows:
   - the log types with their number of files, total size and time range;
   - an estimate of how long the import will take.

   For each log type you choose how it is handled:
   - **Zuerst**: imported first;
   - **Hintergrund**: imported after the priority files;
   - **Auslassen**: not imported.

   A time window leaves out files whose time range lies outside it; they can also go to the background instead.
3. **Import.**
   - Files are read once and never written to.
   - Files that are byte-identical to one already imported are skipped.
   - A log that grew between two copies, for example the log of the current day collected at noon and again in the evening, is read only in its longest copy. An earlier copy in the same import is left out; one already in the index is replaced once the longer copy is in, and keeps its zone and clock settings and the review decisions. The scan marks such copies, the import checks them in full; see [Continued logs](#continued-logs).
   - The status shows the phase, files and bytes done, and the time left.
   - As soon as the priority files are in, the investigation can be searched. The background files keep coming in, and *Neue Daten anzeigen* loads what has arrived since.
   - While an import runs, adding and removing files and changing zones are locked.
   - Cancelling keeps every file that was completely read.
4. **Check the time settings.** The table under *Logdateien, Zeitzonen und Uhrkorrektur* shows, per file:
   - the detected format;
   - the time range;
   - how many lines have no usable time.

   The zone can be fixed per file, and a clock that runs ahead or behind can be corrected in seconds.
5. **Search.**
   - Type an address, account, Message-ID, queue file, device id or any text.
   - Suggestions show known values with their kind and frequency.
   - A known value turns the search into a *trace*: every event that belongs to it, with the level and the basis of each link.
6. **Inspect.**
   - **Event:** a click on an event shows its original lines with the lines around them, the recognized values, and the session, request or block it belongs to.
   - **Value:** a click on a value opens the entity explorer, and the graph shows its neighbourhood.
7. **Review.**
   - A value can be excluded from linking ("Nie verknüpfen").
   - A frequent value can be used on purpose ("Trotzdem verknüpfen").
   - Single links can be excluded in the entity explorer or the graph.
8. **Export** a selection for an outside analysis:
   - preview, check, release;
   - then copy or save. Where the text goes is up to you.

## Architecture

| Module | Role |
|---|---|
| `logmasque/logformats.py` | Format detection and parsers. Turns lines into events: time as written, type, severity, context (session, request, block), identifiers read from known positions. |
| `logmasque/entities.py` | Identifier rules: what a value is, how it is normalized, which kinds link events. Shares the address, mail and domain patterns with the anonymizer. |
| `logmasque/investigate.py` | The investigation: SQLite schema, import, time normalization, frequency marks, search, trace and correlation, entity detail, graph, export. |
| `logmasque/server.py` | `/api/inv/*` routes for the interface; scans, imports and time changes run as background jobs with progress and cancel. |
| `logmasque/web/investigate.js` | The tab: scan and import plan, search, timeline, event detail, entity explorer, graph, export dialog. |

All modules use the standard library only. The single-file build bundles them like every other module.

### Data model

| Table | Content |
|---|---|
| `sources` | One row per imported file: path, SHA-256 of the whole file and of its first 512 bytes, size and modification time, format, encoding, line and event counts, detected and stated zones, zone and clock settings, import state, counts per event type and time flag. |
| `events` | One row per event: file, first and last line, wall-clock time as written, stated offset, normalized UTC time and sort key, time flag, type, severity, context. |
| `texts` | The original text of the events, compressed in blocks of 512 consecutive events. Events of the first versions keep their text in `events` instead. |
| `contexts` | The sessions, requests and blocks, numbered; events refer to them by number. |
| `marks` | The byte position of every 256th line of a file, for the context view. |
| `bins` | Event counts per file, 10 minutes and severity, for the overview and the time strip of large result sets. |
| `entities` | One row per distinct value per kind: display form, counts of events, contexts and files, first and last sighting, `common` and `generic` marks. |
| `entity_source` | The same counts per entity and file; the totals in `entities` are their sums. |
| `ip_accounts` | Which accounts log in from which address, per file; it decides the shared-address mark. |
| `occurrences` | Entity × event, with the role the value plays there (`client`, `server`, `from`, `to`, `return-path`, `account`, `context`, ...). |
| `excluded`, `included`, `link_excluded` | The reviewer's decisions. |
| `events_fts` | SQLite FTS5 index over the event text, without word positions and without a copy of the text, when the Python build supports FTS5. Without it, search falls back to `LIKE`. |

**Import.**

- A file is read as bytes, line by line. Every 256th line's position is noted, so the context view can later read the lines around an event from the original file.
- Events are written in portions and committed every 50,000 events. Search sees a large file while it is being read.
- At the end of a file, its times are settled and its statistics and entity counts are updated. Counts are kept per file, so a new file only touches the entities that occur in it.
- When a file states a zone that changes the investigation default, the times of all files are recomputed.
- Large imports are read and parsed in helper processes, several files at a time, while the main process writes; see [Performance](#performance).

**Removing a file** deletes its events, occurrences, contexts and statistics, and the entities that no longer occur anywhere, together with the review decisions about them: their numbers are given out again.

### Continued logs

A log that is still being written grows between two copies. The later copy begins with every byte of the earlier one, so their checksums differ and both would be read in full. The investigator recognizes such copies:

1. Files of 512 bytes and more are grouped by a checksum of their first 512 bytes, the files to import together with the imported ones.
2. Within a group, a shorter file is a candidate when the longer one begins with its first 64 KB, and for longer files also with its last 64 KB at the same place. The scan stops here and marks the file.
3. The import compares the checksum of the whole shorter file with the checksum of as many bytes of the longer one. An imported file that has changed since, such as the log of the current day at its old path, is compared by the checksum taken when it was read.

Then:

| Shorter copy | Longer copy | What happens |
|---|---|---|
| to import | to import | the shorter one is left out; if it was a priority file, the longer one is read with the priority files |
| to import | in the index | the shorter one is left out |
| in the index | to import | the longer one is read; then the shorter one is removed, its zone and clock settings go to the longer one, and the review decisions stay with addresses, accounts and the other values (not with its sessions and requests, which are numbered per file) |

The index then holds the same as if only the longer copy had been read. Copies that both are in the index already stay as they are.

**Investigations of an earlier version** are converted when they are opened: missing columns, the sort key, numbered contexts and the per-file statistics are added. Their stored lines stay and serve the context view. The text of their events stays uncompressed; files added later are stored compressed. For the smaller index throughout, create the investigation anew.

## Log formats

The format rules were derived from MDaemon 26 logs of a lab system: about 50 files from more than 40 log types. Only structures that occur in those logs are interpreted. Everything else is read by the generic reader. The first 300 lines decide the format; the format that recognizes the most lines wins, and below a third the generic reader takes over.

| Format | Example layout | What it reads |
|---|---|---|
| MDaemon event log | `Wed 2026-10-21 08:00:00.100: text` | `START Event Log` headers (session numbers restart, so contexts carry the restart), `Server Shutdown <RFC 2822 date>` headers (zone of the file), sessions (`Session N; child M`), sessions written in partial transcripts, processing blocks closed by `----------`, request ids in braces, job ids in brackets, level and id prefixes |
| MDaemon component log | `261021 080500123 I [0002B7C1] 0x41330080 text` | date and time with milliseconds, level letter, worker or request id as context, message code; ActiveSync request lines with client address, user and device id from the query string |
| Request log | `[Wed 2026-10-21 08:06:00] INFO, [ABCDEFGHJK] text` | level, request id as context, connection and authentication lines of WebDAV, WebAdmin and XMPP |
| HTTP access log | `client - user [21/Oct/2026:08:07:00 +0200] "GET / HTTP/1.1" 200 4096` | client address, user, stated zone, status |
| Column log | `2026-10-21 08:08:00 \| WARNING \| text` | level, request lines with client address and status |
| ctime log | `Wed Oct 21 08:09:00 2026 -> text` | ClamAV daemon messages |
| Generic | ISO 8601 with or without zone, `2026/10/21 …`, `21.10.2026 …`, syslog `Oct 21 08:00:00` | time stamps, severity words; identifiers by the general rules |

Details of the MDaemon event log:

- **Partial transcripts.** A long session is written in parts between `--------- Partial transcript` and `---------- End partial transcript`. Every later part starts with the last line of the part before. A part that starts with such a repeated line belongs to that session, and the repeated line is not counted twice. The final part, written as a normal block, is attached the same way. No other evidence is used: a part whose first line repeats nothing and that names no session stays without a session.
- **Processing blocks.** Lines up to a `----------` delimiter form one event, for example a virus scan of one queue file with sender, recipient and result. A block keeps the types of its lines; the most severe one decides its severity. Blocks of more than 400 lines are not merged.
- **Contexts.** Request and job ids with more than 400 events or spanning more than 30 minutes name a worker thread rather than a request, and are not used as context.
- **Line continuation.** A line without a time stamp belongs to the event before it. In the line-based formats this applies only to indented lines; an unindented line without a time stands alone and takes the time of the line before, marked as taken.

The type names and German labels of events are in `ETYPE_LABELS` in `logformats.py`.

## Entities

| Kind | Example | Class | Links events |
|---|---|---|---|
| `msgid` | `<a1b2@mail.partner.example>` after a `Message-ID` label or in `processing message <…>` | unique | directly |
| `queue` | `md50000000002.msg`, `pd…`, `….raw` | unique | directly |
| `session` | session number within one file and restart | unique | directly |
| `request` | request or worker id within one file | unique | directly |
| `email` | `alpha@firma.example`; a login that is an address counts as the address | identity | strong or possible |
| `account` | login names that are not addresses | identity | strong or possible |
| `device` | ActiveSync device id | identity | strong or possible |
| `ipv4`, `ipv6` | addresses; IPv4-mapped IPv6 counts as IPv4 | identity | strong or possible |
| `endpoint` | address with port, `198.51.100.20:51744` | identity | strong or possible |
| `domain`, `host`, `url` | `mail.firma.example`, `https://…` | descriptive | no, searchable and shown in the graph |
| `status`, `code`, `pid`, `port` | `HTTP 401`, `0x41330080` | weak | no, searchable |

Rules that avoid false identifiers:

- A Message-ID is recognized by its label, because it looks exactly like a mail address. The address inside it does not count as a mail address again.
- A version number such as `Chrome/120.0.0.0` is not an address.
- A domain needs a real-looking ending. File names such as `service.dll` or `favicon.ico`, and sentences glued together such as `Task 30927.Regards`, are not domains. These are the anonymizer's rules, so both agree on what a domain is.
- A mail address is taken without what stands in front of it: in `QS:Cmd=Sync&User=alpha@firma.example` the address is `alpha@firma.example`.

**Roles.** A value read from a known position carries a role, for example `client` and `server` of a connection, `from`, `to` and `return-path` of a message, or `account` of a login. The server address of a connection (`… to 192.0.2.10:993`) is marked `server` and never links events.

**Generic values** link nothing:

- loopback and unspecified addresses;
- system mailboxes and accounts such as `postmaster`, `mailer-daemon`, `noreply`, `mdaemon` and `administrator`.

**Frequent values** link only close in time:

- a Message-ID, queue file, domain, host or URL seen in 40 or more separate contexts;
- an address that three or more accounts log in from, in the same session or request (a NAT router, a proxy, the server itself).

Both marks are visible in the interface and can be overruled per value.

## Time

Every event keeps the time as the log wrote it. The normalized UTC time is derived from it, in this order:

1. A zone stated in the line itself, such as `+0200`, `Z` or `+02:00`.
2. A zone set by the user for the file.
3. A zone the file states, such as the `Server Shutdown` header of MDaemon logs.
4. For lines without any zone, the investigation default:
   - *automatic* takes the zone that all stated zones of the investigation agree on, otherwise this computer's zone (summer time included);
   - *this computer* always takes this computer's zone;
   - *fixed* takes a fixed offset.
5. A clock correction in seconds per file is added on top.

Each event carries a flag that the timeline shows:

| Flag | Meaning |
|---|---|
| `exact` | the line states its zone |
| `source` | the zone of the file (stated by the file or set by the user) |
| `inferred` | the zone the other files of the investigation agree on |
| `local` | this computer's zone was assumed |
| `inherited` | the line has no time; the time of the line before is used |
| `ambiguous` | the time is doubtful, for example a syslog line without a year and without a date in the file name, or a date far from the file's date |
| `invalid` | the time stamp could not be read, for example a 13th month |
| `none` | no time at all |

Events without a usable time are listed after all timed events and never placed by guesswork. Changing a zone or clock setting recomputes all times at once.

## Correlation

A trace starts from one or more entities and collects events in three levels. Every event in a trace names the basis of its link, for example `gleiche Queue-Datei md50000000002.msg` or `gleiche IPv4-Adresse 198.51.100.20, zeitlich nah (±5 min)`.

### Direct

- Events that contain the entity.
- All events of the same session, request or processing block as such an event.
- From these, the chain continues over Message-IDs and queue files (not frequent, not excluded) up to three steps.

In the lab logs, the conversion of a received message, its virus scan and its content filter share both its queue file and its Message-ID. DKIM signing, the PGP plug-in, AntiSpam and spamd share the Message-ID of a sent message.

### Strong and possible

Only the searched entity's own events, together with their sessions, requests and blocks, are searched for further identities: addresses, accounts, devices, endpoints. Other events containing these identities are then:

| Level | Condition |
|---|---|
| strong | one or more of these identities within ±5 minutes |
| possible | one or more of these identities further apart in time |
| possible | a shared address (NAT, proxy) within ±5 minutes, marked as "geteilte Adresse" |
| possible | only when asked for in the interface: another file's event within a chosen number of seconds, with no shared identifier at all, marked as "nur zeitliche Nähe" |

Further limits:

- The server address of a connection never links.
- Generic values never link.
- **Messages versus persons.** When the search is for a person (a mail address, account, device or IP address), the sender and recipient of a message that person appears in are somebody else. They are not used to widen the trace. When the search is for a message (a Message-ID or queue file), its sender and recipient are used. A block with the same parties is strong only close in time; further apart it is possible, because the same two parties also write each other at other times.

Closeness in time alone never makes a link stronger than *possible*.

### Review

- **Never link** (*Nie verknüpfen*) takes a value out of all links. The value stays searchable.
- **Link anyway** (*Trotzdem verknüpfen*) uses a frequent or generic value like a rare one.
- **Exclude a link** removes the relation between two values from relations, graph and trace. The `×` in the entity explorer and the edge menu in the graph do this.
- All decisions are stored in the investigation and can be undone.

## Search, timeline, explorer and graph

**Search.**

- Text that is exactly a known value of any kind becomes a trace of that value, otherwise a full-text search.
- With FTS5, all words must occur, and a trailing `*` searches by prefix. The text index keeps no word positions, which saves about a third of its size. A search for words joined by punctuation, such as `user@host` or `a.b`, is checked against the event text afterwards, so it finds only events that contain the words in that order.
- Free text next to chosen values narrows their trace.
- Filters for time range, files, event types, detail lines and levels combine freely.

**Timeline.**

- 200 events per page, ordered by UTC time; events without time come last.
- A strip above the list shows the distribution over time, by level in a trace; a click on a bar narrows the time range to it.
- Hits are counted up to 100,000; above that the count reads "über 100.000". For such a result, filtered only by files, levels and time, the strip comes from the per-file statistics in 10-minute steps and says so. With text, event types or a trace it is left out rather than scanning the whole index.
- Each row shows:
  - the time in the event's own zone and a mark for doubtful times;
  - the log type, the level or severity, the event type and the basis;
  - the first values.
- *Alle wählen* takes up to 5,000 hits of the current search into the export selection.

**Event detail.**

- The original lines, numbered as in the file, with six lines before and after; recognized values are highlighted and clickable.
- The lines are read from the original file, but only while its size and modification time are those of the import. If the file was changed, moved or deleted, the stored text of the event is shown instead, with a note.
- The time as written and how it was interpreted.
- The session, request or block the event belongs to, which can be listed in full.

**Entity explorer.**

- Kind, marks, occurrences, files, contexts, first and last sighting, roles.
- The level counts of its trace.
- Occurrences per file; a click shows the trace in that file.
- Directly related values (same event or context) with the number of shared events.
- Values from strong and possible events.

**Graph.**

- The entity, its closest direct relations (24 by default), and one more step behind Message-IDs, queue files, sessions and requests.
- Domains, hosts, URLs and endpoints are off by default and can be switched on.
- Nodes are coloured and lettered by kind. Edge width follows the number of shared events.
- Zoom with the wheel or the buttons, pan by dragging.
- A click highlights the neighbours; a double click centres the graph on another value. A click on an edge offers to exclude that link.

## Export for an outside analysis

The export dialog builds a text from the chosen events and masks it:

1. Events are ordered by time. Each line starts with the UTC time in its own zone and an alias such as `Q3` instead of the file name. The header maps aliases to log types (`Q3 = AirSync (MDaemon-Komponentenlog)`), and the header is masked as well.
2. The anonymizer of LogMasque masks the text:
   - with the personal mapping store, so the placeholders are the same as in every other masked file and can be restored locally;
   - or, when unchecked, with a throwaway mapping.
3. Values the patterns cannot know by their shape are masked as own terms (`[WERT-001]`): accounts, device ids, host names, and the host of a URL that is not a domain. System names such as `postmaster` stay.
4. **Leftover values are masked with their placeholder.** The anonymizer's patterns judge a value by what surrounds it, and can miss one glued to a word or standing behind an underscore. The investigation knows every value of the chosen events. Whatever is left of them is replaced by the placeholder the anonymizer gives that value, so it stays consistent and reversible. This runs twice, because masking one value can lay open another.
5. **Leak check.**
   - If an original value of the events is still readable as a whole, the export is **blocked**, and the preview marks the place in red.
   - The general check of LogMasque marks what still looks like personal data, or words such as `password`, in orange. Those places must be confirmed before release.
   - A value on the never-replace list stays by the user's decision.
6. **Release.**
   - Only after release can the text be copied or saved as a file.
   - With the store, new placeholders are saved so that an answer can be restored on the Anonymize tab.
   - Nothing is sent anywhere.

## Performance

Measurements on a Linux container with four cores and Python 3.11:

| Data | Result |
|---|---|
| 42 lab log files, 11 MB, 110,000 lines, 103,000 events, 9,800 entities | import in 4.8 s, with helper processes 2.8 s; index file about 25 MB |
| full-text search over these | a few milliseconds |
| trace of the most frequent address, IP address or device (up to 27,000 events) | about 0.2 s |
| masked export of all 103,000 events in blocks of 5,000 | about 50 s, no leaks |
| 17 synthetic files, 77 MB, 535,000 events | import in 37 s; with two helper processes 19 s, with three 18 s (4.5 MB/s); index 151 MB |
| trace of an account in these | about 0.3 s |
| 6 synthetic files, 330 MB, 3.5 million one-line events, 1.4 million distinct values | with three helper processes 140 s (2.5 MB/s); index 1.2 GB; at most 450 MB of memory for all processes together |

**Large log sets.**

- **Quick scan.** It reads at most 128 KB per file, about 5 ms per file here. The plan, the estimate and the time window are based on it.
- **Plan.** What matters for the case goes first and is searchable after minutes; what is only needed for context follows in the background or not at all. The estimate uses the speed measured during earlier imports into the same investigation, otherwise 1 MB/s.
- **Helper processes.** From 32 MB on, up to three helper processes (one less than the computer has cores) read and parse the files, several at a time, while the main process writes the index. The index is the same as without them. The only exception is the display form of a value written differently in different files, for example with and without an IPv6 prefix: it comes from the file that is written first. If the helpers cannot be started or fail, the main process reads the remaining files itself. `LOGMASQUE_IMPORT_READERS` sets their number; `0` turns them off.
- **Size.** The index takes two to three and a half times the size of the logs: 2.4 times for the lab logs, twice for the 77 MB set, three and a half times for logs of short lines with very many distinct values, such as ever-new client addresses.
  - The text of the events is compressed in blocks of 512 events, to an eighth to a fifth of its size; a block unpacks in a tenth of a millisecond.
  - The text index keeps no copy of the text and no word positions.
  - The index over sessions and requests holds only the events that belong to one.
  - Lines are not stored a second time; the context view reads them from the original file.
  - What remains is mostly the event rows with their times, the occurrences of every value in both directions, and the indexes for time order and files.
- **Disk space.** The investigations folder is next to the mapping store, on Windows in `%LOCALAPPDATA%\Anonymize-Log\investigations`. Its drive needs free space of about three and a half times the logs to be imported.
- **Memory.** In the measurement with 330 MB the main process needed about 250 MB and each helper process about 70 MB. Memory does not grow with the number or the total size of the files: events travel in bounded portions, and the cache of known values is limited. Only the session and request numbers of the files being read are kept, so a single very large file needs somewhat more.
- **In practice.** A laptop keeps its speed on mains power and in its best-performance power mode. Logs on a network share or a USB drive are read more slowly, and the context view needs them later at the same path; a local copy is better.
- **What stays fast.** The overview and the unfiltered timeline come from statistics per file and need no pass over all events. Hits are counted up to 100,000. Traces, the entity view and suggestions use indexes.

Limits that keep the interface responsive:

- 1,000 rows per request;
- 50,000 events per trace, after which it is marked as cut off;
- 100,000 hits counted per search;
- 5,000 events per export;
- graphs of 40 nodes at most.

## Extending

**A new log format.** Write a subclass of `logformats.Format`:

- a `name` and a German `label`;
- `recognizes(line)` for detection;
- `parse(lines, hints)`, yielding `Event` objects.

For line-based logs, `Format._line_events` handles continuation lines. Messages can be classified with a list of `_rule(...)` entries and `apply_rules`; a rule's named groups become identifiers with a kind and a role. Add the class to `FORMATS`. Base new rules on real log structures and test them with synthetic lines of the same shape.

**A new kind of identifier.** Register a rule:

```python
from logmasque import entities

entities.register(entities.Rule("code", re.compile(r"\bTKT-\d{5}\b"), priority=60))
```

Rules with a priority below 50 run before addresses and claim their text. Rules from 50 run after addresses. A new kind needs a label in `KIND_LABELS`. It links events only when it is added to `UNIQUE_KINDS` (direct) or `LINK_KINDS` (strong and possible).

## Tests

`tests/test_investigate.py` runs on synthetic logs from `tests/inv_samples.py`. These are documentation addresses, `.example` domains and invented accounts in the layouts found in the real logs. The tests cover:

- detection of every format and encoding;
- unchanged originals, verified by hash and modification time;
- duplicate files;
- stored events equal to the original lines;
- partial transcripts and session restarts;
- stated, inferred, fixed and corrected time zones; broken, missing and taken times; sort order;
- the queue file chain and the Message-ID chain;
- person traces without correspondents;
- the basis of every link;
- NAT addresses and the server address;
- time closeness only on request;
- frequent Message-IDs;
- excluded and included values, and excluded links;
- removing a file;
- free-text search with combined filters, prefix search, levels, suggestions, and the fallback without FTS5;
- the export: no original value and no file name in it; consistent placeholders; values hidden by their surroundings; blocking when a value remains; review of suspicious words; the never-replace list;
- 28,000 lines with time limits;
- cancelling an import;
- the quick scan, the import plan with priority and background files, and search while a large file is read;
- per-file counts that add up to a full recount, after adding and removing files;
- the context view from the original file, the byte reader against the text reader, and the fallback for changed files;
- the import with helper processes: the same index as without them, also when helpers fail or cannot start, and after cancelling;
- earlier copies of growing logs: left out in the same import, replaced in the index with their settings and decisions, recognized at the same path after the log grew there, told apart from files that only begin alike, marked in the scan, and the same with helper processes;
- the compressed event text: smaller than the text, intact after removing a file that shares its blocks, and readable next to the uncompressed text of earlier versions;
- the conversion of investigations of the first version;
- persistence and deletion;
- the server API from creation to export, including scan, plan, the locks during an import and time changes as a job.

## Limitations

- **Reference data.** In the lab logs, the SMTP (outbound), DNSBL, DMARC, ARC, POP3, MultiPOP, DomainPOP, Minger, MTA-STS, Connector and main MDaemon logs contained only their headers. There is no inbound SMTP or routing log among them. For these logs there are no event types or chain rules beyond the general MDaemon layout (sessions, blocks, identifiers). A message can therefore be followed from conversion through the filters, and through DKIM, spamd and PGP, but not through its SMTP dialogue or its routing.
- **Received and sent messages.** In the lab logs, the chain of a received message (conversion, virus scan, content filter) and the chain of a sent message (DKIM signing, PGP, AntiSpam, spamd) never share an identifier. Whether one message passes both cannot be shown from them. Message files named in ActiveSync fetch requests (`md…msg`) are treated like queue files; in the lab logs they never matched a file of the filters.
- **Generic reader.** Logs of other products are read by time stamp and general identifier rules. There are no sessions, requests or event types for them until a format is written.
- **Time.** Without a zone in the logs, *automatic* assumes the zone all stated zones agree on, or this computer's. Logs from systems in different zones need a zone per file. The hour repeated when summer time ends cannot be told apart in logs without a zone.
- **Links are hints.** The levels describe what the logs state, not what happened. A NAT address, a shared device or a reused id can still mislead. *Possible* links in particular need checking, and closeness in time is never proof.
- **Continued logs.** A copy counts as earlier only when the longer one begins with all of its bytes. A log that was rotated, cut, rewritten or converted to another encoding is a file of its own. Files under 512 bytes are not compared.
- **Fixed thresholds.** The frequency marks (40 contexts; three accounts per address) and the ±5 minutes for strong links are fixed values chosen on the lab data.
- **Strong is not proof.** A strong link means a shared address, account or device close in time. Two users behind one address that the logs do not reveal as shared, or one device used by two people, still look the same.
- **Input.** ZIP archives are not read directly; collect them into a folder first. Files are imported as a whole; there is no live tail.
- **The investigation holds originals.** The index contains the original text of every event. It is stored next to the mapping store and should be deleted when the case is closed.
- **Context from the original.** The lines around an event are read from the original file. Once the file is changed, moved or deleted, only the event's own text is shown.
- **Quick scan.** The time range of a file comes from its first and last 64 KB. A file whose first or last lines are out of order may be shown with a narrower range than it has, and a time window can then leave it out. A file without times in those parts is always imported.
- **Large imports.** The size of the index grows with the logs, two to three and a half times their size, and a large import can take hours. Free disk space for that is not checked in advance; see [Performance](#performance).
- **Export size.** At most 5,000 events per export.
