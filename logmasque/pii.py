"""Personal data in free text: names, phone numbers, addresses, companies.

Logs carry addresses, mails carry people. A name cannot be told from any other
capitalised word by its shape, so names are learned where the text itself says
what they are: the display name in front of an address, "Herr Muster", the line
under "Mit freundlichen Grüßen", "Geschäftsführer: ...". Once learned, a name is
replaced everywhere, including places without such a hint, and the store keeps
it for the next text.

Phone numbers, streets, postcodes, companies, register numbers and IBANs have a
shape of their own and are matched directly. Each of those patterns is kept
narrow on purpose: the same engine runs over logs, where a loose phone or street
rule would eat session IDs, timestamps or words like "Firewall 2".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

U = "A-ZÀ-ÖØ-ÞĆČĎŁŃŇŘŚŠŤŹŻŽ"
L = "a-zß-öø-ÿćčďłńňřśšťźżž"
_GAP = r"[ \t\u00a0]+"
# Where a word starts: after a non-word character, or at a capital letter glued
# to a lowercase one ("MustermannSitz der Gesellschaft"), as in mails that lost
# their line breaks when copied out of a ticket system.
_START = rf"(?:(?<![\w])|(?<=[{L}])(?=[{U}]))"

NAME_WORD = rf"[{U}][{L}]+(?:-[{U}][{L}]+)?"
_PARTICLE = r"(?:von|van|de|der|den|zu|zum|zur|di|da|del|du|le|la|ter|ten)"
_NAME_TAIL = rf"(?:{_GAP}(?:{_PARTICLE}{_GAP}){{0,2}}{NAME_WORD})"
_TITLE = r"(?:(?:Dr|Prof|Dipl|Ing|Mag)\.?(?:-[A-Za-z]+\.?)?" + _GAP + r")*"

LEGAL_FORMS = (
    r"GmbH[ \t]?&[ \t]?Co\.?[ \t]?KG|gGmbH|GmbH|mbH|AG|KGaA|KG|OHG|GbR"
    r"|UG(?:[ \t]?\(haftungsbeschränkt\))?|e\.[ \t]?K\.|e\.[ \t]?V\.|eG|SE"
    r"|Ltd\.?|Limited|Inc\.?|LLC|Corp\.?|S\.A\.|B\.V\.|S\.r\.l\.|S\.p\.A\."
)
_LEGAL_END = re.compile(rf"(?:^|[ \t])(?:{LEGAL_FORMS})$")

# Words that are never part of a name, however they are capitalised.
STOP_WORDS = frozenset(
    """
    herr herrn frau fräulein damen herren hallo hi hey moin servus liebe lieber dear sehr geehrte
    geehrter guten tag morgen abend mit freundlichen freundlichem freundliche grüßen grüße gruß grüssen
    grüsse gruss viele beste herzliche schöne mfg lg vg regards kind best thanks thank danke vielen dank
    cheers wishes von an cc bcc betreff gesendet datum from to sent subject date tel telefon fax mobil
    mobile handy phone web www e-mail email mail internet team support service services lead customer
    kunde kunden kundin firma geschäftsführer geschäftsführerin geschäftsführung amtsgericht
    registergericht hrb hra ust ustid sitz vorstand inhaber ansprechpartner abteilung technik vertrieb
    buchhaltung einkauf verwaltung admin administrator postmaster info office zentrale hinweise
    datenschutz datenschutzerklärung impressum ihr ihre ihnen sie euch dir du wir uns unser unsere der
    die das den dem des ein eine einer und oder für bei zum zur im am ja nein ok okay bitte ticket
    tickets anfrage re aw wg fw fwd ich es er kollege kollegen kollegin kolleginnen alle zusammen leute
    gesellschafter director directors manager head of the and dach europe germany deutschland
    januar februar märz april mai juni juli august september oktober november dezember jan feb mär
    mar apr jun jul aug sep sept okt oct nov dez dec may march june july october december
    montag dienstag mittwoch donnerstag freitag samstag sonntag monday tuesday wednesday thursday
    friday saturday sunday mon tue wed thu fri sat sun
    mr mrs ms miss mx sir madam monsieur madame mme mlle signor signora sig señor señora sr sra dhr mevr
    meneer mevrouw hello good morning afternoon evening everyone colleague colleagues customer gentile
    caro cara estimado estimada beste bonjour buongiorno buonasera ciao hola hej hoi sincerely faithfully
    truly yours many warm kindest cordiali distinti saluti cordialement saludos atentamente groet groeten
    """.split()
)

# A five-digit number followed by one of these is a count, not a postcode.
_NOT_A_CITY = frozenset(
    """
    bytes byte kb mb gb tb dateien datei files file messages message nachrichten nachricht mails
    einträge zeilen sekunden minuten stunden tage fehler benutzer user users items objekte ordner
    """.split()
)


def _is_stop(word: str) -> bool:
    # "Support-Team" is no name, "Jan-Christian" is one although "Jan" is a month.
    return all(part.casefold() in STOP_WORDS for part in word.split("-") if part)


def _words(value: str) -> list[str]:
    return [word for word in re.split(r"[ \t\u00a0]+", value.strip()) if word]


def clean_name(value: str) -> list[str]:
    """Words of a candidate name, with leading and trailing non-name words removed."""
    words = _words(value)
    while words and (_is_stop(words[0]) or not re.fullmatch(NAME_WORD, words[0])):
        words.pop(0)
    while words and (_is_stop(words[-1]) or not re.fullmatch(NAME_WORD, words[-1])):
        words.pop()
    for word in words:
        if not (re.fullmatch(NAME_WORD, word) or re.fullmatch(_PARTICLE, word)) or _is_stop(word):
            return []
    return words


def clean_company(value: str) -> str:
    words = _words(value)
    while len(words) > 1 and (_is_stop(words[0]) or words[0][:1].islower()):
        words.pop(0)
    return " ".join(words)


@dataclass
class Findings:
    """What a text revealed about the people and companies in it."""

    full: list[str] = field(default_factory=list)
    surname: list[str] = field(default_factory=list)
    first: list[str] = field(default_factory=list)
    company: list[str] = field(default_factory=list)
    city: list[str] = field(default_factory=list)

    def add_name(self, words: list[str], single: str) -> None:
        if len(words) >= 2:
            _append(self.full, " ".join(words))
        elif len(words) == 1 and len(words[0]) >= 3:
            _append(self.surname if single == "surname" else self.first, words[0])

    def merge(self, other: "Findings") -> None:
        for name in ("full", "surname", "first", "company", "city"):
            for value in getattr(other, name):
                _append(getattr(self, name), value)


def _append(target: list[str], value: str) -> None:
    if value and value not in target:
        target.append(value)


def classify(value: str, findings: Findings) -> None:
    """A display name is either a company, a person, or neither."""
    value = value.strip().strip("\"'").strip()
    if not value or "@" in value or re.search(r"\d{3}", value):
        return
    if _LEGAL_END.search(value):
        _append(findings.company, clean_company(value))
        return
    if "," in value:  # "Muster, Erika"
        last, _, first = value.partition(",")
        words = clean_name(first) + clean_name(last)
    else:
        words = clean_name(value)
    names = [word for word in words if not re.fullmatch(_PARTICLE, word)]
    if len(names) > 3:  # "Neue Nachricht Erika Muster": keep the name at the end
        words = words[-2:]
    if len(words) >= 2:  # one word alone could just as well be "Buchhaltung"
        findings.add_name(words, "surname")


_ADDRESS = re.compile(r"<[^<>@\s]+@[^<>\s]+>")
_BEFORE_QUOTED = re.compile(r"\"(?P<v>[^\"<>@\r\n]{2,80})\"[ \t]*$")
_BEFORE_PLAIN = re.compile(rf"(?:^|(?<=[\s(\[>,;:]))(?P<v>[{U}][^\"<>@,;:\r\n]{{1,60}}?)[ \t]+$")
_HEADER = re.compile(
    rf"(?im)(?:(?<![A-Za-zÄÖÜäöüß])|(?<=[{L}])(?=[{U}]))(?:von|an|cc|bcc|from|to|absender|empfänger)[ \t]*:[ \t]*"
    r"(?:\"(?P<q>[^\"\r\n]{2,80})\"|(?P<v>[^\"<(\[\r\n:;]{2,80}?)[ \t]*(?=[<(\[]))"
)
# Forms of address in the languages support mail tends to arrive in.
_ADDRESS_FORMS = (
    r"Herrn?|Frau|Hr\.|Fr\.|Mr\.?|Mrs\.?|Ms\.?|Miss|Mx\.?|Monsieur|Madame|Mme\.?|Mlle\.?"
    r"|Signora|Signor|Sig\.(?:ra)?|Señora|Señor|Sra\.|Sr\.|Dhr\.|Mevr\.|Meneer|Mevrouw"
)
_SALUTATION = re.compile(
    rf"{_START}(?:{_ADDRESS_FORMS}){_GAP}{_TITLE}"
    rf"(?P<v>{NAME_WORD})(?:{_GAP}(?P<w>{NAME_WORD})(?=[ \t]*(?:[,.!?;:\r\n]|$)))?"
)
_GREETING = re.compile(
    rf"{_START}(?:Hallo|Hello|Hi|Hey|Moin|Servus|Lieber|Liebe|Dear|Guten{_GAP}(?:Morgen|Tag|Abend)"
    rf"|Good{_GAP}(?:morning|afternoon|evening|Morning|Afternoon|Evening)|Bonjour|Buongiorno|Buonasera|Ciao"
    rf"|Gentile|Caro|Cara|Hola|Estimado|Estimada|Beste|Hej|Hoi){_GAP}"
    rf"(?P<v>{NAME_WORD})(?:{_GAP}(?P<w>{NAME_WORD}))?(?=[ \t]*(?:[,!.\r\n]|$))"
)
_CLOSING_PHRASE = (
    r"(?i:mit[ \t]+freundlichen[ \t]+gr(?:ü|ue)(?:ß|ss)en|mit[ \t]+freundlichem[ \t]+gru(?:ß|ss)"
    r"|(?:freundliche|viele|beste|liebe|herzliche|schöne)[ \t]+gr(?:ü|ue)(?:ß|ss)e"
    r"|(?:best|kind|kindest|warm|warmest)[ \t]+regards|best[ \t]+wishes|many[ \t]+thanks"
    r"|yours[ \t]+(?:sincerely|faithfully|truly)|sincerely|cordiali[ \t]+saluti|distinti[ \t]+saluti"
    r"|(?:bien[ \t]+)?cordialement|saludos[ \t]+cordiales|un[ \t]+saludo|atentamente"
    r"|met[ \t]+vriendelijke[ \t]+groet(?:en)?|med[ \t]+vänliga[ \t]+hälsningar)"
    r"|(?:^|(?<=[\r\n.!?]))[ \t]*(?i:gr(?:ü|ue)(?:ß|ss)e|gru(?:ß|ss)|mfg|lg|vg|regards|cheers|saluti"
    r"|saludos|groeten|mvg)"
)
_CLOSING = re.compile(
    rf"(?m)(?:{_CLOSING_PHRASE})(?:[ \t]*/[ \t]*(?i:kind|best)[ \t]+regards)?[ \t]*[,.!]?\s{{0,6}}"
    rf"{_TITLE}(?P<v>{NAME_WORD}{_NAME_TAIL}{{0,3}})"
)
_ROLE = re.compile(
    r"(?i:geschäftsführer(?:in)?|geschäftsführung|geschäftsführende[rn]?[ \t]+gesellschafter(?:in)?"
    r"|vorstand|vorstandsvorsitzende[rn]?|inhaber(?:in)?|ansprechpartner(?:in)?|sachbearbeiter(?:in)?"
    r"|bearbeiter(?:in)?|aufsichtsratsvorsitzende[rn]?|managing[ \t]+directors?|ceo|cto|kontakt|contact)"
    r"[ \t]*:[ \t]*(?P<v>[^\r\n|]{3,200})"
)
_WROTE_WORD = re.compile(r"(?i:schrieb|wrote)(?![\w])")
_AFTER_WROTE = re.compile(rf"[ \t]+(?P<v>{NAME_WORD}{_NAME_TAIL}{{1,2}})")
_BEFORE_WROTE = re.compile(rf"(?P<v>{NAME_WORD}{_NAME_TAIL}{{1,2}})[ \t]+$")
_SEAT = re.compile(
    rf"{_START}(?i:sitz(?:[ \t]+der[ \t]+gesellschaft)?|firmensitz|registered[ \t]+office)[ \t]*:[ \t]*"
    rf"(?P<v>[{U}][{L}]+(?:-[{U}][{L}]+)*(?:[ \t](?:am|an|im|in|ob|vor|der)[ \t][{U}][{L}]+)?)"
)
_LEADING_NAME = re.compile(rf"[ \t]*{_TITLE}(?P<v>{NAME_WORD}{_NAME_TAIL}{{0,2}})")


# Keywords that must occur before a rule is worth running. Plain substring tests
# on the lowercased text run in C; a case-insensitive pattern scanned over a log
# block would cost as much as the rest of the anonymizer together.
_HINT_WORDS = {
    "header": ("von:", "an:", "cc:", "from:", "to:", "absender", "empfänger"),
    "salutation": (
        "herr", "frau", "hr.", "fr.", "mr", "ms", "miss", "mx", "monsieur", "madame", "mme", "mlle", "sig",
        "señor", "señora", "sr.", "sra.", "dhr.", "mevr.", "meneer", "mevrouw",
    ),
    "greeting": (
        "hallo", "hello", "hi ", "hey", "moin", "servus", "liebe", "dear", "guten ", "good ", "bonjour",
        "buongiorno", "buonasera", "ciao", "gentile", "caro", "cara", "hola", "estimad", "beste", "hej", "hoi",
    ),
    "closing": (
        "grüß", "grüss", "gruß", "gruss", "gruess", "regards", "wishes", "cheers", "mfg", "lg", "vg", "thanks",
        "sincerely", "faithfully", "truly", "saluti", "cordial", "saludo", "atentamente", "groet", "mvg",
        "hälsningar",
    ),
    "seat": ("sitz", "registered office"),
    "role": (
        "geschäftsführ", "vorstand", "inhaber", "ansprechpartner", "bearbeiter", "aufsichtsrat",
        "managing", "ceo", "cto", "kontakt", "contact",
    ),
    "wrote": ("schrieb", "wrote"),
}


# Two rules need a sharper test: "MAIL FROM:<…>" and "RCPT TO:<…>" stand in every
# SMTP log line, and "ms" hides in "items". Exact spellings run as one literal
# search in C instead of a case-insensitive scan.
_HINT_PATTERNS = {
    "header": re.compile(
        r"(?:Von|VON|von|An|AN|an|Cc|CC|cc|Bcc|BCC|From|FROM|from|To|TO|to|Absender|Empfänger)"
        r"[ \t]*:[ \t]*(?:\"|[^<\s])"
    ),
    "salutation": re.compile(rf"(?:{_ADDRESS_FORMS})[ \t\u00a0]"),
}


def _hinted(lowered: str, rule: str, text: str = "") -> bool:
    pattern = _HINT_PATTERNS.get(rule)
    if pattern is not None and text:
        return pattern.search(text) is not None
    return any(word in lowered for word in _HINT_WORDS[rule])


def learn(text: str) -> Findings:
    """Collect names and companies from the places where the text names them."""
    findings = Findings()
    lowered = text.lower()
    for address in _ADDRESS.finditer(text):
        before = text[max(0, address.start() - 90) : address.start()]
        # "MAIL FROM:<…>" in a log: no name can end in a colon, skip the search.
        tail = before.rstrip(" \t")[-1:]
        if tail == '"':
            match = _BEFORE_QUOTED.search(before)
        elif tail.isalpha() and before[-1:] in " \t":
            match = _BEFORE_PLAIN.search(before)
        else:
            continue
        if match:
            classify(match.group("v"), findings)
    if _hinted(lowered, "header", text):
        for match in _HEADER.finditer(text):
            classify(match.group("q") or match.group("v") or "", findings)
    if _hinted(lowered, "salutation", text):
        for match in _SALUTATION.finditer(text):
            words = clean_name(match.group("v") + (" " + match.group("w") if match.group("w") else ""))
            findings.add_name(words, "surname")
    if _hinted(lowered, "greeting"):
        for match in _GREETING.finditer(text):
            if _is_stop(match.group("v")):
                continue
            words = clean_name(match.group("v") + (" " + match.group("w") if match.group("w") else ""))
            findings.add_name(words, "first")
    if _hinted(lowered, "closing"):
        for match in _CLOSING.finditer(text):
            findings.add_name(clean_name(match.group("v")), "first")
    if _hinted(lowered, "role"):
        for match in _ROLE.finditer(text):
            first_names: list[str] = []
            for part in re.split(r",|;|/|&|(?<![\w])und(?![\w])|(?<![\w])and(?![\w])", match.group("v")):
                lead = _LEADING_NAME.match(part)
                words = clean_name(lead.group("v")) if lead else []
                if not words:
                    break  # the list of names has ended
                if len(words) == 1:
                    # "Ulf und Sven Mustermann": the surname comes with the last name.
                    first_names.append(words[0])
                    continue
                findings.add_name(words, "surname")
                for first in first_names:
                    findings.add_name([first, words[-1]], "surname")
                    findings.add_name([first], "first")
                first_names = []
    if _hinted(lowered, "seat"):
        for match in _SEAT.finditer(text):
            words = _words(match.group("v"))
            while len(words) > 1 and (_is_stop(words[-1]) or words[-1].islower()):
                words.pop()
            if words and not _is_stop(words[0]):
                _append(findings.city, " ".join(words))
    for word in _WROTE_WORD.finditer(text) if _hinted(lowered, "wrote") else ():
        after = _AFTER_WROTE.match(text, word.end())
        before = _BEFORE_WROTE.search(text[max(0, word.start() - 90) : word.start()])
        for match in (after, before):
            words = clean_name(match.group("v")) if match else []
            if len(words) >= 2:
                findings.add_name(words, "surname")
    return findings


# -- shapes that need no learning ------------------------------------------------

_STREET_SUFFIX = r"straße|strasse|str\.|weg|allee|gasse|chaussee"
_STREET_WORD = r"Straße|Strasse|Str\.|Weg|Allee|Platz|Gasse|Ring|Damm|Ufer|Chaussee|Markt|Graben|Steig|Stieg|Pfad|Kamp"
_HOUSE_NUMBER = r"\d{1,4}(?:[ \t]?[a-zA-Z](?![\w]))?(?:[ \t]?[-–/][ \t]?\d{1,4}[a-zA-Z]?)?(?![\w])"
STREET = re.compile(
    rf"(?<![\w-])(?:[{U}][{L}]+(?:-[{U}][{L}]+)*[ \t-]+(?:{_STREET_WORD})"
    rf"|[{U}][{L}]*(?:-[{U}]?[{L}]+)*(?:{_STREET_SUFFIX}))[ \t]?{_HOUSE_NUMBER}"
)
_CITY_NAME = rf"[{U}][{L}]+(?:[ \t-](?:[{U}][{L}]+|(?:an|am|im|in|ob|vor|der|dem|den|bei)(?=[ \t]))){{0,3}}"
CITY = re.compile(
    rf"(?m)(?<![\w-])(?:D|DE|A|AT|CH)-\d{{4,5}}[ \t]+{_CITY_NAME}"
    rf"|(?:^|(?<=[,|;])|(?<=[,|;][ \t]))[ \t]*\d{{5}}[ \t]+{_CITY_NAME}"
)
PHONE_INTERNATIONAL = re.compile(
    r"(?<![\w+])(?:\+|00(?=[1-9]\d{0,2}[ /.-]))[1-9]\d{0,2}(?:[ ./-]?\(0\))?(?:[ ./-]?\d){6,14}(?![\w])"
)
PHONE_LABELLED = re.compile(
    rf"(?:{_START}(?i:(?:tel(?:efon)?|fon|fax|telefax|mobil(?:funk)?|mobile|handy|phone|durchwahl|zentrale)"
    r"\.?)|(?<![\w])[TFMP][ \t]*:)[ \t]*[.:]?[ \t]*(?P<number>\+?\(?\d[\d \t./()-]{5,22}\d)"
)
# The court names the place of the company: "Amtsgericht Musterstadt HRB 12345"
# and "Amtsgericht Musterstadt: HRB 12345" go as one, the court alone as well.
_COURT = (
    rf"(?:Amtsgericht|Registergericht)[ \t]+[{U}][{L}]+(?:-[{U}][{L}]+)*"
    rf"(?:[ \t](?:am|an[ \t]der|im|in|ob)[ \t][{U}][{L}]+)?"
)
REGISTER = re.compile(
    rf"{_START}(?:(?:{_COURT}[ \t,:]+)?(?:HRB|HRA|GnR|VR)[ \t]?\d{{1,6}}(?:[ \t]?[A-Z]{{1,2}}(?![\w]))?"
    rf"|{_COURT}"
    r"|DE[ \t]?\d{9}|ATU[ \t]?\d{8}|CHE[- \t]?\d{3}[. \t]?\d{3}[. \t]?\d{3})"
    rf"(?![\d{L}_])"  # a capital glued on is the next word: "HRB 4711UST-ID"
)
IBAN = re.compile(r"(?<![\w])[A-Z]{2}\d{2}(?:[ \t]?[A-Z0-9]{4}){2,7}(?:[ \t]?[A-Z0-9]{1,3})?(?![\w])")
COMPANY = re.compile(rf"(?:(?<![\w&@.])|(?<=[{L}])(?=[{U}]))(?:[{U}0-9][\w&.+'-]*[ \t]+){{1,4}}(?:{LEGAL_FORMS})(?![\w])")


def valid_iban(value: str) -> bool:
    compact = re.sub(r"[ \t]", "", value)
    if not 15 <= len(compact) <= 34:
        return False
    rearranged = compact[4:] + compact[:4]
    digits = "".join(str(int(char, 36)) for char in rearranged)
    return int(digits) % 97 == 1


def phone_digits_ok(value: str) -> bool:
    return 7 <= sum(char.isdigit() for char in value) <= 15


def trim_city(value: str) -> str:
    """Drop a trailing word such as "Tel" that the city pattern swallowed."""
    words = _words(value)
    while len(words) > 2 and (_is_stop(words[-1]) or words[-1].islower()):
        words.pop()
    return " ".join(words)


def city_ok(value: str) -> bool:
    words = _words(value)
    return len(words) >= 2 and words[1].casefold() not in _NOT_A_CITY and not _is_stop(words[1])


class Span:
    """The part of a match object the replacement passes use."""

    __slots__ = ("_text", "_start", "_end")

    def __init__(self, text: str, start: int, end: int) -> None:
        self._text, self._start, self._end = text, start, end

    def group(self, index: int = 0) -> str:
        return self._text[self._start : self._end]

    def start(self) -> int:
        return self._start

    def end(self) -> int:
        return self._end

    def span(self) -> tuple[int, int]:
        return self._start, self._end


_CANDIDATE = re.compile(rf"(?<![{U}])[{U}]|(?<![\w])\d")
_ENDS_WORD = re.compile(rf"[{L}]")


class NameIndex:
    """Known names, companies and addresses, found by lookup instead of search.

    A pattern with one alternative per name gets slower with every name the
    store learns; here only the places where a capital letter or a digit opens
    a word are looked up, so a long store costs no more per line than a short
    one. Case matters on purpose: it lets "MusterErika Muster", glued together
    when a mail was flattened to plain text, still split at the capital letter.
    """

    def __init__(self, values) -> None:
        self._by_prefix: dict[str, list[str]] = {}
        for value in values:
            if len(value) < 3:
                continue
            for variant in {value, value.upper()} if len(value) >= 4 else {value}:
                self._by_prefix.setdefault(variant[:3], []).append(variant)
        for candidates in self._by_prefix.values():
            candidates.sort(key=len, reverse=True)

    def __bool__(self) -> bool:
        return bool(self._by_prefix)

    def finditer(self, text: str):
        position = 0
        for candidate in _CANDIDATE.finditer(text):
            start = candidate.start()
            if start < position:
                continue
            for value in self._by_prefix.get(text[start : start + 3], ()):
                end = start + len(value)
                if text.startswith(value, start) and not _ENDS_WORD.match(text, end):
                    yield Span(text, start, end)
                    position = end
                    break


_SINGLE_LETTER_LABEL = re.compile(r"(?<![\w])[TFMP][ \t]*:[ \t]*[+(\d]")
_PHONE_START = re.compile(r"\+[1-9]|00[1-9]")
_CITY_START = re.compile(rf"\d{{4,5}}[ \t]+[{U}]")
_LEGAL_WORDS = re.compile(rf"(?<![\w])(?:{LEGAL_FORMS})(?![\w])")
# Gates as plain literal alternatives: one C-level search each, no Python loop.
_GATE_CODES = re.compile(r"HR|VR|GnR|DE|ATU|CHE|gericht")
_GATE_ACCOUNT = re.compile(r"iban|konto|account|bankverbindung")
_GATE_LABEL = re.compile(r"tel|fon|fax|mobil|handy|phone|durchwahl|zentrale")
_GATE_STREET_LOWER = re.compile(r"straße|strasse|str\.|weg|allee|gasse|chaussee")
_GATE_STREET_WORD = re.compile(r"Platz|Ring|Damm|Ufer|Markt|Graben|Steig|Stieg|Pfad|Kamp")


def wanted_passes(line: str) -> set[str]:
    """Which replacement passes can find anything in this line at all.

    A log line usually rules everything out here, without any of the full
    patterns running over it.
    """
    wanted: set[str] = set()
    lowered = line.lower()
    if _GATE_CODES.search(line):
        wanted.add("register")
    if _GATE_ACCOUNT.search(lowered):
        wanted.add("iban")
    if _GATE_LABEL.search(lowered) or (":" in line and _SINGLE_LETTER_LABEL.search(line)):
        wanted.add("phone_labelled")
    if ("+" in line or "00" in line) and _PHONE_START.search(line):
        wanted.add("phone")
    if _GATE_STREET_LOWER.search(lowered) or _GATE_STREET_WORD.search(line):
        wanted.add("street")
    if _CITY_START.search(line):
        wanted.add("city")
    if _LEGAL_WORDS.search(line):
        wanted.add("company")
    return wanted
