#!/usr/bin/env python3
"""Checks the translations of seedtunnel.

Every English message written in the code (first argument of the functions
that translate: t, say, section, ok, warn, err, die, run, confirm, doctor_*;
second argument of ask) must have its translation in lang/fr.txt, with the
same placeholders (%s, %d…) in the same order. Translations nobody uses any
more are reported too. Long texts (text_en_* functions) must exist in every
language, and every « text NAME » of the code must exist.

Usage: tests/i18n_check.py              check (status 1 if something is wrong)
       tests/i18n_check.py --missing    print the missing messages, ready to
                                        be translated in lang/fr.txt
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CODE = [ROOT / "seedtunnel.sh", *sorted((ROOT / "lib").glob("*.sh"))]
LANGUAGES = ["fr"]

FUNCTIONS = r"(?:t|say|section|ok|warn|err|die|run|confirm|doctor_ok|doctor_warn|doctor_error|doctor_title)"
LITERAL = r"""('[^']*'|"(?:[^"\\]|\\.)*")"""
# lookahead: calls inside other calls are found too
CALL = re.compile(r"(?<![\w-])" + FUNCTIONS + r"\s+(?=" + LITERAL + ")")
ASK = re.compile(r"(?<![\w-])ask\s+[A-Za-z_]+\s+(?=" + LITERAL + ")")
TEXT_CALL = re.compile(r"(?<![\w-])text\s+([a-z_]+)")
PLACEHOLDER = re.compile(r"%[-0-9.]*[sd]")


def unquote(literal):
    """Text of a bash string, or None if it holds an expansion ($, `)."""
    if literal[0] == "'":
        return literal[1:-1]
    body = literal[1:-1]
    if re.search(r"(?<!\\)[$`]", body):
        return None
    return re.sub(r"\\([\\\"$`])", r"\1", body)


def code_lines():
    for path in CODE:
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            yield path.relative_to(ROOT), number, line


def code_messages():
    messages = {}
    for path, number, line in code_lines():
        for regex in (CALL, ASK):
            for match in regex.finditer(line):
                text = unquote(match.group(1))
                if text:
                    messages.setdefault(text, f"{path}:{number}")
    return messages


def catalog(language):
    entries, english = {}, None
    path = ROOT / "lang" / f"{language}.txt"
    for line in path.read_text().splitlines():
        if line.startswith("en: "):
            english = line[4:]
        elif line.startswith(f"{language}: ") and english is not None:
            entries[english] = line[len(language) + 2:]
            english = None
    return entries


def text_functions(language):
    source = (ROOT / "lang" / f"{language}.sh").read_text()
    return set(re.findall(rf"^text_{language}_([a-z_]+)\(\)", source, re.M))


def main():
    problems = []
    messages = code_messages()
    for language in LANGUAGES:
        translations = catalog(language)
        missing = [m for m in messages if m not in translations]
        if "--missing" in sys.argv:
            for message in missing:
                print(f"en: {message}\n{language}: \n")
            return 0
        for message in missing:
            problems.append(f"{messages[message]}: no {language} translation for: {message}")
        for message in translations:
            if message not in messages:
                problems.append(f"lang/{language}.txt: translation no longer used: {message}")
            elif PLACEHOLDER.findall(message) != PLACEHOLDER.findall(translations[message]):
                problems.append(f"lang/{language}.txt: placeholders differ: {message}")
        english_texts, texts = text_functions("en"), text_functions(language)
        for name in sorted(english_texts - texts):
            problems.append(f"lang/{language}.sh: missing text_{language}_{name}")
        for name in sorted(texts - english_texts):
            problems.append(f"lang/{language}.sh: text_{language}_{name} has no English version")
    english_texts = text_functions("en")
    for path, number, line in code_lines():
        for name in TEXT_CALL.findall(line):
            if name not in english_texts:
                problems.append(f"{path}:{number}: unknown long text « {name} »")
    for problem in problems:
        print(problem)
    print(f"{len(messages)} messages, {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
