#!/usr/bin/env python3
"""Check manual coverage and local document/fragment links using Python 3 only.

Run: python3 docs/_meta/check_links.py
"""
import html.parser
import json
import pathlib
import re
import sys
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[1]


class HTMLLinks(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get("id"):
            self.ids.add(attrs["id"])
        if tag == "a" and attrs.get("name"):
            self.ids.add(attrs["name"])
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])


def strip_code(text):
    text = re.sub(r"(?ms)^(`{3,}|~{3,})[^\n]*\n.*?^\1\s*$", "", text)
    return re.sub(r"(`+)(.*?)\1", "", text, flags=re.S)


def heading_id(text):
    text = re.sub(r"<[^>]+>", "", text).lower().strip()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


documents = {}
errors = []
for path in sorted(ROOT.rglob("*.md")):
    text = path.read_text(encoding="utf-8")
    parser = HTMLLinks()
    parser.feed(strip_code(text))
    parser.ids.update(heading_id(m[1]) for m in re.finditer(r"(?m)^#{1,6}\s+(.+?)\s*#*\s*$", text))
    parser.links.extend(m[1] for m in re.finditer(r"\[[^\]\n]*\]\(([^\s)]+)(?:\s+[^)]*)?\)", strip_code(text)))
    documents[path.resolve()] = parser
    if re.search(r"PINTOS(?:REF|UNIT|ANCHOR)\d+", text):
        errors.append("{}: unresolved translation marker".format(path.relative_to(ROOT)))

manifest = json.loads((ROOT / "_meta/sources.json").read_text(encoding="utf-8"))
for page in manifest["pages"]:
    path = (ROOT / page["translation_path"]).resolve()
    if path not in documents:
        errors.append("Missing translation: " + page["translation_path"])
    else:
        missing = set(page["source_heading_ids"]) - documents[path].ids
        if missing:
            errors.append("{}: missing source anchors {}".format(page["translation_path"], sorted(missing)))

link_count = 0
for path, parser in documents.items():
    for href in parser.links:
        url = urllib.parse.urlsplit(href)
        if url.scheme or url.netloc:
            continue
        link_count += 1
        target = (path.parent / urllib.parse.unquote(url.path)).resolve() if url.path else path
        if not target.is_relative_to(ROOT.resolve()) or not target.is_file():
            errors.append("{}: missing local target {}".format(path.relative_to(ROOT), href))
        elif url.fragment and target in documents and urllib.parse.unquote(url.fragment) not in documents[target].ids:
            errors.append("{}: missing fragment {}".format(path.relative_to(ROOT), href))

for error in errors:
    print(error)
print("{} source pages; {} Markdown files; {} local links; {} errors".format(manifest["document_count"],len(documents),link_count,len(errors)))
sys.exit(bool(errors))
