#!/usr/bin/env python3
"""Check repository Markdown links to local files and headings; no network calls."""
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

root = Path(__file__).resolve().parents[1]
files = [p for p in root.rglob('*.md') if not any(part in {'.git', '.venv', '.local', 'build', 'dist', 'node_modules'} for part in p.relative_to(root).parts)]
errors = []
count = 0
for source in files:
    content = re.sub(r'```.*?```', '', source.read_text(), flags=re.S)
    for link in re.findall(r'\]\(([^)]+)\)', content):
        target = link.split(' "', 1)[0].strip('<>')
        url = urlsplit(target)
        if url.scheme or url.netloc:
            continue
        count += 1
        path = (source.parent / unquote(url.path)).resolve() if url.path else source
        if not path.is_relative_to(root) or not path.exists():
            errors.append(f'{source.relative_to(root)}: missing {target}')
            continue
        if url.fragment and path.suffix == '.md':
            anchors = set()
            used = {}
            text = re.sub(r'```.*?```', '', path.read_text(), flags=re.S)
            for heading in re.findall(r'^#{1,6}\s+(.+?)\s*#*$', text, re.M):
                heading = re.sub(r'\[([^]]+)\]\([^)]+\)', r'\1', heading)
                slug = re.sub(r'[^\w\- ]', '', heading.lower()).replace(' ', '-')
                number = used.get(slug, 0)
                used[slug] = number + 1
                anchors.add(slug + (f'-{number}' if number else ''))
            anchors.update(re.findall(r'(?:id|name)=[\"\']([^\"\']+)', text))
            if unquote(url.fragment) not in anchors:
                errors.append(f'{source.relative_to(root)}: missing heading {target}')
for error in errors:
    print(error, file=sys.stderr)
print(f'Checked {count} local links in {len(files)} Markdown files; {len(errors)} errors.')
raise SystemExit(bool(errors))
