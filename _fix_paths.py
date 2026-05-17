import os, re

BASE = r"C:\Users\emili\OneDrive\Desktop\ID_LOGIN\security"

# Mapping of old path → new path in Python files
replacements = [
    # Handle the os.path.join(_DIR, "...") pattern
    ('os.path.join(_DIR, "users.json")',    'os.path.join(_DIR, "data", "users.json")'),
    ('os.path.join(_DIR, "sessions.json")', 'os.path.join(_DIR, "data", "sessions.json")'),
    ('os.path.join(_DIR, "attempts.json")', 'os.path.join(_DIR, "data", "attempts.json")'),
    ('os.path.join(_DIR, "audit.log")',      'os.path.join(_DIR, "data", "audit.log")'),
    ('os.path.join(_DIR, "keys")',           'os.path.join(_DIR, "data", "keys")'),
]

py_files = [f for f in os.listdir(BASE) if f.endswith('.py')]
for fname in py_files:
    fpath = os.path.join(BASE, fname)
    with open(fpath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original = content
    for old, new in replacements:
        content = content.replace(old, new)
    
    if content != original:
        with open(fpath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Updated: {fname}")
    else:
        print(f"No change: {fname}")

print("\nDone. Checking current path constants:")
for fname in py_files:
    fpath = os.path.join(BASE, fname)
    with open(fpath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    path_lines = [l.strip() for l in lines if any(k in l for k in ['users', 'sessions', 'attempts', 'audit', 'keys', '.json', '.log', 'FILE', 'PATH', 'LOG'])]
    if path_lines:
        print(f"\n  {fname}:")
        for l in path_lines[:10]:
            print(f"    {l}")
