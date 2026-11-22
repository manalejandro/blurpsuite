import re, html, json, os

def clean(s):
    s = re.sub(r'<[^>]+>', '', s)
    s = html.unescape(s).replace('\u00a0', ' ')
    return re.sub(r'\s+', ' ', s).strip()

def first_code(fragment):
    m = re.search(r'<code>(.*?)</code>', fragment, re.S)
    return clean(m.group(1)) if m else clean(fragment)

def description(fragment):
    m = re.search(r'<div class="block">(.*?)</div>', fragment, re.S)
    return clean(m.group(1)) if m else ''

def tables_for(src, kind):
    return [t for t in re.findall(r'<table class="memberSummary".*?</table>', src, re.S)
            if kind.lower() in t[:700].lower()]

consts = {}
cv = open('constant-values.html').read()
for row in re.findall(r'<tr[^>]*>(.*?)</tr>', cv, re.S):
    a = re.search(r'name="(burp\.[A-Za-z]+\.[A-Z_]+)"', row)
    if not a: continue
    tds = re.findall(r'<td[^>]*>(.*?)</td>', row, re.S)
    if len(tds) >= 3: consts[a.group(1)] = clean(tds[2])

result = {}
for fn in sorted(os.listdir('burp')):
    if not fn.endswith('.html'): continue
    name = fn[:-5]
    src = open(os.path.join('burp', fn), encoding='utf-8', errors='replace').read()

    supers = []
    m = re.search(r'<pre>(.*?)</pre>', src, re.S)
    if m:
        h = clean(m.group(1))
        if ' extends ' in h or h.startswith('extends '):
            tail = h.split('extends', 1)[1].split('implements')[0]
            supers = [x.strip() for x in tail.split(',') if x.strip()]

    fields = []
    for tbl in tables_for(src, 'Field Summary'):
        for row in re.findall(r'<tr[^>]*>(.*?)</tr>', tbl, re.S):
            tds = re.findall(r'<td[^>]*>(.*?)</td>', row, re.S)
            if len(tds) >= 2:
                fld = first_code(tds[1])
                if re.match(r'^[A-Z][A-Z0-9_]*$', fld):
                    declared = clean(tds[0]).replace('static', '').replace('final', '').strip()
                    field_type = declared.split()[-1] if declared else 'int'
                    fields.append({'name': fld, 'type': field_type,
                                   'value': consts.get(f'burp.{name}.{fld}')})

    methods = []
    for tbl in tables_for(src, 'Method Summary'):
        for row in re.findall(r'<tr[^>]*>(.*?)</tr>', tbl, re.S):
            tds = re.findall(r'<td[^>]*>(.*?)</td>', row, re.S)
            if len(tds) >= 2:
                decl = first_code(tds[1])
                if '(' in decl and ')' in decl:
                    methods.append({'signature': clean(tds[0]) + ' ' + decl,
                                    'description': description(tds[1])})

    result[name] = {'extends': supers, 'fields': fields, 'methods': methods}

json.dump(result, open('api-contract.json','w'), indent=2)
for n, d in result.items():
    print(f'{n}: extends={d["extends"]} fields={len(d["fields"])} methods={len(d["methods"])}')
