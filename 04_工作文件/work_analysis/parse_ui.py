import re

txt = open(r'C:\Users\dev\Desktop\work_analysis\ui_cur.xml', encoding='utf-8', errors='replace').read()

nodes = re.findall(r'<node[^>]*/?>', txt)
for n in nodes:
    t = re.search(r'text="([^"]*)"', n)
    b = re.search(r'bounds="(\[[^\"]+\])"', n)
    c = 'clickable="true"' in n
    if t and t.group(1) and b:
        mark = ' [CLICK]' if c else ''
        print(f'{t.group(1)!r:24s} {b.group(1):22s}{mark}')
