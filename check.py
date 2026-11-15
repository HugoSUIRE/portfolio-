import sys, pathlib
from html.parser import HTMLParser
root = pathlib.Path(__file__).parent
errs = []
class P(HTMLParser):
    csp = False
    def handle_starttag(s, t, a):
        a = dict(a)
        if t == 'script': errs.append('balise <script> interdite')
        if t == 'meta' and (a.get('http-equiv') or '').lower() == 'content-security-policy': s.csp = True
        if 'style' in a: errs.append('style inline interdit (CSP)')
        if a.get('target') == '_blank' and 'noopener' not in (a.get('rel') or ''): errs.append('target=_blank sans noopener')
        for k in ('href', 'src'):
            v = a.get(k)
            if not v or v.startswith(('#', 'mailto:')): continue
            if v.startswith('http'):
                if k == 'src' or t == 'link': errs.append('ressource externe : ' + v)
            elif not (root / v).exists(): errs.append('fichier manquant : ' + v)
p = P(); p.feed((root / 'index.html').read_text(encoding='utf-8'))
if not p.csp: errs.append('CSP absente')
print('\n'.join(errs) or 'OK'); sys.exit(1 if errs else 0)
