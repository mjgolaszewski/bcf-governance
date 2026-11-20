"""Offline public-API observations; never a native security approval.

Cases follow CPython GH-161570 and GH-161711 (PSF upstream regression scope).
"""
import hashlib
from email.message import Message
import http.cookiejar
import http.cookies
import json
import os
from pathlib import Path
import platform
import sys
from urllib.request import Request


def receive(jar, url, header):
    message = Message()
    message.add_header('Set-Cookie', header)

    class Response:
        def info(self):
            return message

    jar.extract_cookies(Response(), Request(url))


def seed(policy=None, path='/'):
    jar = http.cookiejar.CookieJar(policy)
    receive(jar, 'http://www.victim.test' + path,
        'session=fixture-value; Domain=.victim.test; Path=' + path.rstrip('/') if path != '/' else
        'session=fixture-value; Domain=.victim.test; Path=/')
    assert len(jar) == 1, 'benign cookie setup failed'
    return jar


def main():
    cookiejar = []
    for domain in ('.victim.test', 'victim.test'):
        for expiry in ('Max-Age=0', 'Expires=Thu, 01 Jan 1970 00:00:00 GMT'):
            jar = seed()
            receive(jar, 'http://www.attacker.test/',
                f'session=x; Domain={domain}; Path=/; {expiry}')
            cookiejar.append(dict(case='foreign_domain', domain=domain, expiry=expiry,
                protected_cookie_retained=len(jar) == 1))
    jar = seed()
    receive(jar, 'http://www.victim.test/', 'session=x; Domain=.victim.test; Path=/; Max-Age=0')
    assert len(jar) == 0, 'benign same-domain deletion failed'
    policy = http.cookiejar.DefaultCookiePolicy(strict_ns_set_path=True)
    jar = seed(policy, '/a/')
    receive(jar, 'http://www.victim.test/b/', 'session=x; Domain=.victim.test; Path=/a; Max-Age=0')
    cookiejar.append(dict(case='foreign_path', protected_cookie_retained=len(jar) == 1))
    jar = seed(policy, '/a/')
    receive(jar, 'http://www.victim.test/a/', 'session=x; Domain=.victim.test; Path=/a; Max-Age=0')
    assert len(jar) == 0, 'benign same-path deletion failed'
    jar = seed()
    jar.set_policy(http.cookiejar.DefaultCookiePolicy(blocked_domains=['.victim.test']))
    receive(jar, 'http://www.victim.test/', 'session=x; Domain=.victim.test; Path=/; Max-Age=0')
    cookiejar.append(dict(case='blocked_policy', protected_cookie_retained=len(jar) == 1))
    jar = seed()
    jar.set_policy(http.cookiejar.DefaultCookiePolicy(blocked_domains=['.victim.test']))
    jar.set_policy(http.cookiejar.DefaultCookiePolicy())
    receive(jar, 'http://www.victim.test/', 'session=x; Domain=.victim.test; Path=/; Max-Age=0')
    assert len(jar) == 0, 'restored ordinary policy deletion failed'

    morsel = []
    for attribute in http.cookies.Morsel._reserved:
        if attribute == 'comment':
            continue
        for route in ('assignment', 'setdefault', 'update', 'ior'):
            value = http.cookies.Morsel()
            try:
                if route == 'assignment':
                    value[attribute] = 'foo; SameSite=none'
                elif route == 'setdefault':
                    value.setdefault(attribute, 'foo; SameSite=none')
                elif route == 'update':
                    value.update({attribute: 'foo; SameSite=none'})
                else:
                    value |= {attribute: 'foo; SameSite=none'}
            except http.cookies.CookieError:
                rejected = True
            else:
                rejected = False
            morsel.append(dict(attribute=attribute, route=route, rejected=rejected))
    ordinary = http.cookies.Morsel()
    ordinary.set('key', 'value', 'value')
    ordinary.update({'domain':'example.test', 'path':'/', 'samesite':'Lax'})
    rendered = ordinary.OutputString()
    assert all(value in rendered for value in ('Domain=example.test', 'Path=/', 'SameSite=Lax'))
    comment = http.cookies.Morsel()
    comment.set('key', 'value', 'value')
    comment['comment'] = 'note;SameSite=none'
    assert r'\073' in comment.OutputString(), 'ordinary comment escaping failed'
    modules = {}
    for module in (http.cookiejar, http.cookies):
        source = Path(module.__file__)
        cached = Path(module.__cached__) if module.__cached__ else None
        modules[module.__name__] = dict(reported_source_origin=str(source),
            source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
            cached_bytecode_sha256=hashlib.sha256(cached.read_bytes()).hexdigest()
                if cached is not None and cached.is_file() else None)
    print(json.dumps(dict(authority=False,security_qualified=False,runtime_context_qualified=False,
        interpreter=dict(version=platform.python_version(),implementation=platform.python_implementation(),
            isolated=sys.flags.isolated,ignore_environment=sys.flags.ignore_environment,
            no_user_site=sys.flags.no_user_site,dont_write_bytecode=sys.dont_write_bytecode),
        environment=dict(os.environ),modules=modules,cookiejar=cookiejar,morsel=morsel,
        positive_controls=dict(same_domain_delete=True,same_path_delete=True,
            restored_policy_delete=True,ordinary_attributes=True,comment_escaping=True)),sort_keys=True))


if __name__ == "__main__":
    main()
