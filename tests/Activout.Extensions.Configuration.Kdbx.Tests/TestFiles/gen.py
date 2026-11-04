import base64, sys, uuid
from xml.sax.saxutils import escape
def u(): return base64.b64encode(uuid.uuid4().bytes).decode()
RB = u()
def s(k, v, prot=False):
    p = ' ProtectInMemory="True"' if prot else ''
    return f"<String><Key>{escape(k)}</Key><Value{p}>{escape(v)}</Value></String>"
def entry(title, pw="", user="", url="", notes="", custom=(), tags="", expires=None):
    t = f'<Times><Expires>{"True" if expires else "False"}</Expires>' + (f'<ExpiryTime>{expires}</ExpiryTime>' if expires else '') + '</Times>'
    return (f'<Entry><UUID>{u()}</UUID><Tags>{tags}</Tags>{t}' + s("Title", title) + s("UserName", user) + s("Password", pw, True)
            + s("URL", url) + s("Notes", notes) + ''.join(s(k, v, p) for k, v, p in custom) + '</Entry>')
def group(name, *children, uid=None):
    return f'<Group><UUID>{uid or u()}</UUID><Name>{escape(name)}</Name>' + ''.join(children) + '</Group>'
def doc(root):
    return (f'<?xml version="1.0" encoding="utf-8"?><KeePassFile><Meta><Generator>gen</Generator><DatabaseName>Test</DatabaseName>'
            f'<RecycleBinEnabled>True</RecycleBinEnabled><RecycleBinUUID>{RB}</RecycleBinUUID></Meta><Root>{root}</Root></KeePassFile>')
if sys.argv[1] == "mapping":
    print(doc(group("Root",
        entry("TopLevel", pw="top-secret"),
        group("Database", entry("Main", pw="Server=db;Password=x", user="app")),
        group("Api", group("Stripe", entry("SecretKey", pw="sk_test_123", custom=[("Endpoint", "https://api.example.com", False), ("Token", "tok-protected", True), ("Empty", "", False)]))),
        group("Empty", entry("NoPassword", user="only-user"), entry("AllEmpty")),
        group("Tagged", entry("Prod", pw="p1", tags="prod;web"), entry("Dev", pw="d1", tags="dev")),
        group("Expiry", entry("Expired", pw="old", expires="2001-01-01T00:00:00Z"), entry("Future", pw="new", expires="2099-01-01T00:00:00Z")),
        group("Special", entry("A:B", pw="colon"), entry("Räksmörgås & <ok>", pw="å\"ä'ö", notes="line1\nline2", url="https://example.com/x?y=1&z=2")),
        group("Recycle Bin", entry("Old", pw="deleted"), uid=RB))))
else:
    print(doc(group("Root",
        group("Database", entry("Main", pw="first")),
        group("database", entry("main", pw="second")))))
