"""Minimal HTML form extraction (stdlib only) for smoke tests."""
from html.parser import HTMLParser


class _P(HTMLParser):
    def __init__(self, want):
        super().__init__(convert_charrefs=True)
        self.want, self.forms, self.cur, self.depth_tpl = want, [], None, 0
        self.select, self.sel_first, self.textarea = None, None, None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "template":
            self.depth_tpl += 1
        if self.depth_tpl:
            return
        if tag == "form":
            self.cur = {"attrs": a, "data": []}
            self.forms.append(self.cur)
        if self.cur is None:
            return
        if tag == "input" and a.get("name"):
            if a.get("type") in ("checkbox", "radio"):
                if "checked" in a:
                    self.cur["data"].append((a["name"], a.get("value", "on")))
            else:
                self.cur["data"].append((a["name"], a.get("value", "")))
        elif tag == "select" and a.get("name"):
            self.select, self.sel_first, self.sel_val = a["name"], None, None
        elif tag == "option" and self.select:
            v = a.get("value")
            self._opt = {"v": v, "sel": "selected" in a, "text": ""}
        elif tag == "textarea" and a.get("name"):
            self.textarea = [a["name"], ""]

    def handle_data(self, data):
        if self.depth_tpl:
            return
        if self.textarea is not None:
            self.textarea[1] += data
        elif self.select and getattr(self, "_opt", None) is not None:
            self._opt["text"] += data

    def handle_endtag(self, tag):
        if tag == "template":
            self.depth_tpl -= 1
            return
        if self.depth_tpl:
            return
        if tag == "option" and self.select and getattr(self, "_opt", None) is not None:
            v = self._opt["v"] if self._opt["v"] is not None else self._opt["text"]
            if self.sel_first is None:
                self.sel_first = v
            if self._opt["sel"]:
                self.sel_val = v
            self._opt = None
        elif tag == "select" and self.select:
            self.cur["data"].append((self.select, self.sel_val if self.sel_val is not None else (self.sel_first or "")))
            self.select = None
        elif tag == "textarea" and self.textarea is not None:
            t = self.textarea[1]
            self.cur["data"].append((self.textarea[0], t[1:] if t.startswith("\n") else t))
            self.textarea = None
        elif tag == "form":
            self.cur = None


def forms(html):
    p = _P(None)
    p.feed(html)
    return p.forms
