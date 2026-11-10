"""Offline HTML5/CSS parsing for structural, script-free archive recovery."""

import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

import html5lib
import tinycss2

TAGS = {"div", "span", "p", "h2", "h3", "h4", "ul", "ol", "li", "strong", "em", "b", "i", "br", "a", "textarea", "img"}
DROP = {"script", "style", "iframe", "object", "embed", "form", "input", "button", "svg", "math", "noscript"}
TOKEN = re.compile(r"^[A-Za-z0-9_-]+$")
FUNCTIONS = {"rgb", "rgba", "hsl", "hsla", "calc", "min", "max", "clamp", "rect", "linear-gradient", "repeating-linear-gradient", "-webkit-gradient", "-webkit-linear-gradient", "-moz-linear-gradient", "from", "to", "color-stop"}
UNSAFE = re.compile(r"https?:|ftp:|data:|javascript:|vbscript:|expression|behavior|-moz-binding|progid|image-set", re.I)


class StaticRecovery:
    def __init__(self, images):
        self.images = images
        self.missing = []
        self.dropped = []
        self.inline_rules = []

    def resolve_image(self, value, origin):
        url = urlsplit(value)
        if not url.scheme and not url.netloc:
            candidate = (origin.parent / unquote(url.path)).resolve()
            if candidate in self.images:
                return self.images[candidate]
        # Archival absolute URLs can be matched only to an unambiguous local
        # basename. No URL is downloaded, and ambiguity is reported as missing.
        name = Path(unquote(url.path)).name
        matches = {asset for path, asset in self.images.items() if path.name == name}
        if len(matches) == 1:
            return matches.pop()
        self.missing.append({"origin": str(origin), "reference": value})
        return None

    def values(self, values, origin):
        result = []
        for token in values:
            if token.type == "comment":
                continue
            if token.type == "url" or (token.type == "function" and token.lower_name == "url"):
                if token.type == "url":
                    value = token.value
                else:
                    args = [x for x in token.arguments if x.type not in ("whitespace", "comment")]
                    if len(args) != 1 or args[0].type != "string":
                        return None
                    value = args[0].value
                asset = self.resolve_image(value, origin)
                if asset is None:
                    return None
                result.extend(tinycss2.parse_component_value_list('url("/skyhome/assets/' + asset + '")'))
            elif token.type == "function":
                if token.lower_name not in FUNCTIONS:
                    return None
                nested = self.values(token.arguments, origin)
                if nested is None:
                    return None
                token.arguments = nested
                result.append(token)
            elif token.type in ("error", "at-keyword", "{} block", "[] block"):
                return None
            else:
                result.append(token)
        return result

    def declarations(self, content, origin):
        result = []
        for declaration in tinycss2.parse_declaration_list(content, skip_comments=True, skip_whitespace=True):
            if declaration.type != "declaration" or declaration.lower_name in ("filter", "-ms-filter", "behavior", "-moz-binding"):
                self.dropped.append({"origin": str(origin), "kind": "unsafe/unsupported declaration"})
                continue
            values = self.values(declaration.value, origin)
            if values is None:
                self.dropped.append({"origin": str(origin), "property": declaration.name})
                continue
            value = tinycss2.serialize(values)
            if any(char in value for char in "\\@<\x00") or UNSAFE.search(value):
                self.dropped.append({"origin": str(origin), "property": declaration.name})
                continue
            declaration.value = values
            result.append(declaration)
        return tinycss2.serialize(result)

    def css(self, path):
        result = []
        for rule in tinycss2.parse_stylesheet(path.read_text(encoding="utf-8-sig", errors="replace"), skip_comments=True, skip_whitespace=True):
            if rule.type != "qualified-rule":
                self.dropped.append({"origin": str(path), "kind": "at-rule or parse error"})
                continue
            selector = tinycss2.serialize(rule.prelude)
            if any(char in selector for char in "\\@<\x00") or "/*" in selector or UNSAFE.search(selector):
                continue
            declarations = self.declarations(rule.content, path)
            if declarations:
                result.append(selector + "{" + declarations + "}")
        return "\n".join(result)

    def html(self, path):
        document = html5lib.parse(path.read_text(encoding="utf-8-sig", errors="replace"), namespaceHTMLElements=False)

        def text_node(text):
            if not text or not text.strip():
                return []
            return [{"text": text[:4096]}]

        def convert(element):
            if not isinstance(element.tag, str) or element.tag in DROP:
                return []
            children = text_node(element.text)
            for child in element:
                children.extend(convert(child))
                children.extend(text_node(child.tail))
            if element.tag not in TAGS:
                return children
            node = {"tag": element.tag}
            if children:
                node["children"] = children
            if TOKEN.fullmatch(element.get("id", "")):
                node["id"] = element.get("id")
            classes = [x for x in element.get("class", "").split() if TOKEN.fullmatch(x)]
            if element.get("style"):
                declarations = self.declarations(element.get("style"), path)
                if declarations:
                    name = "recovered-inline-" + str(len(self.inline_rules))
                    classes.append(name)
                    self.inline_rules.append("." + name + "{" + declarations + "}")
            if classes:
                node["class"] = " ".join(classes)
            if element.tag == "img":
                asset = self.resolve_image(element.get("src", ""), path)
                if asset is None:
                    return []
                node["image"] = asset
            return [node]

        body = document.find("body")
        nodes = text_node(body.text)
        for element in body:
            nodes.extend(convert(element))
            nodes.extend(text_node(element.tail))
        return nodes
