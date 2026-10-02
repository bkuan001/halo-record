import html, json

_REPORT_JS = "const data = %s;"
REPORT_HTML = "<h1>{}</h1>"

def render(name, data):
    # ruleid: halo-html-js-template-format
    js = _REPORT_JS % data
    # ruleid: halo-html-js-template-format
    page = REPORT_HTML.format(name)
    # ruleid: halo-html-js-template-format
    body_html = f"<p>{name}</p>"
    # ruleid: halo-html-js-template-format
    html_out = "<td>%s</td>" % name
    # ruleid: halo-html-js-template-format
    body_html += f"<li>{name}</li>"
    # ok: halo-html-js-template-format
    msg = "hello %s" % name
    # ok: halo-html-js-template-format
    label = f"user {name}"
    return js, page, body_html, html_out, msg, label
