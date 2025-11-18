from jinja2 import Template
alert = {'host': {'hostname': 'WIN-123', 'ip': '10.0.1.50'}}
print(Template("{{alert.host.hostname}}").render(alert=alert))