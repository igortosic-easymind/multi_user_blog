import os
import jinja2

template_dir = os.path.join(os.path.dirname(os.path.pardir), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir), autoescape=True)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


class Template:

    def render_str(self, template, **params):
        print template_dir
        return render_str(template, **params)
