from google.appengine.ext import db
import Template
import User

# Post entity


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    user_id = db.StringProperty()
    last_modified = db.DateTimeProperty(auto_now=True)
    likes = db.StringProperty(default="0")
    dislikes = db.StringProperty(default="0")

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return Template.render_str("post.html", p=self)
