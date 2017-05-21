from google.appengine.ext import db

# Comment entity


class Comment(db.Model):
    user_id = db.StringProperty(required=True)
    post_id = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    author = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name
