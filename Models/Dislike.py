from google.appengine.ext import db

# entities to maintain a record of users who have disliked a post


class Dislike(db.Model):
    user_id = db.StringProperty()
    post_id = db.StringProperty()

    def getLike_UserName(self):
        user = User.by_id(self.user_id)
        return user.name
