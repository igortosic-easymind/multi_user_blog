import re
import random
import hashlib
import hmac
from string import letters

import webapp2

from google.appengine.ext import db
from Models import User
from Models import Post
from Models import Like
from Models import Dislike
from Models import Comment
from Models import Template

secret = 'fart'


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# base class for handlers


class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = Template()
        return t.render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    # check if a particular user owns that post or not
    def users_own_post(self, user, post):
        return int(post.user_id) == user.key().id()

    # check is the post exists or not
    def post_exists(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return
        return post

    # check whether a user is currently logged in or not
    def user_logged_in(self, user):
        if not user:
            self.redirect('/login')
            return
        else:
            return True

    # check whether the user that comment or not
    def comment_exists(self, comm_id):
        key = db.Key.from_path('Comment', int(comm_id))
        comment = db.get(key)

        if not comment:
            self.error(404)
            return
        return comment


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class MainPage(BlogHandler):

    def get(self):
        self.write('Hello, Udacity!')

# blog stuff


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class BlogFront(BlogHandler):

    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts=posts)


class PostPage(BlogHandler):

    def get(self, post_id):
        post = self.post_exists(post_id)
        if post:
            postComm = Comment.all().filter('post_id =', post_id)
            self.render("permalink.html", post=post, comments=postComm)


class DeletePost(BlogHandler):

    def get(self, post_id):
        if self.user_logged_in(self.user):
            post = self.post_exists(post_id)
            if post:
                if self.users_own_post(self.user, post):
                    post.delete()
                    posts = greetings = Post.all().order('-created')
                    self.redirect('/blog/')
                else:
                    postComm = Comment.all().filter('post_id =', post_id)
                    self.render(
                        "permalink.html", post=post,
                        error="You don't have access to delete this record.",
                        comments=postComm)


class EditPost(BlogHandler):

    def get(self, post_id):
        if self.user_logged_in(self.user):
            post = self.post_exists(post_id)
            if post:
                if self.users_own_post(self.user, post):
                    self.render(
                        "editpost.html", subject=post.subject,
                        content=post.content)
                else:
                    postComm = Comment.all().filter('post_id =', post_id)
                    self.render(
                        "permalink.html", post=post,
                        error="You don't have access to edit this record.",
                        comments=postComm)

    def post(self, post_id):
        if not self.user:
            return self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        post = self.post_exists(post_id)
        if not post:
            return

        if not self.users_own_post(self.user, post):
            postComm = Comment.all().filter('post_id =', post_id)
            self.render("permalink.html", post=post,
                        error="You don't have access to edit this record.",
                        comments=postComm)
        elif subject and content:
            post.subject = subject
            post.content = content
            post.put()
            postComm = Comment.all().filter('post_id =', post_id)
            self.render("permalink.html", post=post, comments=postComm)
        else:
            error = "subject and content, please!"
            self.render(
                "editpost.html", subject=subject, content=content, error=error)

# create a new post


class NewPost(BlogHandler):

    def get(self):
        if self.user_logged_in(self.user):
            self.render("newpost.html")

    def post(self):
        if not self.user:
            return self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content)
            p.user_id = str(self.user.key().id())
            p.put()
            postComm = Comment.all().filter('post_id =', p.key().id())
            self.render("permalink.html", post=p, comments=postComm)
        else:
            error = "subject and content, please!"
            self.render(
                "newpost.html", subject=subject, content=content,
                error=error)


class LikePost(BlogHandler):

    def get(self, post_id):
        if self.user_logged_in(self.user):
            post = self.post_exists(post_id)
            if post:
                postComm = Comment.all().filter('post_id =', post_id)
                if self.users_own_post(self.user, post):
                    self.render(
                        "permalink.html", post=post,
                        error="You cannot like your own post",
                        comments=postComm)
                    return

                likes = Like.all()
                likes.filter('user_id =', str(self.user.key().id())).filter(
                    'post_id =', post_id)

                if likes.get():
                    self.render(
                        "permalink.html", post=post,
                        error="You have already liked the post",
                        comments=postComm)
                    return

                l = Like(user_id=str(self.user.key().id()), post_id=post_id)
                l.put()

                post.likes = str(int(post.likes) + 1)
                post.put()
                self.render("permalink.html", post=post, comments=postComm)


class DislikePost(BlogHandler):

    def get(self, post_id):
        if self.user_logged_in(self.user):
            post = self.post_exists(post_id)
            if post:
                postComm = Comment.all().filter('post_id =', post_id)
                if self.users_own_post(self.user, post):
                    return self.render(
                        "permalink.html",
                        post=post,
                        error="You cannot dislike your own post",
                        comments=postComm)

                dislikes = Dislike.all()
                dislikes.filter('user_id =', str(self.user.key().id())).filter(
                    'post_id =', post_id)

                if dislikes.get():
                    self.render(
                        "permalink.html", post=post,
                        error="You have already disliked the post",
                        comments=postComm)
                    return

                l = Dislike(user_id=str(self.user.key().id()), post_id=post_id)
                l.put()

                post.dislikes = str(int(post.dislikes) + 1)
                post.put()
                self.render("permalink.html", post=post, comments=postComm)

# posting a comment


class PostComment(BlogHandler):

    def get(self, post_id):
        if self.user_logged_in(self.user):
            post = self.post_exists(post_id)
            if post:
                postComm = Comment.all().filter('post_id =', post_id)
                self.render("permalink.html", post=post, comments=postComm)


class CommentPage(BlogHandler):

    def post(self, post_id):
        if self.user_logged_in(self.user):
            newComment = self.request.get("comment")
            if not newComment:
                self.render(
                    "permalink.html",
                    content=newComment,
                    error="enter valid content")
                return

            # create a new comments row and update the Comment entity
            c = Comment(user_id=str(self.user.key().id()),
                        post_id=post_id, comment=newComment,
                        author=self.user.name)
            c.put()

            post = self.post_exists(post_id)
            if post:
                postComm = Comment.all().filter(
                    'post_id =', post_id).order('-created')
                self.render("permalink.html", post=post, comments=postComm)


class DelComment(BlogHandler):

    def get(self, comm_id):
        if not self.user_logged_in(self.user):
            return

        comment = self.comment_exists(comm_id)
        if not comment:
            return

        post_id = comment.post_id
        post = self.post_exists(post_id)
        if not post:
            return

        if int(comment.user_id) == self.user.key().id():
            comment.delete()
            postComm = Comment.all().filter('post_id =', post_id)
            self.render("permalink.html", post=post, comments=postComm)
        else:
            postComm = Comment.all().filter('post_id =', post_id)
            self.render(
                "permalink.html",
                post=post,
                error="You can only delete the comments posted by you.!",
                comments=postComm)


class EditComment(BlogHandler):

    def get(self, comm_id):
        if not self.user_logged_in(self.user):
            return

        comment = self.comment_exists(comm_id)
        if not comment:
            return

        post = self.post_exists(comment.post_id)
        if not post:
            return
        postComm = Comment.all().filter(
            'post_id =', comment.post_id).order('-created')

        if int(comment.user_id) == self.user.key().id():
            self.render(
                "editcomment.html",
                post=post,
                content=comment.comment,
                comment=comment)
        else:
            self.render(
                "permalink.html",
                post=post,
                error="You can only edit the comments posted by you.!",
                comments=postComm)

    def post(self, comm_id):
        if not self.user_logged_in(self.user):
            return

        comment = self.comment_exists(comm_id)
        if not comment:
            return

        newComment = self.request.get("comment")
        if not newComment:
            error = "enter valid content"
            self.render("editcomment.html", content=newComment, error=error)
            return

        post = self.post_exists(comment.post_id)
        if not post:
            return

        # update the row and the Comment entity
        key = db.Key.from_path('Comment', int(comm_id))
        comment = db.get(key)
        comment.comment = newComment
        comment.put()

        postComm = Comment.all().filter(
            'post_id =', comment.post_id).order('-created')
        self.render("permalink.html", post=post, comments=postComm)

# Unit 2 HW's


class Rot13(BlogHandler):

    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text=rot13)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Unit2Signup(Signup):

    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)


class Register(Signup):

    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render(
                'signup-form.html', error_username=msg, username=self.username)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


class Login(BlogHandler):

    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg, username=username)


class Logout(BlogHandler):

    def get(self):
        self.logout()
        self.redirect('/blog')


class Unit3Welcome(BlogHandler):

    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


class Welcome(BlogHandler):

    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username=username)
        else:
            self.redirect('/unit2/signup')

# all the handlers for the webApp
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/rot13', Rot13),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/delpost/([0-9]+)', DeletePost),
                               ('/blog/like/([0-9]+)', LikePost),
                               ('/blog/dislike/([0-9]+)', DislikePost),
                               ('/blog/comment/([0-9]+)', PostComment),
                               ('/blog/commentPage/([0-9]+)', CommentPage),
                               ('/blog/editcomment/([0-9]+)', EditComment),
                               ('/blog/delcomment/([0-9]+)', DelComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ],
                              debug=True)
