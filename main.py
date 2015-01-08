import os
import json
import logging
import webapp2
import jinja2
import hashlib
import datetime
import hmac
from google.appengine.ext import db


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)


# Hashing Functions

def hash_str(s):
    return hmac.new("mYsECRETcODE", s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split("|")[0]
    if h == make_secure_val(val):
        return val

# Password hashing Functions

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
    if salt == None:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    if make_pw_hash(name, pw, salt) == h:
        return True

def flushCache():
    CACHE.clear()

CACHE = {}

def top_entries():
    key = 'top'
    if 'dateKey' in CACHE:
        dateCached = CACHE['dateKey']
    else:
        dateCached = datetime.datetime.today()
        CACHE['dateKey'] = dateCached

    if key in CACHE:
        entries = CACHE[key]
    else:
        entries = db.GqlQuery("SELECT * FROM Blog "
                              "ORDER BY submitted DESC " 
                              "limit 10")
        CACHE[key] = entries
    return entries

def postPageQuery(postPage):
    if postPage in CACHE:
        return CACHE[postPage]
    else:
        CACHE[postPage] = {}
        CACHE[postPage]['entry'] = Blog.get_by_id(postPage)
        CACHE[postPage]['cacheTime'] = datetime.datetime.today()
        return  CACHE[postPage]


# Database Classes

class Blog(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    submitted = db.DateTimeProperty(auto_now_add = True)

    def as_dict(self):
        time_fmt = '%c'
        d = {'subject': self.subject,
             'content': self.content,
             'created': self.submitted.strftime(time_fmt)}
        return d

class User(db.Model):
    userName = db.StringProperty(required = True)
    userPassword = db.StringProperty(required = True)
    userEmail = db.StringProperty(required = False)

# Handler

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d):
        json_text = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_text)

# Page Handler functions

class MainPage(Handler):
    def get(self):
        visits = 0
        userName = ""

        visit_cookie_str = self.request.cookies.get('visits')
        userName = self.request.cookies.get('username')
        if userName:
            userName = userName.split('|')[0]

        if visit_cookie_str:
            cookie_val = check_secure_val(visit_cookie_str)
            if cookie_val:
                visits = int(cookie_val)

        visits += 1

        new_cookie_val = make_secure_val(str(visits))

        self.response.headers.add_header('Set-Cookie', 'visits=%s' % new_cookie_val)

        entries = top_entries()

        cacheDate = CACHE['dateKey']

        now = datetime.datetime.today()

        deltaSeconds = int(round((now - cacheDate).total_seconds()))
        entries = list(entries)

        self.render("homepage.html", entries=entries, visits=visits, userName=userName, cacheSeconds=deltaSeconds)

class MainJSON(Handler):
    def get(self):

        entries = db.GqlQuery("SELECT * FROM Blog "
                              "ORDER BY submitted DESC limit 10")

        entries = list(entries)

        self.render_json([e.as_dict() for e in entries])

class PostPageJSON(Handler):
    def get(self, num):

        num = self.request.url
        num = num.split('/')[-1]
        num = num.split('.')[-2]
        entry = Blog.get_by_id(int(num))

        self.render_json([entry.as_dict()])

class PostPage(Handler):
    def get(self, num):
        
        entryAndDate = postPageQuery(int(num))
        entry = entryAndDate['entry']
        cacheDate = entryAndDate['cacheTime']
        now = datetime.datetime.today()
        deltaSeconds = int(round((now - cacheDate).total_seconds()))
        subject = entry.subject
        content= entry.content
        self.render("identry.html", subject=subject, content=content, id=num, cacheSeconds=deltaSeconds)

class Welcome(Handler):     
    def get(self):

        userName = self.request.cookies.get('username')
        userName = userName.split('|')[0]

        self.render("welcome.html", userName=userName)

class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'username=; path=/')
        self.redirect('/')

class Login(Handler):
    def render_login(self, userName="", error=""):
        self.render("login.html", userName=userName, error=error)

    def get(self):
        userName = self.request.cookies.get('username')

        if userName:
            self.redirect('/')

        self.render_login()

    def post(self):
        userName = self.request.get("username")
        password = self.request.get("password")

        valid_user = db.GqlQuery("SELECT * FROM User WHERE userName=:1", userName).get()

        if valid_user and valid_user.userName == userName and valid_user.userPassword == hash_str(userName + password):
            cookie_hash_val = hash_str(str(userName) + str(password))            
            self.response.headers.add_header('Set-Cookie', 'username=%s|%s' % (str(userName), cookie_hash_val))
            self.redirect('/welcome')
        else:
            error = "Invalid Login"
            self.render_login(userName=userName, error=error)


class Flush(Handler):
    def get(self):
        flushCache()
        self.redirect('/')


class NewPost(Handler):
    def render_newpost(self, subject="", content="", error=""):
        self.render("newpost.html", subject=subject, content=content, error=error)
    
    def get(self):
        userName = self.request.cookies.get('username')
        if not userName:
            self.redirect('/')
            
        self.render_newpost()
    
    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            entry = Blog(subject = subject, content = content)
            entry.put()
            num = entry.key().id()
            self.redirect('/'+str(num), num)
        else:
            error = "We need an entry and a subject"
            self.render_newpost(subject, content, error)

class SignUp(Handler):
    def render_signup(self, uname_error="", userName="", password_error="", email=""):
        self.render("signup.html", userName=userName, uname_error=uname_error, password_error=password_error, email=email)

    def get(self):
        self.render_signup()

    def post(self):
        password_error = ""
        uname_error = ""

        password = self.request.get("password")
        verify = self.request.get("verify")
        userName = self.request.get("username")
        email = self.request.get("email")

        if password and verify:
            if password != verify:
                password_error = "Password need to match"
        elif (password and not verify) or (verify and not password):
            password_error = "Need to enter password twice"
        else:
            password_error = "Enter Password"

        if not userName:
            uname_error = "Must supply user name"

        used = db.GqlQuery("SELECT * FROM User WHERE userName=:1", userName).get()

        if used:
            uname_error = "User Name already taken"

        if password_error != "" or uname_error != "":
            self.render_signup(uname_error=uname_error, userName=userName, password_error=password_error, email=email)
        elif password_error == "" and uname_error == "":
            hash_val = hash_str(str(userName) + str(password))
            self.response.headers.add_header('Set-Cookie', 'username=%s|%s' % (str(userName), hash_val))
            newUser = User(userName=userName, userPassword=hash_val, userEmail=hash_str(email))
            newUser.put()

            self.redirect('/welcome', userName)

pages = [('/', MainPage),
         ('/.json', MainJSON),
         ('/newpost', NewPost),
         ('/signup', SignUp),
         ('/welcome', Welcome),
         ('/([0-9]+)', PostPage),
         ('/([0-9]+).json', PostPageJSON),
         ('/login', Login),
         ('/logout', Logout),
         ('/flush', Flush)]

app = webapp2.WSGIApplication(pages, debug=True)