from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, Login, Register, Comment
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    use_ssl=False,
                    base_url=None)
##CONFIGURE TABLES
@login_manager.user_loader
def load_user(user_id):
    return UserInfo.query.get(int(user_id))

def admin(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.id == 1:
            return func(*args, **kwargs)
        else:
            return abort(403)
    return decorated_function
class UserInfo(db.Model, UserMixin):
    __tablename__ = "user_info"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250),  unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    post = relationship("BlogPost", back_populates="author")
    comment = relationship("comments", back_populates="author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = relationship("UserInfo", back_populates="post")
    author_id = db.Column(db.Integer, db.ForeignKey("user_info.id"))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    comment = relationship("comments", back_populates="parent_post")
    img_url = db.Column(db.String(250), nullable=False)

class comments(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author = relationship("UserInfo", back_populates="comment")
    author_id = db.Column(db.Integer, db.ForeignKey("user_info.id"))
    text = db.Column(db.Text, nullable=False)
    parent_post = relationship("BlogPost", back_populates="comment")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))

    # def get_comment(self):
    #     for i in self.__table__.__colunms__:

# db.create_all()

def check(email):
    result = db.session.query(UserInfo).filter_by(email=email).first()
    return result




@app.route('/register', methods=["GET", "POST"])
def register():
    form = Register()
    if request.method == "POST":
        if form.validate_on_submit():
            name = form.name.data
            email = form.email.data
            result = check(email)
            if result == None:
                password = form.password.data
                hash = generate_password_hash(
                    password=password,
                    method= "pbkdf2:sha256",
                    salt_length=8)
                new_user = UserInfo(
                    name = name,
                    email = email,
                    password = hash,
                )
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                return redirect(url_for('get_all_posts'))
            flash("Plase Login you'r email is already register.")
            return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = Login()
    if request.method == "POST":
        if form.validate_on_submit():
            result = check(form.email.data)
            if result != None:
                if check_password_hash(result.password, form.password.data) :
                    login_user(result)
                    return redirect(url_for('get_all_posts'))
                error = "Password Wrong"
            else:
                error = "Register First!"
            return render_template("login.html", error=error, form=form)

    return render_template("login.html", form=form)
@app.route('/')

def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)

@app.route('/logout')

def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])

def show_post(post_id):
    form = Comment()
    requested_post = BlogPost.query.get(post_id)
    user_data = comments.query.all()

    if request.method == "POST":
        print(current_user)
        if form.validate_on_submit():
            try:
                comment = comments(
                    text = form.body.data,
                    author_id = current_user.id,
                    post_id = post_id
                )
                db.session.add(comment)
                db.session.commit()
                return redirect(url_for("show_post", post_id=post_id))
            except AttributeError:
                flash("Login First")
                return redirect(url_for("login"))
    return render_template("post.html", post=requested_post, form=form, user_data = user_data, gravatar=gravatar)


@app.route("/about")
@login_required
def about():
    return render_template("about.html")


@app.route("/contact")
@login_required
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@login_required
@admin
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body,
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@login_required
@admin
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
