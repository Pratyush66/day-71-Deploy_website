import os
from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask import request

'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
ckeditor = CKEditor(app)
Bootstrap5(app)


# TODO: Configure Flask-Login


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


login_manager = LoginManager()
login_manager.init_app(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")

db = SQLAlchemy(model_class=Base)
db.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='x',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# CONFIGURE TABLES
class BlogPosts(db.Model):
    __tablename__ = 'blog'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author = relationship("Users", back_populates='posts')
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    comments = relationship("Comments", back_populates="parent_post")


# TODO: Create a User table for all your registered users. 
class Users(db.Model, UserMixin):
    # __table_name = 'parent_table'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)
    name: Mapped[str] = mapped_column(String(250), nullable=False)
    posts: Mapped['BlogPosts'] = relationship(back_populates='author')
    comments = relationship("Comments", back_populates="comment_author")


class Comments(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    comment_id: Mapped[int] = mapped_column(ForeignKey('users.id'), autoincrement=True)
    comment_author = relationship('Users', back_populates='comments')
    post_id: Mapped[int] = mapped_column(ForeignKey('blog.id'), autoincrement=True)
    parent_post = relationship('BlogPosts', back_populates='comments')
    text: Mapped[str] = mapped_column(String, nullable=False)


with app.app_context():
    db.create_all()


def admin_only(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        # The current_user.get_id() this returns a string '1' so we are checking in string format
        if current_user.get_id() != '1':
            return abort(403)
        return func(*args, **kwargs)

    return wrapper


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        if db.session.execute(db.select(Users).where(Users.email == request.form.get('email'))).scalar():
            flash("You have already signed up with that email, please login.")
            return redirect(url_for('login', logged_in=current_user))
        hashpass = generate_password_hash(request.form.get('password'), method='scrypt', salt_length=8)
        new_user = Users()
        new_user.email = request.form.get('email')
        new_user.password = hashpass
        new_user.name = request.form.get('name')
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('get_all_posts', logged_in=current_user))
    return render_template("register.html", form=RegisterForm(), logged_in=current_user)


# TODO: Retrieve a user from the database based on their email.
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        result = db.session.execute(db.select(Users).where(Users.email == request.form.get('email'))).scalar()
        if result:
            password = result.password
            if check_password_hash(password, request.form.get('password')):
                login_user(result)
                return redirect(url_for('get_all_posts', logged_in=current_user))
            else:
                flash('Wrong password, Try again!')
                return render_template('login.html', form=LoginForm(), logged_in=current_user)
        else:
            flash('E-mail does not exist, please try again.')
            return render_template('login.html', form=LoginForm(), logged_in=current_user)
    return render_template("login.html", form=LoginForm(), logged_in=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts', logged_in=current_user))


@app.route('/')
def get_all_posts():
    print(os.environ.get('FLASK_KEY'))
    result = db.session.execute(db.select(BlogPosts)).scalars()
    posts = result.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            requested_post = db.get_or_404(BlogPosts, post_id)
            new_comment = Comments(
                comment_author=current_user,
                parent_post=requested_post,
                text=request.form.get('comment')
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
        else:
            flash('You need to login or register to comment.')
            return redirect(url_for('login'))
    requested_post = db.session.get(BlogPosts, post_id)
    return render_template("post.html", post=requested_post, logged_in=current_user, comment_form=CommentForm())


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPosts(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
def edit_post(post_id):
    post = db.get_or_404(BlogPosts, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id, logged_in=current_user))
    return render_template("make-post.html", form=edit_form, is_edit=True, logged_in=current_user)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPosts, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts', logged_in=current_user))


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user)


if __name__ == "__main__":
    app.run(debug=True, port=5002)
