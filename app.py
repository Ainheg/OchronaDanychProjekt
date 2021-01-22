from flask import Flask, render_template, url_for, request, flash, make_response, session
from flask_session import Session
from flask_recaptcha import ReCaptcha
from os import getenv
from dotenv import load_dotenv
from datetime import datetime, timedelta
from uuid import uuid4
from validation import *
from bcrypt import gensalt, hashpw, checkpw
from datetime import datetime, timedelta
import redis
import requests
from random import sample


load_dotenv()
db = redis.Redis(host = '192.168.0.222', port = 6379, db=0)

app = Flask(__name__)
SESSION_TYPE = 'redis'
SESSION_COOKIE_SECURE = True
SESSION_REDIS = db
PERMANENT_SESSION_LIFETIME = timedelta(minutes=5)
MAX_ATTEMPTS = 3
RECAPTCHA_SITE_KEY = getenv('RECAPTCHA_SITE')
RECAPTCHA_SECRET_KEY = getenv('RECAPTCHA_SECRET')
#Przeglądarki blokują ciastka z tagiem Secure
#wysłane z http
app.config.from_object(__name__)
app.secret_key = getenv('SECRET_KEY')
app.config.update({
    "RECAPTCHA_SITE_KEY": RECAPTCHA_SITE_KEY,
    "RECAPTCHA_SECRET_KEY": RECAPTCHA_SECRET_KEY,
    "RECAPTCHA_ENABLED": True
})
Session(app)
recaptcha = ReCaptcha(app)

def is_database_connected():
    return db.ping() if db else None

def is_user_in_database(username):
    if not is_database_connected():
        flash("Błąd połączenia z bazą danych")
        return None
    return db.hexists(f"ochrona:user:{username}", "password")

def redirect(url, status=301):
    response = make_response("", status)
    response.headers['Location'] = url
    return response

def verify_user(username, password):
    if not is_database_connected():
        flash("Błąd połączenia z bazą danych")
        return False
    hashed = db.hget(f"ochrona:user:{username}", "password")
    if not hashed:
        return False
    print(hashed, flush=True)
    return checkpw(password.encode(), hashed)

def register_user(username, password, email, birthday, q1, a1, q2, a2):
    if not is_database_connected():
        flash("Błąd połączenia z bazą danych")
        return False
    user = dict()
    user["password"] = hashpw(password.encode(), gensalt(14))
    user["email"] = email
    user["birthday"] = birthday
    user["q1"] = q1
    user["q2"] = q2
    user["a1"] = hashpw(a1.encode(), gensalt(14))
    user["a2"] = hashpw(a2.encode(), gensalt(14))
    success = False
    if db.hset(f"ochrona:user:{username}", mapping=user) == len(user):
        success = True
    return success

def update_password(username, password):
    if not is_database_connected():
        flash("Błąd połączenia z bazą danych")
        return False
    salt = gensalt(14)
    hashed = hashpw(password.encode(), salt)
    success = False
    if db.hset(f"ochrona:user:{username}", 'password', hashed) == 0:
        success = True
    return success


def check_answers(username, a1, a2):
    if not is_database_connected():
        flash("Błąd połączenia z bazą danych")
        return False
    if not is_user_in_database(username):
        return False
    reala1 = db.hget(f"ochrona:user:{username}", "a1")
    reala2 = db.hget(f"ochrona:user:{username}", "a2")
    checka1 = checkpw(a1.encode(), reala1)
    checka2 = checkpw(a2.encode(), reala2)
    return (checka1 and checka2)

def get_login_attempts(username):
    if not is_database_connected():
        flash("Błąd połączenia z bazą danych")
        return None
    return int(db.get(f"attempts:{username}"))

def add_login_attempt(username):
    if not is_database_connected():
        flash("Błąd połączenia z bazą danych")
        return None
    db.incr(f"attempts:{username}", 1)

def reset_login_attempts(username):
    if not is_database_connected():
        flash("Błąd połączenia z bazą danych")
        return None
    db.delete(f"attempts:{username}")
    try:
        session.pop('attempts')
    except:
        return None

def add_login_to_history(username, info):
    if not is_database_connected():
        flash("Błąd połączenia z bazą danych")
        return None
    db.hset(f"historia:{username}", datetime.now().strftime("%d/%m/%Y %H:%M:%S"), info)

def get_login_history(username):
    history = []
    if not is_database_connected():
        flash("Błąd połączenia z bazą danych")
        return history
    logins = db.hgetall(f'historia:{username}')
    if logins is not None:
        for key, value in logins.items():
            history.append(str(key.decode() + ' ' + value.decode()))
    return history

def get_safe_questions():
    return {"1":"W jakim mieście się urodziłeś(aś)?", "2":"Jak miał na imię twój pierwszy zwierzak?", "3":"Z którego roku był twój pierwszy samochód?"}

def is_user_logged_in():
    return 'username' in session

def current_user_info():
    if 'username' in session:
        return f'Jesteś zalogowany jako <a href="{url_for("panel")}">{session["username"]}</a>'
    return f'Nie jesteś zalogowany'

def check_user_birthday(username, bday):
    if not is_database_connected():
        flash("Błąd połączenia z bazą danych")
        return False
    if not username:
        flash("Wystąpił błąd")
        return False
    realbday = db.hget(f"ochrona:user:{username}", "birthday").decode()
    result = False
    if realbday is not None:
        result = (bday == realbday)
    return result

def retreive_user_questions(username):
    if not is_database_connected():
        flash("Błąd połączenia z bazą danych")
        return None
    if not is_user_in_database(username):
        q = sample(list(get_safe_questions().values()), 2)
        return q[0], q[1]
    q1db = db.hget(f"ochrona:user:{username}", "q1").decode()
    q2db = db.hget(f"ochrona:user:{username}", "q2").decode()
    if q1db is not None and q2db is not None:
        return get_safe_questions()[q1db], get_safe_questions()[q2db]
    return None

def add_note_to_database(note, notename, owner):
    if not is_database_connected():
        flash("Błąd połączenia z bazą danych")
        return False
    note_uid = str(uuid4())
    notename = notename + ":" + note_uid
    n = { 'id':note_uid, 'content':note, 'owner':owner, 'db_key':notename}
    db.hset(notename, mapping=n)
    return True

def get_current_user_notes():
    if not is_database_connected():
        flash("Błąd połączenia z bazą danych")
        return []
    notes = []
    public_notes = db.scan_iter("public_note:*")
    for n in public_notes:
        notes.append(db.hgetall(n))
    user = ""
    try:
        user = session['username']
    except:
        flash("Błąd autoryzacji, być może sesja wygasła")
        return False
    private_notes = db.scan_iter(f"private_note:*:{user}:*")
    for n in private_notes:
        notes.append(db.hgetall(n))
    notes = [{k.decode(): v.decode() for k, v in note.items()} for note in notes]
    return notes

def get_note_owner(key):
    if not is_database_connected():
        flash("Błąd połączenia z bazą danych")
        return None
    return db.hget(key, 'owner')

def delete_note_from_database(key):
    if not is_database_connected():
        flash("Błąd połączenia z bazą danych")
        return None
    items = db.hgetall(key)
    for item in items:
        db.hdel(key, item)
    return not get_note_owner(key)
    
@app.context_processor
def pass_to_templates():
    current_user=''
    try:
        current_user = session['username']
    except:
        return {"user_logged_in":is_user_logged_in, "user_info":current_user_info}
    return {"user_logged_in":is_user_logged_in, "user_info":current_user_info, "current_user":current_user}

@app.after_request
def add_headers(r):
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    return r

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods = ["GET"])
def sign_up():
    return render_template("signup.html", safe_questions=get_safe_questions())

@app.route("/register", methods = ["POST"])
def sign_up_process():
    if not validate_register_form(request.form):
        flash("Walidacja danych rejestracji nie powiodła się")
        return redirect(url_for("sign_up"))
    
    username = request.form.get("login")
    email = request.form.get("email")
    birthday = request.form.get("date")
    q1 = request.form.get('q1')
    q2 = request.form.get('q2')
    a1 = request.form.get('a1')
    a2 = request.form.get('a2')
    password = request.form.get("password")

    if is_user_in_database(username):
        flash(f"Użytkownik {username} jest już zarejestrowany")
        return redirect(url_for("sign_up"))
    if not (register_user(username, password, email, birthday, q1, a1, q2, a2)):
        flash("Błąd przy rejestracji użytkownika")
        return redirect(url_for("sign_up"))
    return redirect(url_for("sign_in"))

@app.route("/login", methods = ["GET"])
def sign_in(captcha_needed=False):
    captcha_needed = request.args.get('captcha_needed')
    captcha = False
    if captcha_needed == "True":
        captcha = True
    return render_template("login.html", is_captcha_needed=captcha)

@app.route("/login", methods = ["POST"])
def sign_in_process():
    try:
        session['attempts'] = session['attempts'] + 1
    except:
        session['attempts'] = 1
    if not validate_login_form(request.form):
        flash("Walidacja danych logowania się nie powiodła")
        return redirect(url_for("sign_in"))
    username = request.form.get("login")
    print(username, flush=True)
    password = request.form.get("password")
    print(password, flush=True)
    add_login_attempt(username)
    attempts = max(session['attempts'], get_login_attempts(username))
    captcha = False
    if attempts is not None:
        captcha = attempts > MAX_ATTEMPTS
    if captcha:
        if not recaptcha.verify():
            flash("Zbyt wiele nieudanych prób logowania, należy wypełnić Captcha")
            return redirect(url_for("sign_in", captcha_needed=captcha))
    if not (verify_user(username, password)):
        flash("Niepoprawna kombinacja nazwy uzytkownika i hasła")
        return redirect(url_for("sign_in", captcha_needed=captcha))
    session["username"] = username
    session["login-time"] = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    reset_login_attempts(username)
    try:
        info = request.remote_addr + ' ' + request.user_agent.browser
    except:
        info = 'Nie udało się uzyskać informacji (podejrzane!)'
    add_login_to_history(username, info)
    return redirect(url_for('panel'))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route("/register/username-check/<username>", methods = ["GET"])
def check_username(username):
    if is_user_in_database(username):
        return {'available':"no"}
    else:
        return {'available':"yes"}

@app.route("/panel", methods = ["GET"])
def panel():
    if not is_user_logged_in():
        flash("Obszar niedostępny dla niezalogowanych użytkowników")
        return redirect(url_for('sign_in'))
    return render_template("panel.html", notes=get_current_user_notes())

@app.route("/panel/password_change", methods = ["GET"])
def password_change():
    if not is_user_logged_in():
        flash("Obszar niedostępny dla niezalogowanych użytkowników")
        return redirect(url_for('sign_in'))
    return render_template("password_change.html")

@app.route("/panel/password_change", methods = ["POST"])
def password_change_process():
    if not is_user_logged_in():
        flash("Obszar niedostępny dla niezalogowanych użytkowników")
        return redirect(url_for('sign_in'))
    validation, old_pw_present = validate_pass_change_form(request.form)
    if old_pw_present:
        oldPw = request.form.get('oldPassword')
        if not verify_user(session.get('username'), oldPw):
            session.clear()
            flash("Błąd autoryzacji, zaloguj się ponownie")
            return redirect(url_for('sign_in'))
    if not validation:
        flash("Walidacja danych nie powiodła się")
        return redirect(url_for("panel"))
    password = request.form.get("password")
    repeatPassword = request.form.get("repeatPassword")
    success = update_password(session.get('username'), password)
    if not success:
        flash("Zmiana hasła nie udała się, spróbuj ponownie")
        return redirect(url_for('password_change'))
    flash("Zmiana hasła powiodła się, zaloguj się ponownie")
    session.clear()
    return redirect(url_for('sign_in'))

@app.route("/panel/history", methods = ["GET"])
def login_history():
    if not is_user_logged_in():
        flash("Obszar niedostępny dla niezalogowanych użytkowników")
        return redirect(url_for('sign_in'))
    return render_template("login_history.html", history=get_login_history(session['username']))

@app.route("/forgot_pw_request", methods = ["POST"])
def forgot_pw_request():
    if is_user_logged_in():
        flash("Obszar niedostępny dla zalogowanych użytkowników")
        return redirect(url_for('panel'))
    if not validate_pass_recovery_request_form(request.form):
        flash("Walidacja danych nie powiodła się")
        return redirect(url_for("sign_in"))
    username = request.form.get('login')
    birthday = request.form.get("date")
    error = False
    if is_user_in_database(username):
        if not check_user_birthday(username, birthday):
            flash("Niepoprawne nazwa użytkownika i/lub data urodzenia")
            error = True
    else:
        session["recovery"] = username
        return redirect(url_for("forgot_pw"))
    if error:
        return redirect(url_for("sign_in"))
    session["recovery"] = username
    return redirect(url_for("forgot_pw"))
@app.route("/forgot_pw", methods = ["GET"])
def forgot_pw():
    if is_user_logged_in():
        flash("Obszar niedostępny dla zalogowanych użytkowników")
        return redirect(url_for('panel'))
    try:
        username = session["recovery"]
    except:
        flash("Wystąpił błąd")
        return redirect(url_for('sign_in'))
    try:
        q1, q2 = retreive_user_questions(username)
    except TypeError:
        flash("Wystąpił błąd")
        return redirect(url_for('sign_in'))
    return render_template("account_recovery.html", username = username, q1 = q1, q2 = q2)
@app.route("/forgot_pw", methods = ["POST"])
def forgot_pw_process():
    username = session.pop('recovery', None)
    if not validate_pass_recovery_form(request.form):
        flash("Walidacja danych nie powiodła się")
        return redirect(url_for("sign_in"))
    if username is None:
        flash("Wystąpił błąd")
        return redirect(url_for('sign_in'))
    a1 = request.form.get('a1')
    a2 = request.form.get('a2')
    password = request.form.get("password")
    repeatPassword = request.form.get("repeatPassword")        
    are_answers_ok = check_answers(username, a1, a2)
    if not are_answers_ok:
        flash("Wystąpił błąd")
        return redirect(url_for('sign_in'))
    success = update_password(username, password)
    if not success:
        flash("Wystąpił błąd")
        return redirect(url_for('sign_in'))
    flash("Odzyskiwanie konta powiodło się, teraz możesz się zalogować")
    return redirect(url_for("sign_in"))

@app.route("/add_note", methods = ["POST"])
def add_note():
    if not is_user_logged_in():
        flash("Obszar niedostępny dla niezalogowanych użytkowników")
        return redirect(url_for('sign_in'))
    owner = ""
    try:
        owner = session['username']
    except:
        flash("Błąd autoryzacji, być może sesja wygasła")
        return redirect(url_for('panel'))
    note_name = ""
    error = False
    note_type = request.form.get('type')
    if not note_type:
        flash("Nie wybrano typu notatki")
        error = True
    if note_type == 'private':
        note_name = f"private_note::{owner}:"
        usernames = request.form.get('usernames')
        if usernames:
            note_name = note_name + usernames.replace(",", ":")
    elif note_type == 'public':
        note_name = f"public_note::{owner}:"
    else:
        flash('Niepoprawny typ notatki')
        error = True
    note_text = request.form.get('note')
    if not note_text:
        flash("Brak treści notatki")
        error = True
    if error:
        return redirect(url_for('panel'))
    success = add_note_to_database(note_text, note_name + ":", owner)
    if not success:
        flash("Coś się, coś się popsuło i nie udało się dodać notatki")
    return redirect(url_for('panel'))

@app.route("/delete_note/<key>", methods = ["POST"])
def delete_note(key):
    user = None
    try:
        user = session['username']
    except:
        flash("Błąd autoryzacji")
        return redirect(url_for('sign_in'))
    owner = get_note_owner(key).decode()
    if not owner:
        flash("Wystąpił błąd")
        return redirect(url_for('panel'))
    if user != owner:
        flash("Nie można usunąć nie swojej notatki")
        return redirect(url_for('panel'))
    succes = delete_note_from_database(key)
    if not succes:
        flash("Nie udało się usunąć notatki")
        return redirect(url_for('panel'))
    flash("usunięto notatkę")
    return redirect(url_for('panel'))
    
if __name__ == "__main__":
    app.run()
