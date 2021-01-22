import re

USERNAME_REGEX = r'^[a-zA-Z0-9]{3,24}$'
PASSWORD_REGEX = r'^.{8,}$'
EMAIL_REGEX = r'^[a-z0-9]+([\._]?[a-z0-9])+[@]\w+([.]\w+)+$'
ANSWER_REGEX = r'^[\wĄĆĘŁŃÓŚŹŻąćęłńóśźż\/.\-, ]+$'
DATE_REGEX = r'^[1-9]{4}\-[0-9]{2}\-[0-9]{2}$'

PW_1 = r'[@#$%^&*(){}\[\]:"_;\'<>,.\-]+'
PW_2 = r'[A-Z]+'
PW_3 = r'[a-z]+'
PW_4 = r'[0-9]+'

def username_validation(username):
    return (re.fullmatch(USERNAME_REGEX, username) is not None)
def password_validation(password):
    pw0 = re.fullmatch(PASSWORD_REGEX, password) is not None
    pw1 = re.search(PW_1, password) is not None
    pw2 = re.search(PW_2, password) is not None
    pw3 = re.search(PW_3, password) is not None
    pw4 = re.search(PW_4, password) is not None
    print(password, flush=True)
    print(pw0, flush=True)
    print(pw1, flush=True)
    print(pw2, flush=True)
    print(pw3, flush=True)
    print(pw4, flush=True)
    return ( pw0 and pw1 and pw2 and pw3 and pw4 )
def email_validation(email):
    return (re.fullmatch(EMAIL_REGEX, email) is not None)
def date_validation(date):
    return (re.fullmatch(DATE_REGEX, date) is not None)
def answer_validation(answer):
    return (re.fullmatch(ANSWER_REGEX, answer) is not None)

def validate_pass_recovery_request_form(form):
    username = form.get('login')
    error = False
    if not username:
        error = True
    elif not username_validation(username):
        error = True
    birthday = form.get("date")
    if not birthday:
        error = True
    elif not date_validation(birthday):
        error = True
    return not error

def validate_pass_recovery_form(form):
    a1 = form.get('a1')
    error = False
    if not a1:
        error = True
    elif not answer_validation(a1):
        error = True
    a2 = form.get('a2')
    if not a2:
        error = True
    elif not answer_validation(a2):
        error = True
    password = form.get("password")
    if not password:
        error = True
    elif not password_validation(password):
        error = True
    repeatPassword = form.get("repeatPassword")
    if not repeatPassword:
        error = True
    if password != repeatPassword:
        error = True
    return not error

def validate_pass_change_form(form):
    old_pw_present = True
    oldPw = form.get('oldPassword')
    if not oldPw:
        old_pw_present = False
    error = False
    if not password_validation(oldPw):
        error = True
    password = form.get("password")
    if not password:
        error = True
    elif not password_validation(password):
        error = True
    repeatPassword = form.get("repeatPassword")
    if not repeatPassword:
        error = True
    if password != repeatPassword:
        error = True
    return (not error, old_pw_present)

def validate_login_form(form):
    error = False
    username = form.get("login")
    if not username:
        error = True
    if not username_validation(username):
        error = True
    password = form.get("password")
    if not password:
        error = True
    if not password_validation(password):
        error = True
    return not error

def validate_register_form(form):
    error = False
    username = form.get("login")
    print(username)
    if not username:
        error = True
    elif not username_validation(username):
        error = True
    email = form.get("email")
    if not email:
        error = True
    elif not email_validation(email):
        error = True
    birthday = form.get("date")
    if not birthday:
        error = True
    elif not date_validation(birthday):
        error = True
    q1 = form.get('q1')
    if not q1:
        error = True
    q2 = form.get('q2')
    if not q2:
        error = True
    if q1 == q2:
        error = True
    a1 = form.get('a1')
    if not a1:
        error = True
    elif not answer_validation(a1):
        error = True
    a2 = form.get('a2')
    if not a2:
        error = True
    elif not answer_validation(a2):
        error = True
    password = form.get("password")
    if not password:
        error = True
    elif not password_validation(password):
        error = True
    repeatPassword = form.get("repeatPassword")
    if not repeatPassword:
        error = True
    if password != repeatPassword:
        error = True
    return not error