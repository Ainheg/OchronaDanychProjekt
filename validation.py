import re
USERNAME_REGEX = r'^[a-zA-Z0-9]{3,24}$'
PASSWORD_REGEX = r'^.{8,}$'
EMAIL_REGEX = r'^[a-z0-9]+([\._]?[a-z0-9])+[@]\w+([.]\w+)+$'
ANSWER_REGEX = r'^[\wĄĆĘŁŃÓŚŹŻąćęłńóśźż\/.\-, ]+$'
DATE_REGEX = r'^[1-9]{4}\-[0-9]{2}\-[0-9]{2}$'

PW_1 = r'[@#$%^&*(){}\[\]:"_;\'<>,.]+'
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