var signupform;

var usernameField;
var passwordField;
var repeatPasswordField;
var emailField;
var q1Field;
var q2Field;
var a1Field;
var a2Field;
var submitButton;

var usernameError;
var emailError;
var passwordError;
var repeatpasswordError;
var secretquestionsError;
var a1Error;
var a2Error;
var pwEntropyField;

var isPasswordOk = false;
var isPasswordMatched = false;
var isUsernameOk = false;
var isEmailOk = false;
var areSecretQuestionsDifferent = false;
var isQuestion1Ok = false;
var isQuestion2Ol = false;

const passwordRegex = /^.{8,}$/;
const usernameRegex = /^[a-zA-Z0-9]{3,24}$/;
const emailRegex = /^[a-z0-9]+([\._]?[a-z0-9])+[@]\w+([.]\w+)+$/;
const answerRegex = /^[\wĄĆĘŁŃÓŚŹŻąćęłńóśźż.\-,\/ ]+$/;

window.onload = function() {
    signupform = document.getElementById("formList")
    loadFields();
    createErrors();
    loadListeners();
    submitButton = document.getElementById("submitButton");
    submitButton.disabled = true;
    qCheck();
}

function loadFields(){
    usernameField = document.getElementById("usernameField");
    passwordField = document.getElementById("passwordField");
    repeatPasswordField = document.getElementById("repeatPasswordField");
    emailField = document.getElementById("emailField");
    q1Field = document.getElementById("q1Field");
    q2Field = document.getElementById("q2Field");
    a1Field = document.getElementById("a1Field");
    a2Field = document.getElementById("a2Field");
}

function loadListeners(){
    passwordField.addEventListener("input", passwordCheck);
    repeatPasswordField.addEventListener("input", passwordCheck);
    usernameField.addEventListener("input", usernameCheck);
    emailField.addEventListener("input", emailCheck);
    q1Field.addEventListener("input", qCheck);
    q2Field.addEventListener("input", qCheck);
    a1Field.addEventListener("input", a1Check);
    a2Field.addEventListener("input", a2Check);
}

function createErrors(){
    usernameError = signupform.insertBefore(document.createElement("li"), usernameField.parentElement.nextElementSibling);
    emailError = signupform.insertBefore(document.createElement("li"), emailField.parentElement.nextElementSibling);
    passwordError = signupform.insertBefore(document.createElement("li"), passwordField.parentElement.nextElementSibling);
    pwEntropyField = signupform.insertBefore(document.createElement("li"), passwordField.parentElement.nextElementSibling);
    repeatpasswordError = signupform.insertBefore(document.createElement("li"), repeatPasswordField.parentElement.nextElementSibling);
    secretquestionsError = signupform.insertBefore(document.createElement("li"), q1Field.parentElement.nextElementSibling);
    a1Error = signupform.insertBefore(document.createElement("li"), a1Field.parentElement.nextElementSibling);
    a2Error = signupform.insertBefore(document.createElement("li"), a2Field.parentElement.nextElementSibling);
}

function passwordCheck(){
    pwEntropyCheck();
    var isPasswordLengthOk = passwordRegex.test(passwordField.value);
    if(isPasswordLengthOk) {
        var pass = passwordField.value;
        if(/[@#$%^&*(){}\[\]:"_;'<>,.]+/.test(pass) && /[A-Z]+/.test(pass) && /[a-z]+/.test(pass) && /[0-9]+/.test(pass)) {
            isPasswordOk = true;
            isPasswordMatched = (passwordField.value == repeatPasswordField.value)
            passwordError.innerText = "";
            passwordError.className = "error_hidden";
            if(!isPasswordMatched) {
                repeatpasswordError.innerText = "Hasła się nie zgadzają";
                repeatpasswordError.className = "error_shown";
            } else {
                repeatpasswordError.innerText = "";
                repeatpasswordError.className = "error_hidden";
            }
        } else {
            isPasswordOk = false;
            passwordError.innerText = "Hasło powinno zawierać co najmniej 1: wielką literę, małą literę, cyfrę, znak specjalny spośród @#$%^&*(){}[]:\";'<>,._";
            passwordError.className = "error_shown";
        }
    } else {
        isPasswordOk = false;
        passwordError.innerText = "Hasło musi mieć co najmniej 8 znaków";
        passwordError.className = "error_shown"
    }
    validateForm();
}

function usernameCheck(){
    var username = usernameField.value;
    isUsernameOk = usernameRegex.test(username)
    if (isUsernameOk){
        var xhr = new XMLHttpRequest();
        var url = document.location + "/username-check/" + username;
        xhr.open("GET", url, true);
        xhr.onreadystatechange = function () {
            if(xhr.readyState == 4){
                if (xhr.status == 200) {                    
                    var json = JSON.parse(xhr.responseText);
                    isUsernameAvailable = (json["available"] == "yes");
                } else if (xhr.status >= 400 && xhr.status < 500) {
                    console.log("Client side error: ", xhr.status)
                } else if (xhr.status >= 500 && xhr.status < 600) {
                    console.log("Server side error: ", xhr.status)
                }
                if(!isUsernameAvailable){
                    usernameError.className = "error_shown";
                    usernameError.innerText = "Nazwa użytkownika jest zajęta";
                } else {
                    usernameError.innerText = "";
                    usernameError.className = "error_hidden";
                }
                validateForm();
            }
        }
        xhr.send();
    } else {
        isUsernameAvailable = false;
        usernameError.className = "error_shown";
        usernameError.innerText = "Nazwa użytkownika powinna mieć od 3 do 24 liter lub cyfr";
        validateForm();
    }
}

function emailCheck() {
    email = emailField.value;
    isEmailOk = emailRegex.test(email)
    if (isEmailOk){
        emailError.className = "error_hidden";
        emailError.innerText = ""; 
    } else {
        emailError.className = "error_shown";
        emailError.innerText = "Podaj poprawny adres e-mail";
    }
    validateForm();
}

function qCheck(){
    areSecretQuestionsDifferent = q1Field.value != q2Field.value;
    if(areSecretQuestionsDifferent) {
        secretquestionsError.innerText = "";
        secretquestionsError.className = "error_hidden";
    } else {
        secretquestionsError.innerText = "Wybierz różne pytania awaryjne";
        secretquestionsError.className = "error_shown";
    }
    validateForm();
}

function a1Check(){
    answer = a1Field.value;
    isQuestion1Ok = answerRegex.test(answer)
    if (isQuestion1Ok){
        a1Error.className = "error_hidden";
        a1Error.innerText = ""; 
    } else {
        a1Error.className = "error_shown";
        a1Error.innerText = "Podaj odpowiedź";
    }
    validateForm();
}

function a2Check(){
    answer = a2Field.value;
    isQuestion2Ok = answerRegex.test(answer)
    if (isQuestion2Ok){
        a2Error.className = "error_hidden";
        a2Error.innerText = ""; 
    } else {
        a2Error.className = "error_shown";
        a2Error.innerText = "Podaj odpowiedź";
    }
    validateForm();
}

function validateForm(){
    if (isUsernameOk && isPasswordMatched && isPasswordOk && isQuestion1Ok && isQuestion2Ok && isEmailOk && areSecretQuestionsDifferent){
        submitButton.disabled = false;
    } else {
        submitButton.disabled = true;
    }
}

function pwEntropyCheck(){
    var alphabetLength = 0;
    var pw = passwordField.value;
    if(/[@#$%^&*(){}\[\]:"_;'<>,.\-]+/.test(pw)){
        alphabetLength += 23;
    }
    if(/[A-Z]+/.test(pw)){
        alphabetLength += 26;
    }
    if(/[a-z]+/.test(pw)){
        alphabetLength += 26;
    }
    if(/[0-9]+/.test(pw)){
        alphabetLength += 10;
    }
    var entropy
    if(alphabetLength > 0){
        entropy = pw.length*Math.log2(alphabetLength);
    } else {
        entropy = 0;
    }
    pwEntropyField.className = "error_shown";
    pwEntropyField.innerText = "Entropia hasła: " + entropy.toFixed(3) + ", zalecamy wartości powyżej 70";
}