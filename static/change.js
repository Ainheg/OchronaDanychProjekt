var form;

var passwordField;
var repeatPasswordField;
var submitButton;

var isPasswordOk = false;
var isPasswordMatched = false;

const passwordRegex = /^.{8,}$/;

window.onload = function() {
    form = document.getElementById("formList")
    loadFields();
    createErrors();
    loadListeners();
    submitButton = document.getElementById("submitButton");
    submitButton.disabled = true;
}

function loadFields(){
    passwordField = document.getElementById("passwordField");
    repeatPasswordField = document.getElementById("repeatPasswordField");
}

function loadListeners(){
    passwordField.addEventListener("input", passwordCheck);
    repeatPasswordField.addEventListener("input", passwordCheck);
}

function createErrors(){
    passwordError = form.insertBefore(document.createElement("li"), passwordField.parentElement.nextElementSibling);
    repeatpasswordError = form.insertBefore(document.createElement("li"), repeatPasswordField.parentElement.nextElementSibling);
}

function passwordCheck(){
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
    validateForm()
}

function validateForm(){
    if (isPasswordMatched && isPasswordOk){
        submitButton.disabled = false;
    } else {
        submitButton.disabled = true;
    }
}