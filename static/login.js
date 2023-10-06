document.addEventListener("DOMContentLoaded", function () {
    const loginForm = document.getElementById("loginForm");
    const registerForm = document.getElementById("registerForm");
    const toggleLogin = document.getElementById("toggleLogin");
    const toggleRegister = document.getElementById("toggleRegister");

    toggleLogin.addEventListener("click", function (e) {
        e.preventDefault();
        loginForm.style.display = "block";
        registerForm.style.display = "none";
    });

    toggleRegister.addEventListener("click", function (e) {
        e.preventDefault();
        loginForm.style.display = "none";
        registerForm.style.display = "block";
    });
});
