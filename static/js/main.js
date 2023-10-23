document.addEventListener("DOMContentLoaded", function () {
    const passwordInput = document.getElementById("password");
    const showPasswordCheckbox = document.getElementById("showPassword");
    const registerForm = document.getElementById("registerForm");

    // Add an event listener to the form for submission
    registerForm.addEventListener("submit", function (e) {
        const password = passwordInput.value;
        const passwordFeedback = document.getElementById("password-feedback");

        const isPasswordValid = validatePassword(password);

        if (!isPasswordValid) {
            e.preventDefault(); // Prevent form submission

            // Create a list to store error messages
            const errorMessages = [];

            if (password.length < 8) {
                errorMessages.push("Password must be at least 8 characters long.");
            }
            if (!/[A-Z]/.test(password)) {
                errorMessages.push("Password must include at least one uppercase letter.");
            }
            if (!/[a-z]/.test(password)) {
                errorMessages.push("Password must include at least one lowercase letter.");
            }
            if (!/\d/.test(password)) {
                errorMessages.push("Password must include at least one digit.");
            }

            // Display error messages
            passwordFeedback.textContent = errorMessages.join(" ");
            passwordInput.classList.remove("is-valid");
            passwordInput.classList.add("is-invalid");
        } else {
            passwordFeedback.textContent = "";
        }
    });

    // Function to validate the password format
    function validatePassword(password) {
        // Add your password validation criteria here
        return password.length >= 8 && /[A-Z]/.test(password) && /[a-z]/.test(password) && /\d/.test(password);
    }

    showPasswordCheckbox.addEventListener("change", function () {
        if (showPasswordCheckbox.checked) {
            passwordInput.type = "text"; // Show the password
        } else {
            passwordInput.type = "password"; // Hide the password
        }
    });
});
