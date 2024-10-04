// Start custom script
var userInteracted = false;
var errorContainer=null, errorList=null;
var errors = [];

// Listen for mouse movement
document.addEventListener('mousemove', () => {
    userInteracted = true;
    console.log("userInteracted: "+userInteracted)
});

// Listen for touch events
document.addEventListener('touchstart', () => {
    userInteracted = true;
    console.log("userInteracted: "+userInteracted)
});

document.addEventListener('touchmove', () => {
    userInteracted = true;
    console.log("userInteracted: "+userInteracted)
});

function getBaseRoute(path, segment) {
    const segments = path.split('/');
    // Return the first two segments joined by '/' (assuming base route is always the first two segments)
    return `/${segments[segment]}`; 
}

try {
    errorContainer = document.getElementById('errors-container');
    errorList = errorContainer.querySelector('.error-list');
} catch (e) {}


function handleSubmission(event, route) {

    event.preventDefault();
    if (!userInteracted) {
        alert('Please interact with the page before submitting.');
    }
    var formData, formObject;
    if (event.type == 'submit') {
        let errors = [];
        formData = new FormData(event.target);
        formObject = Object.fromEntries(formData.entries());
        loginOrSignup(formObject, window.location.pathname);
    }
    else{
        // For forgot password anchor tag ('click')
        console.log("forgot triggered")
        let form = document.getElementById('login_form')
        formData = new FormData(form);
        formObject = Object.fromEntries(formData.entries());
        let emailString = document.getElementById('email').value;
        console.log(emailString)
        if (!validateEmail(emailString)){
            if (!errors.includes("Invalid email address")) {
                errors.push("Invalid email address")
            }            
            errorContainer.style.display = 'block';
            errorList.innerHTML = ''; // Clear existing errors
            errors.forEach(error => {
                const li = document.createElement('li');
                li.textContent = error;
                li.id = "invalidEmailLi";
                errorList.appendChild(li);
            });
             
        }
        else{
            errors = errors.filter(item => item !== "Invalid email address");
            errorList.removeChild(document.getElementById('invalidEmailLi'));
            errorContainer.style.display = 'none'; 
            loginOrSignup(formObject, route);
        }
        
    }
}


if (getBaseRoute(window.location.pathname, 1) == "/login") {
    document.getElementById('login_form').addEventListener('submit', function (event) {
        handleSubmission(event, "/login");
    });
    document.getElementById("forgot-password").addEventListener('click', (event)=>{
        handleSubmission(event, '/forgot_password');
    })
}

if (getBaseRoute(window.location.pathname, 1) == "/signup") {
    document.getElementById('signup_form').addEventListener('submit', function (event) {
        handleSubmission(event, "/signup");
    });
}

if (getBaseRoute(window.location.pathname, 1) == "/reset_password") {
    document.getElementById('reset_password_form').addEventListener('submit', function (event) {
        handleSubmission(event, "/reset_password");
    });
}

async function loginOrSignup(formObject, route) {
    console.log(route)
    const res = await fetch(`${window.location.origin}/${route}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(formObject)
    });
    console.log(res)
    if (!res.ok) {
        if (res.status == 429) {
            errorContainer.style.display = 'block';
            errorList.innerHTML = '';
            
            const li = document.createElement('li');
            li.textContent = "Too many requests. Please try again later.";
            errorList.appendChild(li);  
        }
        throw new Error(`HTTP error! status: ${res.status}`);
    }
    
    let data = await res.json(); 
    console.log(data);
    
    let code = data['code'];
    let message = data['message']
    let redirect = data['redirect']
    if (code == 101) {
        // TODO:remove form and display message in success box
        console.log(message)
        errors = [];
        errorList='';
        errorContainer.style.display = 'none'; 
    }
    if (code == 103) {
        // display message
        console.log(message)
        errorContainer.style.display = 'block';
        errorList.innerHTML = '';
        
        const li = document.createElement('li');
        li.textContent = message;
        errorList.appendChild(li);        
    }
    if (redirect) {
        window.location.href = redirect;
    }
}

function validateEmail(email) {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
}

function validatePassword(password) {
    const minLength = 8;
    const uppercase = /[A-Z]/;
    const lowercase = /[a-z]/;
    const number = /[0-9]/;
    const specialChar = /[!@#$%^&*]/;

    if (password.length < minLength) {
        return "Password must be at least 8 characters long.";
    }
    if (!uppercase.test(password)) {
        return "Password must contain at least one uppercase letter.";
    }
    if (!lowercase.test(password)) {
        return "Password must contain at least one lowercase letter.";
    }
    if (!number.test(password)) {
        return "Password must contain at least one number.";
    }
    if (!specialChar.test(password)) {
        return "Password must contain at least one special character.";
    }
    return "";
}
