document.addEventListener('DOMContentLoaded', function() {
    fetch('/auth/status')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.authenticated) {
                console.log(data.authenticated)
                document.getElementById('login-button').style.display = 'none';
                document.getElementById('signup-button').style.display = 'none';
                document.getElementById('logout-button').style.display = 'block';
            } else {
                document.getElementById('login-button').style.display = 'block';
                document.getElementById('signup-button').style.display = 'block';
                document.getElementById('logout-button').style.display = 'none';
            }
        })
        .catch(error => {
            console.error('Error fetching auth status:', error);
        });
});
