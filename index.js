const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_API_KEY);
const session = require('express-session');
const passport = require('passport');
const mysql = require('mysql2');
const fs = require('fs');
const bcrypt = require('bcrypt');
const path = require('path');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
delete require.cache[require.resolve('dotenv')];
require('dotenv').config();

require('./auth');
const OpenAI = require('openai');
const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
});

// Nodemailer setup for sending emails
const transporter = nodemailer.createTransport({
    host: 'smtp.porkbun.com',
    port: 465,
    secure: true, // Use SSL/TLS
    auth: {
        user: 'contact@aiulabs.io', // Use environment variables for sensitive data
        pass: 'GIGIhadid@97'  // Use environment variables for sensitive data
    }
});

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'abc123',
    database: 'aiulabs'
});
db.connect((err) => {
    if (err) throw err;
    console.log('Connected to MySQL Database.');
});

function isLoggedIn(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    } else {
        res.redirect('/access-denied');
    }
}

const app = express();

// Increase payload size limit
app.use(bodyParser.json({ limit: '10mb' })); // You can increase the limit as needed
app.use(bodyParser.urlencoded({ limit: '10mb', extended: true })); // If you use URL-encoded data

app.use('/views', express.static(path.join(__dirname, 'views')));
app.use(session({
    secret: 'cats',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to `true` in production when using HTTPS
}));

app.use(passport.initialize());
app.use(passport.session());


// Stripe payment
app.post('/create-checkout-session', async (req, res) => {
    const session = await stripe.checkout.sessions.create({
        ui_mode: 'embedded',
        line_items: [
            {
            // Provide the exact Price ID (for example, pr_1234) of the product you want to sell
            price: '{{PRICE_ID}}',
            quantity: 1,
            },
        ],
        mode: 'payment',
        return_url: `${YOUR_DOMAIN}/return.html?session_id={CHECKOUT_SESSION_ID}`,
    });
  
    res.send({clientSecret: session.client_secret});
});
app.get('/session-status', async (req, res) => {
        const session = await stripe.checkout.sessions.retrieve(req.query.session_id);
  
    res.send({
        status: session.status,
        customer_email: session.customer_details.email
    });
});
// main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
});
// Route to handle sending email from the contact form
app.post('/send-email', (req, res) => {
    const { 'Your-Name': name, 'Your-Email': email, 'LinkedIn-Link': linkedin, 'Phone-Number': phone, 'Your-Message': message } = req.body;

    const mailOptions = {
        from: 'contact@aiulabs.io', // Ensure this matches the authenticated user
        to: 'chinjun@outlook.com',
        subject: `New Contact Form Submission from ${name}`,
        text: `You have a new message from your contact form.\n\nName: ${name}\nEmail: ${email}\nLinkedIn Link: ${linkedin}\nPhone Number: ${phone}\nMessage: ${message}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error('Error sending email:', error);
            res.status(500).send('Oops! Something went wrong while submitting the form.');
        } else {
            console.log('Email sent:', info.response);
            res.status(200).send('Thank you! Your submission has been received!');
        }
    });
});
// google login
app.get('/auth/google',
    passport.authenticate('google', { scope: ['email', 'profile'] })
);
app.get('/google/callback', 
    passport.authenticate('google', {
        successRedirect: '/',
        failureRedirect: '/auth/failure',
    }),
    (req, res) => {
        req.session.user_id = req.user.id; // Set the user ID from Google in the session
    }
);
//login auth
app.get('/auth/failure', (req, res) =>{
    res.send('something wrong');
});
app.get('/auth/status', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ authenticated: true });
    } else {
        res.json({ authenticated: false });
    }
});
app.get('/auth/user', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ 
            userName: req.user.display_name,
            profilePicture: req.user.profile_picture
         });
    } else {
        res.json({ userName: '', profilePicture: '' });
    }
});



//reset password
app.get('/reset-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'reset-password.html'));
});
// Route to handle password reset form submission
app.post('/reset-password', (req, res) => {
    const { Email } = req.body;

    // Check if the email exists in the database
    db.query('SELECT * FROM users WHERE email = ?', [Email], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('An error occurred.');
        }

        if (results.length === 0) {
            // Don't reveal that the email doesn't exist for security reasons
            return res.send('A password reset link has been sent to your email.');
        }

        const user = results[0];

        // Generate a secure token
        const token = crypto.randomBytes(20).toString('hex');

        // Set token expiration time (e.g., 1 hour from now)
        const expires = new Date(Date.now() + 3600000); // 1 hour in milliseconds

        // Update the user's reset token and expiration in the database
        db.query('UPDATE users SET reset_password_token = ?, reset_password_expires = ? WHERE email = ?', [token, expires, Email], (err) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).send('An error occurred.');
            }

            // Send the reset email
            const resetLink = `http://${req.headers.host}/reset-password/${token}`;
            const mailOptions = {
                from: 'contact@aiulabs.io',
                to: Email,
                subject: 'Password Reset Request',
                text: `You are receiving this email because you (or someone else) have requested the reset of the password for your account.\n\n
Please click on the following link, or paste it into your browser to complete the process:\n\n
${resetLink}\n\n
If you did not request this, please ignore this email, and your password will remain unchanged.\n`
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.error('Error sending email:', error);
                    return res.status(500).send('An error occurred while sending the email.');
                } else {
                    console.log('Password reset email sent:', info.response);
                    res.send('A password reset link has been sent to your email.');
                }
            });
        });
    });
});
// Route to handle the password reset form submission
app.post('/reset-password/:token', (req, res) => {
    const { token } = req.params;
    const { password, confirm } = req.body;

    // Check if passwords match
    if (password !== confirm) {
        return res.send('Passwords do not match.');
    }

    // Find the user with the matching reset token and ensure it's not expired
    db.query('SELECT * FROM users WHERE reset_password_token = ? AND reset_password_expires > NOW()', [token], async (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('An error occurred.');
        }

        if (results.length === 0) {
            return res.send('Password reset token is invalid or has expired.');
        }

        const user = results[0];

        try {
            // Hash the new password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Update the user's password and clear the reset token and expiration
            db.query('UPDATE users SET password = ?, reset_password_token = NULL, reset_password_expires = NULL WHERE id = ?', [hashedPassword, user.id], (err) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).send('An error occurred.');
                }

                // Optionally, send a confirmation email
                const mailOptions = {
                    from: 'contact@aiulabs.io',
                    to: user.email,
                    subject: 'Your password has been changed',
                    text: `Hello,\n\nThis is a confirmation that the password for your account ${user.email} has just been changed.\n`
                };

                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.error('Error sending confirmation email:', error);
                        // You can choose to not treat this as a fatal error
                    } else {
                        console.log('Confirmation email sent:', info.response);
                    }
                });

                // Password reset successful
                res.send('Your password has been updated. You can now log in with your new password.');
            });
        } catch (error) {
            console.error('Error hashing password:', error);
            return res.status(500).send('An error occurred.');
        }
    });
});
app.get('/reset-password/:token', (req, res) => {
    const { token } = req.params;
    // Verify that the token exists and has not expired
    db.query('SELECT * FROM users WHERE reset_password_token = ? AND reset_password_expires > NOW()', [token], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('An error occurred.');
        }

        if (results.length === 0) {
            return res.send('Password reset link is invalid or has expired.');
        }

        // Token is valid; render the reset password form
        res.sendFile(path.join(__dirname, 'views', 'reset-password-form.html'));
    });
});



//denied page
app.get('/access-denied', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'access-denied.html'));
});
app.get('/p&p', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'p&p.html'));
});
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'signup.html'));
});
app.post('/signup', async (req, res) => {
    const { Name, Email, Password } = req.body;

    try {
        // Check if the user already exists (either Google login or manual sign-up)
        db.query('SELECT * FROM users WHERE email = ?', [Email], async (err, results) => {
            if (err) throw err;

            if (results.length > 0) {
                // User already exists
                return res.status(400).send('User already exists.');
            } else {
                // Hash the password
                const hashedPassword = await bcrypt.hash(Password, 10);

                // Insert the new user into the database
                db.query('INSERT INTO users (display_name, email, password) VALUES (?, ?, ?)', 
                    [Name, Email, hashedPassword], (err, results) => {
                    if (err) throw err;

                    res.redirect('/login?signup=success');
                });
            }
        });
    } catch (err) {
        console.error('Error handling signup:', err);
        res.status(500).send('An error occurred during signup.');
    }
});
app.post('/generate-gpt-suggestions', async (req, res) => {
    const { prompt } = req.body;

    try {
        const completion = await openai.chat.completions.create({
            messages: [{ role: "user", content: prompt }],
            model: "gpt-4",
            max_tokens: 300,
            temperature: 0.7,
            n: 3,
        });

        console.log('OpenAI Response:', completion.choices);  // Log the API response
        res.json(completion.choices);
    } catch (error) {
        console.error('Error generating GPT-4 suggestions:', error);
        res.status(500).send('Error generating GPT-4 suggestions');
    }
});
app.get('/dashboard', isLoggedIn, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});
app.get('/resumeAI', isLoggedIn, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'resumeAI.html'));
});


app.post('/create', (req, res) => {
    const title = req.body.title || 'Untitled'; // Default to 'Untitled'
    const defaultContent = ''; // Default content for new documents
    const userId = req.user.id; // Assuming req.user is populated with session data

    // Log the request body to debug
    console.log('Creating new document for user:', userId, 'with title:', title);

    const query = 'INSERT INTO templates (user_id, template_name, html_content) VALUES (?, ?, ?)';
    db.query(query, [userId, title, defaultContent], (err, result) => {
        if (err) {
            console.error('Database error:', err);  // Log the error for debugging
            return res.json({ success: false, error: err });
        }
        res.json({ success: true, documentId: result.insertId });
    });
});
// List all documents
app.get('/documents', (req, res) => {
    const userId = req.user.id; // Retrieve user ID from the session
    const query = `SELECT id, template_name AS title FROM templates WHERE user_id = ?`;
    db.query(query, [userId], (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }
        res.send(results);
    });
});
// Load a specific document by ID
app.get('/load/:id', (req, res) => {
    const documentId = req.params.id;
    const userId = req.user.id; // Retrieve user ID from the session
    const query = 'SELECT template_name, html_content AS content FROM templates WHERE id = ? AND user_id = ?';
    db.query(query, [documentId, userId], (err, result) => {
        if (err) {
            return res.status(500).send(err);
        }
        if (result.length > 0) {
            // Return both template_name and content
            res.send({ template_name: result[0].template_name, content: result[0].content });
        } else {
            res.send({ template_name: 'Untitled', content: '' });
        }
    });
});
// Save content to a specific document
app.post('/save/:id', (req, res) => {
    const documentId = req.params.id;
    const { content } = req.body;
    const userId = req.user.id; // Retrieve user ID from the session
    const query = 'UPDATE templates SET html_content = ? WHERE id = ? AND user_id = ?';
    db.query(query, [content, documentId, userId], (err, result) => {
        if (err) {
            return res.status(500).send(err);
        }
        res.send({ success: true });
    });
});
app.delete('/remove/:id', (req, res) => {
    const documentId = req.params.id;
    const userId = req.user.id; // Assuming req.user contains the user data
    const query = 'DELETE FROM templates WHERE id = ? AND user_id = ?';
    db.query(query, [documentId, userId], (err, result) => {
        if (err) {
            return res.status(500).send(err);  // Ensure error handling sends JSON or plain text
        }
        res.json({ success: true });
    });
});
app.post('/update-template-name/:id', (req, res) => {
    const documentId = req.params.id;
    const newName = req.body.newName;

    const query = 'UPDATE templates SET template_name = ? WHERE id = ?';
    db.query(query, [newName, documentId], (err, result) => {
        if (err) {
            return res.json({ success: false, error: err });
        }
        res.json({ success: true });
    });
});

app.get('/get_start', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'newUser.html'));
});



app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'login.html'));
});
app.post('/login', function(req, res, next) {
    passport.authenticate('local-login', function(err, user, info) {
      if (err) {
        console.error('Login error:', err);
        return res.status(500).send('An error occurred during login.');
      }
      if (!user) {
        // Authentication failed
        return res.status(400).send(info.message);
      }
      // Log the user in
      req.logIn(user, function(err) {
        if (err) {
          console.error('Login error:', err);
          return res.status(500).send('An error occurred during login.');
        }
        // Login successful
        return res.redirect('/');
      });
    })(req, res, next);
});
app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) { return next(err); }
        req.session.destroy((err) => {
            if (err) {
                return next(err);
            }
            res.redirect('/');
        });
    });
});

// test 
app.get('/test', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'test.html'));
});

app.listen(3000, () => console.log('run on port 3000'));