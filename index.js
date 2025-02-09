const express = require('express');
const session = require('express-session');
const passport = require('passport');
const mysql = require('mysql2');
const fs = require('fs');
const bcrypt = require('bcrypt');
const path = require('path');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
delete require.cache[require.resolve('dotenv')];
require('dotenv').config();
const { handleWebhook } = require('./webhooks');
const puppeteer = require('puppeteer');
require('./auth');
const stripe = require('stripe')(process.env.STRIPE_API_KEY);

const OpenAI = require('openai');
const crypto = require('crypto'); // For generating OTP
const otps = new Map(); // To store OTPs temporarily
const app = express();
const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY1
});
const transporter = nodemailer.createTransport({
    host: 'smtp.porkbun.com', // SMTP Hostname
    port: 587,               // Port number (STARTTLS)
    secure: false,           // Use false for STARTTLS
    auth: {
        user: 'noreply@aiulabs.io', // Your email
        pass: 'GIGIhadid@97', // Your email password
    },
});
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});
db.connect((err) => {
    if (err) {
        console.error('Error connecting to database:', err.message);
    } else {
        console.log('Connected to database');
    }
});
function isLoggedIn(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    } else {
        res.redirect('/loginFirst');
    }
}
// ✅ Webhook for Stripe Events
app.post('/webhook', express.raw({ type: 'application/json' }), handleWebhook);
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


const requestIp = require('request-ip');

async function checkUsageLimit(req, res, next) {
    const clientIp = requestIp.getClientIp(req); // Get the client's IP
    console.log('Client IP:', clientIp);

    try {
        // Check if the IP exists in the database
        const [rows] = await db.query(
            'SELECT usage_count FROM ip_usage WHERE ip_address = ?',
            [clientIp]
        );

        if (rows.length > 0) {
            // IP found in the database
            const usageCount = rows[0].usage_count;
            if (usageCount >= 5) {
                // Limit reached
                return res.status(403).send('You have reached the usage limit. Please upgrade to continue.');
            }

            // Increment usage count
            await db.query(
                'UPDATE ip_usage SET usage_count = usage_count + 1 WHERE ip_address = ?',
                [clientIp]
            );
        } else {
            // IP not found, insert it with initial usage count
            await db.query(
                'INSERT INTO ip_usage (ip_address, usage_count) VALUES (?, 1)',
                [clientIp]
            );
        }

        next(); // Allow access to the GPT generation route
    } catch (err) {
        console.error('Error checking IP usage:', err);
        res.status(500).send('An error occurred.');
    }
}
const sendEmail = async (to, subject, text) => {
    const mailOptions = {
        from: 'contact@aiulabs.io', // Sender address
        to,                        // Recipient address
        subject,                   // Email subject
        text,                      // Email body (plain text)
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent:', info.messageId);
        return { success: true, messageId: info.messageId };
    } catch (error) {
        console.error('Error sending email:', error);
        return { success: false, error };
    }
};

// ✅ Stripe Checkout Session Route
app.post('/create-checkout-session', (req, res) => {
    console.log('📌 [STEP 1] Received request to create checkout session');

    if (!req.user || !req.user.id || !req.user.email) {
        console.error('❌ User not authenticated.');
        return res.status(401).json({ error: { message: 'Please log in to continue.' }, redirect: '/login' });
    }

    const { priceId } = req.body;
    if (!priceId) {
        return res.status(400).json({ error: { message: 'Missing priceId in request.' } });
    }

    console.log(`📌 [STEP 2] Fetching Stripe customer ID for User ID: ${req.user.id}`);

    db.query('SELECT stripe_customer_id FROM users WHERE id = ?', [req.user.id], function (err, result) {
        if (err) {
            console.error('❌ Database query error:', err);
            return res.status(500).json({ error: { message: 'Database query failed' } });
        }

        let stripeCustomerId = result.length > 0 ? result[0].stripe_customer_id : null;
        console.log(`📌 [STEP 3] Stripe Customer ID: ${stripeCustomerId || 'Not Found'}`);

        function createCheckoutSession(customerId) {
            console.log('📌 [STEP 4] Creating Stripe Checkout Session...');
            stripe.checkout.sessions.create({
                payment_method_types: ['card'],
                mode: 'subscription',
                customer: customerId,
                metadata: { user_id: req.user.id },
                line_items: [{ price: priceId, quantity: 1 }],
                success_url: `${req.headers.origin}/dashboard?subs=success`,
                cancel_url: `${req.headers.origin}/?payment_status=cancelled`,
            }, function (err, session) {
                if (err) {
                    console.error('❌ Stripe checkout session creation failed:', err);
                    return res.status(500).json({ error: { message: 'Checkout session creation failed' } });
                }
                console.log('✅ [STEP 5] Checkout Session Created! Redirecting user...');
                res.json({ url: session.url });
            });
        }

        if (!stripeCustomerId) {
            console.log('📌 [STEP 6] No Stripe Customer ID found, creating one...');
            stripe.customers.create({ email: req.user.email, metadata: { user_id: req.user.id } }, function (err, customer) {
                if (err) {
                    console.error('❌ Stripe customer creation failed:', err);
                    return res.status(500).json({ error: { message: 'Stripe customer creation failed' } });
                }

                stripeCustomerId = customer.id;
                console.log(`✅ [STEP 7] Stripe Customer Created: ${stripeCustomerId}`);

                db.query('UPDATE users SET stripe_customer_id = ? WHERE id = ?', [stripeCustomerId, req.user.id], function (err) {
                    if (err) {
                        console.error('❌ Database update error:', err);
                        return res.status(500).json({ error: { message: 'Database update failed' } });
                    }
                    console.log('✅ [STEP 8] User updated with Stripe Customer ID. Proceeding to checkout session...');
                    createCheckoutSession(stripeCustomerId);
                });
            });
        } else {
            createCheckoutSession(stripeCustomerId);
        }
    });
});


app.get('/check-subscription-status', async (req, res) => {
    if (!req.user || !req.user.id) {
        return res.status(401).json({ error: 'User not authenticated.' });
    }

    const query = `SELECT subscription_status FROM users WHERE id = ?`;

    try {
        const [rows] = await db.execute(query, [req.user.id]);
        if (rows.length > 0) {
            res.json({ subscription_status: rows[0].subscription_status });
        } else {
            res.status(404).json({ error: 'User not found.' });
        }
    } catch (err) {
        console.error('Database query error:', err);
        res.status(500).json({ error: 'Failed to check subscription status.' });
    }
});
app.get('/get-subscription-info', isLoggedIn, (req, res) => {
    const email = req.user.email; // Assuming `req.user` contains logged-in user info

    db.query(
    'SELECT subscription_status, subscription_end_date, email FROM users WHERE email = ?',
    [email],
    (err, results) => {
        if (err) {
        console.error('Database query error:', err);
        return res.status(500).json({ message: 'Database query failed.' });
        }

        if (results.length === 0) {
        return res.status(404).json({ message: 'User not found.' });
        }

        res.json(results[0]);
    }
    );
});
app.post('/cancel-subscription', isLoggedIn, (req, res) => {
    const email = req.user.email; // Retrieve email of the logged-in user

    // Fetch the Stripe customer ID from the database
    db.query('SELECT stripe_customer_id FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).json({ message: 'Database query failed.' });
        }

        if (results.length === 0 || !results[0].stripe_customer_id) {
            return res.status(400).json({ message: 'No active subscription found for this user.' });
        }

        const stripeCustomerId = results[0].stripe_customer_id;

        try {
            // Retrieve active subscription
            const subscriptions = await stripe.subscriptions.list({
                customer: stripeCustomerId,
                status: 'active',
                limit: 1, // Only retrieve the latest active subscription
            });

            if (subscriptions.data.length === 0) {
                return res.status(400).json({ message: 'No active subscription found.' });
            }

            const subscriptionId = subscriptions.data[0].id;

            // Cancel the subscription at the end of the current period
            const canceledSubscription = await stripe.subscriptions.update(subscriptionId, {
                cancel_at_period_end: true, // Ensure it doesn't immediately cancel
            });

            // Update the user's subscription status in the database
            const updateQuery = `
                UPDATE users
                SET subscription_status = 'canceled'
                WHERE email = ?
            `;

            db.query(updateQuery, [email], (err) => {
                if (err) {
                    console.error('Database update error:', err);
                    return res.status(500).json({ message: 'Failed to update subscription status in the database.' });
                }

                // Respond with success and the subscription's end date
                res.json({
                    message: 'Subscription successfully canceled.',
                    subscription_end_date: new Date(canceledSubscription.current_period_end * 1000), // Send human-readable date
                });
            });
        } catch (err) {
            console.error('Error canceling subscription:', err);
            res.status(500).json({ message: 'Failed to cancel subscription.' });
        }
    });
});
// Success page
app.get('/success', (req, res) => {
    res.send('Subscription successful!');
});
app.get('/welcome', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'welcome.html'));
});
app.get('/generateQR', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'generateQR.html'));
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
        to: 'support@aiulabs.io',
        subject: `New Contact Form Submission from ${name}`,
        text: `You have a new message from your contact form.\n\nName: ${name}\nEmail: ${email}\nLinkedIn Link: ${linkedin}\nPhone Number: ${phone}\nMessage: ${message}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error('Error sending email:', error);
            return res.status(500).json({ success: false, message: 'Oops! Something went wrong while submitting the form.' });
        }
        console.log('Email sent:', info.response);
        return res.status(200).json({ success: true, message: 'Thank you! Your submission has been received!' });
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
    const { email, name, password, subscribed_to_marketing } = req.body;

    if (!email || !name || !password) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Default subscribed_to_marketing to 'false' if not provided
        const isSubscribed = subscribed_to_marketing === 'true' ? 'true' : 'false';

        // Query to insert the user
        const query = `
            INSERT INTO users (email, password, display_name, subscribed_to_marketing)
            VALUES (?, ?, ?, ?)
        `;
        const values = [email, hashedPassword, name, isSubscribed];

        // Execute the query
        const result = await db.execute(query, values);

        // Redirect to the login page on success
        res.redirect('/login');
    } catch (err) {
        console.error('Signup error:', err.message);
        res.status(500).json({ error: 'Failed to sign up.' });
    }
});
app.post('/google-signup', async (req, res) => {
    const { email, google_id, display_name } = req.body;

    try {
        const created_at = new Date();
        const result = await db.execute(
            `INSERT INTO users (email, google_id, display_name, created_at) VALUES (?, ?, ?, ?)`,
            [email, google_id, display_name, created_at]
        );

        const insertId = result[0].insertId;
        res.redirect(`/questions?user_id=${insertId}`);
    } catch (err) {
        console.error("Google signup error:", err.message);
        res.status(500).json({ error: "Failed to sign up with Google" });
    }
});
app.get('/signup1', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'signup1.html'));
});
app.post('/signup1', async (req, res) => {
    const { email, name, password, subscribed_to_marketing } = req.body;

    if (!email || !name || !password) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Default subscribed_to_marketing to 'false' if not provided
        const isSubscribed = subscribed_to_marketing === 'true' ? 'true' : 'false';

        // Query to insert the user
        const query = `
            INSERT INTO users (email, password, display_name, subscribed_to_marketing)
            VALUES (?, ?, ?, ?)
        `;
        const values = [email, hashedPassword, name, isSubscribed];

        // Execute the query
        const result = await db.execute(query, values);

        // Redirect to the login page on success
        res.redirect('/login1');
    } catch (err) {
        console.error('Signup error:', err.message);
        res.status(500).json({ error: 'Failed to sign up.' });
    }
});
app.get('/login1', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'login1.html'));
});
app.post('/login1', function(req, res, next) {
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
        return res.redirect('/questions');
      });
    })(req, res, next);
});
app.get('/loginFirst', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'loginFirst.html'));
});



app.get('/questions', isLoggedIn, (req, res) => {
    const user_id = req.user.id; // Assuming `req.user.id` is available through middleware

    // Check if the questionnaire has already been submitted
    db.execute(`SELECT questionnaire_submitted FROM users WHERE id = ?`, [user_id], (err, results) => {
        if (err) {
            console.error("Error checking questionnaire submission:", err);
            return res.status(500).send("An error occurred");
        }

        if (results.length > 0) {
            const questionnaireStatus = results[0].questionnaire_submitted;

            // Check if the status is "false" as a string
            if (questionnaireStatus === "false") {
                return res.sendFile(path.join(__dirname, 'views', 'questions.html')); // Load the questions page
            }

            // Redirect to dashboard if the questionnaire has been submitted
            return res.redirect('/dashboard');
        }

        // If no user found (optional fallback)
        res.status(404).send("User not found");
    });
});
app.post('/questions', isLoggedIn, (req, res) => {
    let {
        phone, location, education, field_of_study, experience,
        job_title, employer, industry, skills, career_goals, accomplishments, linkedin
    } = req.body;

    const user_id = req.user.id;

    // Convert empty strings to null for nullable fields
    experience = experience ? parseInt(experience) : null; // Convert to integer or set to null

    const queryInsertProfile = `
        INSERT INTO user_profiles 
        (user_id, phone, location, education, field_of_study, 
         experience, job_title, employer, industry, skills, career_goals, accomplishments, linkedin)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    db.execute(queryInsertProfile, [
        user_id, phone || null, location || null, education || null, field_of_study || null,
        experience, job_title || null, employer || null, industry || null, 
        skills || null, career_goals || null, accomplishments || null, linkedin || null
    ], (err) => {
        if (err) {
            console.error("Error saving user profile:", err);
            return res.status(500).json({ error: "Failed to save user profile" });
        }

        const queryUpdateUser = `UPDATE users SET questionnaire_submitted = ? WHERE id = ?`;

        db.execute(queryUpdateUser, ['true', user_id], (err) => {
            if (err) {
                console.error("Error updating questionnaire status:", err);
                return res.status(500).json({ error: "Failed to update questionnaire status" });
            }

            res.redirect('/dashboard');
        });
    });
});



app.get('/api/check-questionnaire', (req, res) => {
    if (req.isAuthenticated()) {
        const userId = req.user.id;
        db.query('SELECT questionnaire_submitted FROM users WHERE id = ?', [userId], (err, results) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to check status' });
            }
            const { questionnaire_submitted } = results[0];
            res.json({ questionnaireSubmitted: questionnaire_submitted });
        });
    } else {
        res.json({ questionnaireSubmitted: true }); // Assume completed for unauthenticated users
    }
});
app.post('/send-otp', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: 'Email is required.' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000); // Generate 6-digit OTP
    otps.set(email, otp); // Save OTP

    // Nodemailer transporter configuration
    const transporter = nodemailer.createTransport({
        host: 'smtp.porkbun.com',
        port: 587,
        secure: false, // true for port 465, false for other ports
        auth: {
            user: 'noreply@aiulabs.io', // Your email
            pass: 'GIGIhadid@97', // Your password
        },
    });

    // HTML email content
    const htmlContent = `
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f4;
                    margin: 0;
                    padding: 0;
                }
                .email-container {
                    max-width: 600px;
                    margin: 30px auto;
                    background-color: #ffffff;
                    border: 1px solid #ddd;
                    border-radius: 10px;
                    box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
                    padding: 20px;
                }
                .header {
                    text-align: center;
                    padding: 10px 0;
                    font-size: 18px;
                    font-weight: bold;
                    color: #555;
                }
                .greeting {
                    text-align: center;
                    font-size: 16px;
                    margin: 10px 0;
                    color: #333;
                }
                .message {
                    font-size: 14px;
                    color: #555;
                    line-height: 1.5;
                    text-align: center;
                    margin: 20px 0;
                }
                .otp-box {
                    text-align: center;
                    font-size: 30px;
                    font-weight: bold;
                    color: #5234ff;
                    margin: 20px 0;
                }
                .note {
                    font-size: 12px;
                    color: #888;
                    text-align: center;
                    margin-top: 10px;
                }
                .footer {
                    font-size: 12px;
                    text-align: center;
                    color: #aaa;
                    margin-top: 20px;
                }
            </style>
        </head>
        <body>
            <div class="email-container">
                <div class="header">One-Time PIN (OTP)</div>
                <div class="greeting">Dear User,</div>
                <div class="message">
                    You recently requested for a One-Time PIN (OTP) for your account.<br>
                    Enter the 6-digit OTP shown below to proceed:
                </div>
                <div class="otp-box">${otp}</div>
                <div class="note">
                    This OTP is valid for 5 minutes and usable only once.<br><br>
                    Thank you,<br>
                    Your Virtual Assistant
                </div>
            </div>
            <div class="footer">
                © 2025 Aiu Labs. All rights reserved.
            </div>
        </body>
        </html>
    `;

    // Mail options
    const mailOptions = {
        from: '"Aiu Labs" <noreply@aiulabs.io>', // Sender address
        to: email,
        subject: 'Your OTP for Email Verification',
        html: htmlContent, // Use the HTML content here
    };

    try {
        await transporter.sendMail(mailOptions);
        res.json({ success: true, message: 'OTP sent successfully.' });
    } catch (error) {
        console.error('Error sending email:', error);
        res.status(500).json({ success: false, message: 'Error sending OTP.' });
    }
});
app.post('/verify-otp', (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
    return res.status(400).json({ success: false, message: 'Email and OTP are required.' });
    }

    const savedOtp = otps.get(email);

    if (parseInt(otp) === savedOtp) {
    otps.delete(email); // Remove OTP after successful verification
    return res.json({ success: true, message: 'Email verified successfully!' });
    }

    res.status(400).json({ success: false, message: 'Invalid OTP.' });
});
  















app.post('/generate-gpt-suggestions', (req, res) => {
    const { prompt } = req.body;
    const userId = req.user.id;

    if (!userId) {
        return res.status(400).json({ error: 'User ID is required.' });
    }

    console.log(`📌 [CHECK] User ID: ${userId} is requesting GPT suggestions`);

    // ✅ Check if this user's subscription is expired & update status if needed
    const queryCheck = `
        UPDATE users 
        SET subscription_status = 'past_due' 
        WHERE id = ? AND subscription_status = 'active' AND subscription_end_date < NOW()
    `;
    db.query(queryCheck, [userId], (err, result) => {
        if (err) {
            console.error('❌ Database error while updating expired subscriptions:', err);
        } else if (result.affectedRows > 0) {
            console.log(`🔄 [UPDATED] User ${userId} subscription changed to 'past_due'`);
        }
    });

    // ✅ Get user details after the potential update
    const queryUser = 'SELECT subscription_status, subscription_end_date, defaultgptprompt FROM users WHERE id = ?';
    db.query(queryUser, [userId], (err, results) => {
        if (err) {
            console.error('❌ Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        const user = results[0];
        const { subscription_status, subscription_end_date, defaultgptprompt } = user;
        const currentDate = new Date();
        const endDate = new Date(subscription_end_date);

        console.log(`📌 [CHECK] User: ${userId}, Status: ${subscription_status}, End Date: ${subscription_end_date}, Prompts: ${defaultgptprompt}`);

        // ❌ Block users with expired subscriptions
        if (subscription_status === 'past_due' || (subscription_status === 'active' && currentDate > endDate)) {
            console.log(`❌ [BLOCKED] Subscription expired for User ${userId}`);
            return res.status(403).json({
                error: 'Your subscription has expired. Please renew to continue using GPT.',
                redirect: '/subscribe'
            });
        }

        // ❌ Block free trial users with no prompts left
        if (subscription_status === 'freetrial' && defaultgptprompt <= 0) {
            console.log(`❌ [BLOCKED] No prompts remaining for Free Trial User ${userId}`);
            return res.status(403).json({
                error: 'No free trial prompts left. Please subscribe to continue.',
                redirect: '/subscribe'
            });
        }

        // ✅ Deduct 1 prompt for free trial users
        if (subscription_status === 'freetrial') {
            console.log(`📌 [UPDATE] Deducting 1 prompt for Free Trial User ${userId}`);
            db.query('UPDATE users SET defaultgptprompt = defaultgptprompt - 1 WHERE id = ?', [userId], (updateErr) => {
                if (updateErr) {
                    console.error('❌ Database error while updating prompts:', updateErr);
                    return res.status(500).json({ error: 'Database error' });
                }
                generateResponse(prompt, res);
            });
        } else {
            // ✅ Active users have unlimited prompts
            console.log(`✅ [ALLOWED] User ${userId} has unlimited prompts.`);
            generateResponse(prompt, res);
        }
    });
});

// ✅ Function to generate GPT response
function generateResponse(prompt, res) {
    openai.chat.completions
        .create({
            messages: [{ role: 'user', content: prompt }],
            model: 'gpt-4o',
            max_tokens: 300,
            temperature: 0.7,
            n: 3,
        })
        .then((completion) => {
            res.json(completion.choices);
        })
        .catch((error) => {
            console.error('❌ Error generating GPT-4 suggestions:', error);
            res.status(500).send('Error generating GPT-4 suggestions');
        });
}


app.get('/dashboard', isLoggedIn, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});
app.get('/resumeAI', isLoggedIn, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'resumeAI.html'));
});
app.get('/account', isLoggedIn, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'account.html'));
});
// Load user profile by user ID
app.get('/loadprofile', (req, res) => {
    if (!req.user || !req.user.id) {
        console.error('User not authenticated or req.user missing.');
        return res.status(401).json({ error: 'User not authenticated.' });
    }

    const userId = req.user.id;

    const query = `
        SELECT 
            users.display_name, 
            users.subscription_status, 
            users.subscription_end_date, 
            users.stripe_customer_id,
            user_profiles.phone, 
            user_profiles.location, 
            user_profiles.education, 
            user_profiles.field_of_study, 
            user_profiles.experience, 
            user_profiles.job_title, 
            user_profiles.employer, 
            user_profiles.industry, 
            user_profiles.skills, 
            user_profiles.career_goals, 
            user_profiles.accomplishments, 
            user_profiles.linkedin 
        FROM users
        LEFT JOIN user_profiles ON users.id = user_profiles.user_id 
        WHERE users.id = ?
    `;

    db.query(query, [userId], (err, rows) => {
        if (err) {
            console.error('Database error in /loadprofile:', err);
            return res.status(500).json({ error: 'An error occurred while fetching the profile data.' });
        }

        if (rows.length > 0) {
            res.json({ user_info: rows[0] });
        } else {
            console.error('No profile found for user ID:', userId);
            res.status(404).json({ error: 'User profile not found.' });
        }
    });
});
app.post('/update-profile', (req, res) => {
    if (!req.user || !req.user.id) {
        return res.status(401).json({ success: false, message: 'User not authenticated.' });
    }

    const userId = req.user.id;
    const {
        phone,
        location,
        education,
        field_of_study,
        experience,
        job_title,
        employer,
        industry,
        skills,
        career_goals,
        accomplishments,
        linkedin,
    } = req.body;

    const query = `
        INSERT INTO user_profiles (
            user_id, phone, location, education, field_of_study, experience, job_title, 
            employer, industry, skills, career_goals, accomplishments, linkedin
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        ON DUPLICATE KEY UPDATE
            phone = VALUES(phone),
            location = VALUES(location),
            education = VALUES(education),
            field_of_study = VALUES(field_of_study),
            experience = VALUES(experience),
            job_title = VALUES(job_title),
            employer = VALUES(employer),
            industry = VALUES(industry),
            skills = VALUES(skills),
            career_goals = VALUES(career_goals),
            accomplishments = VALUES(accomplishments),
            linkedin = VALUES(linkedin);
    `;

    const values = [
        userId,
        phone || null,
        location || null,
        education || null,
        field_of_study || null,
        experience || null,
        job_title || null,
        employer || null,
        industry || null,
        skills || null,
        career_goals || null,
        accomplishments || null,
        linkedin || null,
    ];

    db.query(query, values, (err) => {
        if (err) {
            console.error('Database update error:', err);
            return res.status(500).json({ success: false, message: 'Failed to update profile.' });
        }

        return res.json({ success: true, message: 'Profile updated successfully!' });
    });
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
    const userId = req.user?.id; // Retrieve user ID from the session
    const query = `
        SELECT id, template_name AS title, preview_image_path, updated_at
        FROM templates
        WHERE user_id = ?
    `;

    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send(err);
        }
        res.json(results);
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
    const { content } = req.body; // Get the content sent from the client
    const userId = req.user?.id; // Ensure the user is logged in

    const query = 'UPDATE templates SET html_content = ? WHERE id = ? AND user_id = ?';
    db.query(query, [content, documentId, userId], (err) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to save template' });
        }
        res.json({ success: true });
    });
});
// Endpoint to duplicate a document
app.post('/duplicate/:id', (req, res) => {
    const { id } = req.params;
    const userId = req.user?.id; // Retrieve user ID from session

    const getQuery = 'SELECT template_name, html_content FROM templates WHERE id = ? AND user_id = ?';
    db.query(getQuery, [id, userId], (err, results) => {
        if (err || results.length === 0) {
            return res.status(404).json({ success: false, message: 'Document not found' });
        }

        const doc = results[0];
        const duplicateQuery = `
            INSERT INTO templates (user_id, template_name, html_content)
            VALUES (?, ?, ?)
        `;
        db.query(
            duplicateQuery,
            [userId, `${doc.template_name} (Copy)`, doc.html_content],
            (err, result) => {
                if (err) {
                    return res.status(500).json({ success: false, error: err.message });
                }
                res.json({ success: true, documentId: result.insertId });
            }
        );
    });
});
// Endpoint to download a document as PDF
app.get('/download/:id', async (req, res) => {
    const { id } = req.params;
    const userId = req.user?.id;

    const query = 'SELECT template_name, html_content FROM templates WHERE id = ? AND user_id = ?';
    db.query(query, [id, userId], async (err, results) => {
        if (err || results.length === 0) {
            return res.status(404).json({ success: false, message: 'Document not found' });
        }

        const doc = results[0];
        const htmlContent = doc.html_content; // The raw HTML content of the resume

        try {
            const browser = await puppeteer.launch();
            const page = await browser.newPage();
            
            // Load the HTML content into Puppeteer
            await page.setContent(htmlContent, { waitUntil: 'load' });

            // Generate the PDF
            const pdfBuffer = await page.pdf({
                format: 'A4',
                printBackground: true,
                margin: {
                    top: '10mm',
                    bottom: '10mm',
                    left: '10mm',
                    right: '10mm',
                },
            });

            await browser.close();

            // Send the generated PDF as a downloadable file
            res.set({
                'Content-Type': 'application/pdf',
                'Content-Disposition': `attachment; filename="${doc.template_name}.pdf"`,
            });

            res.send(pdfBuffer);
        } catch (error) {
            console.error('Error generating PDF:', error);
            res.status(500).json({ success: false, message: 'Failed to generate PDF' });
        }
    });
});
// Endpoint to remove a document
app.delete('/remove/:id', (req, res) => {
    const { id } = req.params;
    const userId = req.user?.id; // Assuming user ID is stored in the session

    // Get the screenshot path from the database
    const queryFetch = 'SELECT preview_image_path FROM templates WHERE id = ? AND user_id = ?';
    db.query(queryFetch, [id, userId], (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Failed to fetch document details', error: err });
        }

        if (results.length === 0) {
            return res.status(404).json({ success: false, message: 'Document not found' });
        }

        const screenshotPath = results[0].preview_image_path;
        const queryDelete = 'DELETE FROM templates WHERE id = ? AND user_id = ?';

        // Delete the document from the database
        db.query(queryDelete, [id, userId], (err) => {
            if (err) {
                return res.status(500).json({ success: false, message: 'Failed to delete document', error: err });
            }

            // If a screenshot exists, delete the file
            if (screenshotPath) {
                const fullPath = path.join(__dirname, 'views', screenshotPath); // Adjust the path as needed
                fs.unlink(fullPath, (unlinkErr) => {
                    if (unlinkErr) {
                        console.error('Failed to delete screenshot:', unlinkErr);
                    }
                });
            }

            res.json({ success: true, message: 'Document and screenshot removed successfully' });
        });
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
// Save the screenshot to a folder
app.post('/save-screenshot/:id', async (req, res) => {
    const { id } = req.params;
    const { content } = req.body; // Receive updated HTML content
    const userId = req.user?.id;

    // Path to save the screenshot
    const screenshotPath = path.join(__dirname, `views/screenshots/${id}.png`);

    try {
        // Launch Puppeteer
        const browser = await puppeteer.launch({ headless: true });
        const page = await browser.newPage();

        // Define a full HTML structure with CSS links
        const cssPath = 'http://localhost:3000/views/css/resume.css'; // Replace with your actual CSS path
        const fullHTML = `
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Resume</title>
                <style>
                    @font-face { 
                        font-family: 'Calibri'; 
                        src: url('/views/fonts/Calibri.woff2') format('woff2'), 
                            url('/views/fonts/Calibri.woff') format('woff'); 
                        font-weight: normal; 
                        font-style: normal; 
                    } 
                    * {
                        margin: 0;
                    }
                    body {
                        font-family: helvetica, sans-serif;
                        background-color: #333144;
                        margin: 0;
                        padding: 0;
                    }
                    [contenteditable] {
                        line-height: 1.5; /* Apply line height only to editable content */
                    }
                    ul {
                        padding-left: 20px;
                        position: relative;
                    }
                    .container {
                        width: 210mm; /* A4 width */
                        height: 297mm; /* A4 height */
                        margin: 0 auto; /* Center the container */
                        background: #fff;
                        padding: 10mm; /* Add padding in mm for consistency */
                        border-radius: 10px;
                        box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
                        overflow: visible; /* Ensure content doesn't overflow */
                        box-sizing: border-box; /* Include padding in total size */
                        position: relative;
                    }
                    .section {
                        margin-bottom: 15px;
                    }
                    .section-header {
                        display: flex;
                        align-items: center;
                        justify-content: space-between;
                        border-bottom: 1px solid #2d2d2d;
                    }
                    .section-title {
                        font-size: 14px;
                        font-weight: bold;
                        color: #2A4879; /* Standard dark blue */
                        margin: 0;
                        cursor: default;
                        line-height: 1.5;
                    }
                    .drag-handle {
                        cursor: grab;
                        display: none;
                        align-items: center;
                        justify-content: center;
                        width: 20px;
                        height: 20px;
                    }
                    .drag-handle::before {
                        content: "⋮⋮";
                        font-size: 16px;
                        color: #666;
                    }
                    .drag-handle1 {
                        cursor: grab;
                        display: none;
                        align-items: center;
                        justify-content: center;
                        width: 20px;
                        height: 20px;
                    }
                    .drag-handle1::before {
                        content: "⋮⋮";
                        font-size: 16px;
                        color: #666;
                    }
                    .content {
                        font-size: 11px;
                    }
                    .placeholder {
                        color: #cecece !important; /* Placeholder text color */
                    }
                    .editable-text {
                        width: 85%;
                        border-bottom: 1px solid transparent !important; /* Default state */
                        transition: background-color 0.3s, border-bottom-color 0.3s;
                        outline: none;
                        color: #000; /* Default text color */
                        outline: none;
                        border: none;
                    }
                    .editable-text:focus {
                        background-color: #fef0ff;
                        border-bottom-color: #580067 !important;
                        outline: none;
                    }
                    /* Top-Info & Image */
                    .top-info {
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        text-align: left;
                        margin-bottom: 15px;
                    }
                    .image-box {
                        width: 90px;
                        height: 116px;
                        border: 1px solid #ccc;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        margin-right: 15px;
                        overflow: hidden;
                        cursor: pointer;
                        text-align: center;
                    }
                    .image-box img {
                        width: 100%;
                        height: 100%;
                    }
                    .info-text {
                        font-size: 12px;
                    }
                    .info-text table {
                        width: 100%;
                        border-collapse: collapse;
                    }
                    .info-text .label {
                        text-align: left;
                        font-weight: bold;
                        font-size: 12px;
                        white-space: nowrap;
                        padding-right: 5px;
                    }
                    .info-text .separator {
                        text-align: center;
                        font-weight: bold;
                        font-size: 12px;
                        width: 10px;
                    }
                    .info-text .value {
                        text-align: left;
                        font-size: 12px;
                        word-wrap: break-word;
                        width: 100%;
                    }
                    .content {
                        margin: 1mm 0 2mm 0;
                    }
                    /* Style the ghost element during dragging */
                    .dragging-ghost {
                        height: 30px;
                        overflow: hidden;
                        background: #f5f5f5;
                        border: 1px solid #ddd;
                        box-shadow: none;
                    }
                    .dragging-ghost .content {
                        display: none;
                    }
                    .skills-content {
                        display: table;
                        width: 100%;
                    }
                    .skill-row {
                        width: 100%;
                        display: flex;
                        padding-right: 20%;
                        margin-bottom: 1px;
                        line-height: 1.5;
                    }
                    .skill-category {
                        display: table-cell;
                        font-size: 11px;
                        font-weight: bold;
                        text-align: left;
                        white-space: normal; /* Allow wrapping */
                        word-wrap: break-word; /* Break long words */
                        padding-right: 10px;
                        width: 20mm;
                    }
                    .skill-detail {
                        width: calc((190mm * 0.85) - 20mm - 15px);
                        display: table-cell;
                        font-size: 11px;
                        white-space: normal; /* Allow wrapping */
                        word-wrap: break-word; /* Break long words */
                        text-align: left;
                        padding-left: 5px;

                    }
                    .skill-row:hover .remove-button {
                        display: inline-block;
                    }
                    .research-row {
                        width: 100%;
                        display: flex;
                        padding-right: 20%;
                    }
                    .research-row:hover .remove-button {
                        display: inline-block;
                    }
                    .leadership-row {
                        width: 100%;
                        display: flex;
                        padding-right: 20%;
                    }
                    .leadership-row:hover .remove-button {
                        display: inline-block;
                    }
                    .award-row {
                        width: 100%;
                        display: flex;
                        padding-right: 20%;
                    }
                    .award-row:hover .remove-button {
                        display: inline-block;
                    }
                    .value a {
                        color: #007bff; /* Link color */
                        text-decoration: none; /* Remove underline */
                    }
                    .value a:hover {
                        text-decoration: underline; /* Add underline on hover */
                    }
                    .pagination-line {
                        width: 100%;
                        border-top: 1px dashed #ddd;
                        text-align: center;
                        font-size: 12px;
                        color: #666;
                        position: absolute;
                        left: 0;
                        text-align: left;
                    }
                    .pagination-line span {
                        position: relative;
                        left: -15mm;
                        padding: 0 5px;
                        font-weight: bold;
                    }
                    /* Date picker */
                    .date-container {
                        display: flex;
                        align-items: center;
                        gap: 3px;
                        font-weight: bold;
                    }
                    .date-display {
                        cursor: pointer;
                        color: black; /* Black text color */
                        text-decoration: none; /* Remove underline */
                        position: relative;
                    }
                    .month-picker {
                        position: absolute;
                        background: white;
                        border: 1px solid #ccc;
                        padding: 10px;
                        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
                        width: 200px;
                        text-align: center;
                        cursor: default;
                        border-radius: 8px; /* Slightly rounded corners for a modern look */
                        z-index: 2;
                    }
                    .month-picker .year {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        font-size: 16px;
                        margin-bottom: 10px;
                    }
                    .month-picker .months {
                        display: flex;
                        flex-wrap: wrap;
                        gap: 5px;
                        justify-content: center;
                    }
                    .month-picker .month {
                        width: 45px;
                        padding: 5px;
                        text-align: center;
                        cursor: pointer;
                        transition: all 0.1s ease-in-out; /* Smooth transition */
                        border-radius: 6px;
                        background-color: white; /* Default background */
                    }
                    .month-picker .month:hover {
                        background-color: #eaeefc; /* Soft pastel hover color */
                        color: #4a6ef5; /* Contrast text color */
                        transform: scale(1.1); /* Slight zoom effect */
                    }
                    .month-picker .actions {
                        margin-top: 10px;
                        display: flex;
                        justify-content: space-between;
                    }
                    .month-picker .action {
                        cursor: pointer;
                        font-size: 14px;
                        color: #4a6ef5; /* Soft blue for actions */
                        transition: color 0.1s ease-in-out; /* Smooth color transition */
                    }
                    .month-picker .action:hover {
                        color: #354bb7; /* Darker blue on hover */
                    }
                    .year span {
                        cursor: pointer;
                        transition: all 0.1s ease-in-out; /* Smooth transition for year navigation */
                    }
                    .year span:hover {
                        color: #4a6ef5; /* Match hover color for consistency */
                        transform: scale(1.2); /* Slight zoom effect */
                    }
                    .year-picker {
                        position: absolute;
                        background: white;
                        border: 1px solid #ccc;
                        padding: 10px;
                        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
                        width: 200px;
                        text-align: center;
                        cursor: default;
                        border-radius: 8px; /* Rounded corners */
                        z-index: 2;
                    }
                    .year-picker .year-navigation {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        font-size: 16px;
                        margin-bottom: 10px;
                        font-weight: bold;
                    }
                    .year-picker .year-navigation span {
                        cursor: pointer;
                        transition: color 0.2s ease-in-out;
                        color: black; /* Blue for navigation arrows */
                        cursor: pointer;
                        transition: all 0.1s ease-in-out;
                    }
                    .year-picker .year-navigation span:hover {
                        color: #354bb7; /* Darker blue on hover */
                        color: #4a6ef5; /* Match hover color for consistency */
                        transform: scale(1.2); /* Slight zoom effect */
                    }
                    .year-picker .years {
                        display: flex;
                        flex-wrap: wrap;
                        gap: 5px;
                        justify-content: center;
                        font-size: 14px;
                    }
                    .year-picker .year {
                        width: 45px;
                        padding: 5px;
                        text-align: center;
                        cursor: pointer;
                        transition: all 0.1s ease-in-out;
                        border-radius: 6px;
                        background-color: white; /* Default background */
                    }
                    .year-picker .year:hover {
                        background-color: #eaeefc; /* Soft pastel hover color */
                        color: #4a6ef5; /* Contrast text color */
                        transform: scale(1.1); /* Slight zoom effect */
                    }
                    .year-picker .actions {
                        margin-top: 10px;
                        display: flex;
                        justify-content: space-between;
                    }
                    .year-picker .action {
                        cursor: pointer;
                        font-size: 14px;
                        color: #4a6ef5; /* Soft blue for actions */
                        transition: color 0.1s ease-in-out;
                    }
                    .year-picker .action:hover {
                        color: #354bb7; /* Darker blue on hover */
                    }
                    /* Add more button */
                    .add-button {
                        border: none;
                        cursor: pointer;
                        text-align: center;
                        display: none;
                        position: relative;
                        color: grey;
                        background: 0;
                        align-items: center;
                        margin-left: 2mm;
                    }
                    .add-button:hover::after {
                        content: attr(data-tooltip);
                        position: absolute;
                        bottom: 100%; /* Position above the button */
                        left: 50%;
                        transform: translateX(-50%);
                        background-color: #1a1a1a;
                        color: #fff;
                        padding: 5px;
                        border-radius: 5px;
                        white-space: nowrap;
                        box-shadow: 0 0 5px rgba(0, 0, 0, 0.2);
                        font-size: 12px;
                        opacity: 1;
                        z-index: 10;
                    }
                    .remove-button {
                        border: none;
                        cursor: pointer;
                        text-align: center;
                        display: none;
                        position: relative;
                        color: rgb(255, 0, 0);
                        background: 0;
                        align-items: center;
                        margin-left: 2mm;
                    }
                    .remove-button:hover::after {
                        content: attr(data-tooltip);
                        position: absolute;
                        bottom: 100%;
                        left: 50%;
                        transform: translateX(-50%);
                        background-color: #1a1a1a;
                        color: #fff;
                        padding: 5px;
                        border-radius: 5px;
                        white-space: nowrap;
                        box-shadow: 0 0 5px rgba(0, 0, 0, 0.2);
                        font-size: 12px;
                        opacity: 1;
                        z-index: 10;
                    }
                    .section-title .remove-button, .section-title .add-button {
                        display: none; /* Hide the remove button by default */
                    }
                    .section-title:hover .remove-button, .section-title:hover .add-button {
                        display: inline-block; /* Display the remove button when hovering over .section-title p */
                    }
                    .add-project-button {
                        border: none;
                        cursor: pointer;
                        text-align: center;
                        display: inline-block;
                        position: relative;
                        color: grey;
                        background: 0;
                        align-items: center;
                        margin-left: 2mm;
                    }
                    .add-project-button:hover::after {
                        content: attr(data-tooltip);
                        position: absolute;
                        bottom: 100%; /* Position above the button */
                        left: 50%;
                        transform: translateX(-50%);
                        background-color: #1a1a1a;
                        color: #fff;
                        padding: 5px;
                        border-radius: 5px;
                        white-space: nowrap;
                        box-shadow: 0 0 5px rgba(0, 0, 0, 0.2);
                        font-size: 12px;
                        opacity: 1;
                        z-index: 10;
                    }

                    .add-button1 {
                        border: none;
                        cursor: pointer;
                        text-align: center;
                        position: absolute;
                        color: grey;
                        background: 0;
                        align-items: center;
                        margin-left: 2mm;
                        left: 0;
                    }
                    .add-button1:hover::after {
                        content: attr(data-tooltip);
                        position: absolute;
                        bottom: 100%; /* Position above the button */
                        left: 50%;
                        transform: translateX(-50%);
                        background-color: #1a1a1a;
                        color: #fff;
                        padding: 5px;
                        border-radius: 5px;
                        white-space: nowrap;
                        box-shadow: 0 0 5px rgba(0, 0, 0, 0.2);
                        font-size: 12px;
                        opacity: 1;
                        z-index: 10;
                    }
                    .remove-button1 {
                        border: none;
                        cursor: pointer;
                        text-align: center;
                        position: absolute;
                        color: rgb(255, 0, 0);
                        background: 0;
                        align-items: center;
                        margin-left: 2mm;
                        right: 5px;
                    }
                    .remove-button1:hover::after {
                        content: attr(data-tooltip);
                        position: absolute;
                        bottom: 100%;
                        left: 50%;
                        transform: translateX(-50%);
                        background-color: #1a1a1a;
                        color: #fff;
                        padding: 5px;
                        border-radius: 5px;
                        white-space: nowrap;
                        box-shadow: 0 0 5px rgba(0, 0, 0, 0.2);
                        font-size: 12px;
                        opacity: 1;
                        z-index: 10;
                    }
                    /* Ruler */
                    .sets {
                        display: flex;
                        margin-left: 5px;
                        padding-left: 5px;
                    }
                    .sets button {
                        background-color: transparent;
                        border: 0;
                        cursor: pointer;
                        padding: 2mm 3mm;
                        color: white;
                    }
                    .sets button:hover {
                        background-color: #272636;
                    }
                    .sets select {
                        padding: 2mm 3mm;
                        background-color: transparent;
                        border: 0;
                        border-radius: 8px;
                        cursor: pointer;
                        color: white;
                    }
                    .sets select:hover {
                        background-color: #272636;
                    }
                    .sets select:hover  option{
                        background-color: #272636;
                    }
                    .button-container {
                        width: 100px;
                    }
                    .button-container button {
                        border: 0;
                        border-radius: 5px;
                        background-color: rgb(226, 210, 242);
                        width: 100px;
                        height: 40px;
                        font-weight: bold;
                        cursor: pointer;
                    }
                    .button-container p {
                        width: auto;
                        max-width: 200px;
                        position: absolute;
                        border: 0;
                        top: 10px;
                        left: 10%;
                        font-weight: bold;
                        cursor: pointer;
                        text-align: center;
                        font-size: 20px;
                        border-bottom: 1px solid black !important;
                        color: black !important;
                        padding: 2mm;
                    }
                    .draggable-section {
                        padding: 1mm 0;
                        margin-bottom: 5mm;
                        cursor: move;
                    }
                    #ruler {
                        position: relative;
                        width: 21cm;
                        height: 20px;
                        background: #272636;
                        margin: 0 auto;
                        display: flex;
                        align-items: center;
                        user-select: none;
                    }
                    .tick {
                        position: absolute;
                        height: 100%;
                        color: #9a9a9a;
                        font-size: 10px;
                        line-height: 20px;
                    }
                    .draggable-marker {
                        position: absolute;
                        width: 0;
                        height: 0;
                        border-left: 8px solid transparent;
                        border-right: 8px solid transparent;
                        border-top: 12px solid #ff0000; /* Triangle color */
                        cursor: ew-resize;
                        transform: translateX(-50%); /* Center align the triangle */
                        z-index: 30; /* Higher z-index to ensure it's above other elements */
                    }
                    #left-marker {
                        left: 10mm; /* Default padding for left */
                    }
                    #right-marker {
                        left: calc(210mm - 10mm); /* Default position for right marker */
                    }
                    .measure-line {
                        position: absolute;
                        width: 0.2px;
                        min-height: 100vh;
                        background-color: #ff0000;
                        display: none;
                        top: 0;
                        left: 10mm;
                        z-index: 20;
                    }
                    .back-button {
                        width: 45px;
                        height: 45px;
                        border-radius: 50%;
                        border: none;
                        background-color: #2C2C2C;
                        color: white;
                        cursor: pointer;
                        position: fixed;
                        top: 10px;
                        left: 20px;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        z-index: 1000;
                        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.2);
                        transition: background-color 0.3s;
                    }
                    .back-button i {
                        font-size: 20px;
                    }
                    .back-button:hover {
                        background-color: #3B1F4C;
                    }
                    .button-container {
                        margin-top: 20px; /* Adjust as needed */
                    }
                    /* GPT button & form */
                    .work-experience-entry {
                        margin-top: 20px;
                    }
                    ul:hover li {
                        background-color: #fef0ff;
                    }
                    .gpt-generate-form {
                        width: 500px;
                        height: auto;
                        border-radius: 10px;
                        background-color: #fff;
                        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
                        font-family: Calibri, sans-serif;
                        display: flex;
                        position: fixed; /* Fixed ensures positioning relative to the viewport */
                        top: 50%; /* Center vertically in the viewport */
                        left: 50%; /* Center horizontally in the viewport */
                        transform: translate(-50%, -50%); /* Adjust for element's own size */
                        cursor: grab; /* Dragging cursor */
                        z-index: 1000; /* Ensure it's above other elements */
                    }
                    .gpt-generate-form.dragging {
                        cursor: grabbing;
                        transform: none;
                        position: fixed; /* Fixed ensures positioning relative to the viewport */
                        top: 50%; /* Center vertically in the viewport */
                        left: 50%; /* Center horizontally in the viewport */
                        transform: translate(-50%, -50%); /* Adjust for element's own size */
                        z-index: 1000; /* Ensure it's above other elements */
                    }
                    .gpt-generate-btn {
                        position: absolute;
                        top: 50%; /* Center vertically relative to UL */
                        left: 50%; /* Center horizontally relative to UL */
                        transform: translate(-50%, -50%); /* Adjusts position to align with the center */
                        z-index: 10; /* Ensures button is on top */
                        display: none;
                        align-items: center;
                        padding: 5px 10px;
                        border: none;
                        border-radius: 8px;
                        font-size: 12px;
                        font-weight: bold;
                        color: #ffffff;
                        cursor: pointer;
                        background: linear-gradient(45deg, #ff0077, #9b00e5);
                        transition: transform 0.2s ease-in-out;
                        outline: none;
                    }
                    ul:hover .gpt-generate-btn {
                        display: inline-block;
                    }
                    .generate-btn-container {
                        display: flex;
                        justify-content: flex-end; /* Align button to the right */
                        margin-top: 10px; /* Optional: space above the button */
                    }
                    .generate-btn {
                        display: flex;
                        align-items: center;
                        padding: 10px 20px;
                        border: none;
                        border-radius: 8px; /* Rounded corners */
                        font-size: 16px;
                        font-weight: bold;
                        color: #ffffff;
                        cursor: pointer;
                        background: linear-gradient(45deg, #ff0077, #9b00e5); /* Gradient background */
                        transition: transform 0.2s ease-in-out;
                        outline: none;
                    }
                    .generate-btn i {
                        margin-right: 8px; /* Space between icon and text */
                        font-size: 18px;
                    }
                    .generate-btn:hover {
                        transform: scale(1.05); /* Slight zoom effect on hover */
                    }
                    .generate-btn:active {
                        transform: scale(0.98); /* Slight press effect on click */
                    }
                    .form-group {
                        margin-bottom: 20px;
                        padding: 0 20px;
                    }
                    .form-group label {
                        display: block;
                        font-weight: 500;
                        font-size: 14px;
                        margin-bottom: 8px;
                        color: #333;
                    }
                    .form-field {
                        width: 100%;
                        padding: 10px;
                        border: 1px solid #ccc;
                        border-radius: 5px;
                        font-size: 14px;
                        transition: border-color 0.3s;
                    }
                    .form-field:focus {
                        border-color: #DD00AC;
                        outline: none;
                    }
                    /* Close button style */
                    .form-header {
                        display: flex;
                        align-items: center;
                        justify-content: space-between; /* Aligns the close button to the top-right */
                        margin-bottom: 20px; /* Adds some space below the header */
                        cursor: default;
                        padding: 20px;
                    }
                    .close-btn {
                        background-color: transparent;
                        border: none;
                        font-size: 20px;
                        cursor: pointer;
                        color: #888;
                        transition: color 0.3s;
                        position: absolute;
                        top: 20px;
                        right: 20px; /* Adjusts to the right within the form */
                    }
                    .close-btn:hover {
                        color: #333;
                    }
                    textarea.form-field {
                        resize: none;
                    }
                    .gpt-suggestions {
                        border-top: 1px solid #ddd;
                        background-color: #DEDEDE;
                        padding: 20px;
                        border-radius: 0 0 10px 10px;
                    }
                    .bullet-point-option {
                        display: flex;
                        align-items: center;
                        padding: 10px;
                        margin-bottom: 8px;
                        border-radius: 5px;
                        cursor: pointer; /* Makes the row clickable */
                        transition: background-color 0.2s;
                        background-color: #f9f9f9;
                    }
                    .bullet-point-option:hover {
                        background-color: #f0f0f0; /* Highlight effect on hover */
                    }
                    .bullet-checkbox {
                        margin-right: 10px; /* Space between checkbox and text */
                        cursor: pointer;
                        transform: scale(1.2); /* Slightly larger checkbox */
                    }
                    .bullet-point-option span {
                        color: #333;
                        font-size: 14px;
                    }
                    .bullet-point-option input[type="checkbox"]:checked + span {
                        font-weight: bold; /* Optional: Make checked items bold */
                        color: #333;
                    }
                    /* Save as pdf */
                    .pdf-export .placeholder, 
                    .pdf-export .gpt-generate-btn, 
                    .pdf-export .remove-button, 
                    .pdf-export .drag-handle, 
                    .pdf-export .drag-handle1, 
                    .pdf-export .add-section-container,
                    .pdf-export button {
                        display: none !important; /* Hide placeholders and buttons */
                    }
                    .pdf-export ul {
                        list-style-type: disc !important; 
                    } 
                    .custom-download-btn {
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        gap: 8px; /* Spacing between icon and text */
                        background-color: #1E1E29; /* Background color similar to your layout */
                        color: #FFFFFF; /* Text color */
                        font-size: 16px;
                        font-weight: 500;
                        padding: 10px 20px;
                        border-radius: 8px;
                        border: none;
                        cursor: pointer;
                        transition: background-color 0.3s ease;
                    }
                    .custom-download-btn i {
                        font-size: 18px; /* Adjust icon size */
                        color: #EADDFF; /* Icon color similar to the one in your image */
                    }
                    .custom-download-btn:hover {
                        background-color: #3B1F4C; /* Background color on hover */
                        color: #FFFFFF; /* Text color on hover */
                    }
                    /* add section button */
                    /* Modal Styling */
                    .modal {
                        display: none;
                        position: fixed;
                        top: 50%;
                        left: 50%;
                        transform: translate(-50%, -50%);
                        background: white;
                        padding: 20px;
                        border-radius: 12px;
                        box-shadow: 0 8px 20px rgba(0, 0, 0, 0.2);
                        z-index: 1000;
                        text-align: center;
                        width: 300px;
                    }
                    .modal-header {
                        font-size: 20px;
                        color: #4A47A3;
                        margin-bottom: 15px;
                    }
                    /* Buttons inside the modal */
                    .modal-button {
                        background-color: #6A61C1;
                        color: white;
                        border: none;
                        padding: 10px 15px;
                        margin: 5px;
                        font-size: 14px;
                        border-radius: 8px;
                        cursor: pointer;
                        transition: all 0.3s ease;
                    }
                    .modal-button:hover {
                        background-color: #4A47A3;
                        transform: scale(1.05);
                    }
                    .modal-close-button {
                        background-color: #E5E5E5;
                        color: #333;
                        border: none;
                        padding: 10px 15px;
                        font-size: 14px;
                        border-radius: 8px;
                        cursor: pointer;
                        margin-top: 10px;
                        transition: all 0.3s ease;
                    }
                    .modal-close-button:hover {
                        background-color: #C5C5C5;
                    }
                    /* Add Section Button Styling */
                    .add-section-container {
                        display: none;
                        text-align: center;
                        margin: 20px 0;
                    }
                    .add-section-button {
                        background-color: #6A61C1;
                        color: white;
                        border: none;
                        padding: 12px 20px;
                        font-size: 16px;
                        font-weight: bold;
                        border-radius: 8px;
                        cursor: pointer;
                        transition: all 0.3s ease;
                    }
                    .add-section-button:hover {
                        background-color: #4A47A3;
                        transform: scale(1.1);
                    }
                    .modal-button-container {
                        width: 100%;
                        display: flex;
                        flex-direction: column;
                    }
                    #draggable-container {
                        z-index: 2;
                    }
                </style>
                <!-- customize -->
                <style>
                    .bold {
                        font-weight: bold;
                    }
                    .italic {
                        font-style: italic;
                    }
                </style>
            </head>
            <body>
                <div class="container" id="resume-container">
                    ${content}
                </div>
            </body>
            </html>
        `;

        // Load the HTML content into Puppeteer
        await page.setContent(fullHTML, { waitUntil: 'load' });

        // Set the viewport to A4 dimensions at 96 DPI (794px x 1123px)
        await page.setViewport({
            width: 794, // Width in pixels for A4 at 96 DPI
            height: 1123, // Height in pixels for A4 at 96 DPI
        });

        // Capture and save the screenshot as an A4-sized image
        await page.screenshot({
            path: screenshotPath,
            clip: {
                x: 0,
                y: 0,
                width: 794, // A4 width
                height: 1123, // A4 height
            },
        });

        await browser.close();

        // Update the preview_image_path in the database
        const query = 'UPDATE templates SET preview_image_path = ? WHERE id = ? AND user_id = ?';
        db.query(query, [`/screenshots/${id}.png`, id, userId], (err) => {
            if (err) {
                console.error('Database update error:', err);
                return res.status(500).json({ success: false, error: 'Failed to update database' });
            }
            res.json({ success: true });
        });
    } catch (error) {
        console.error('Screenshot generation error:', error);
        res.status(500).json({ success: false, error: 'Screenshot generation failed' });
    }
});
app.use('/screenshots', express.static(path.join(__dirname, 'views/screenshots')));




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
        return res.redirect('/questions');
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