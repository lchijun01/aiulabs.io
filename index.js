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
    apiKey: process.env.OPENAI_API_KEY
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
        res.redirect('/access-denied');
    }
}
// Webhook endpoint must use raw body for Stripe signature verification
app.post('/webhook', bodyParser.raw({ type: 'application/json' }), handleWebhook);
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



// Stripe payment route
app.post('/create-checkout-session', async (req, res) => {
    // Check if the user is authenticated
    if (!req.user || !req.user.id || !req.user.email) {
        console.error('User not authenticated or missing data.');
        
        // Send an alert message to the frontend
        return res.status(401).json({ 
            error: { message: 'Please log in to continue.' },
            redirect: '/login'
        });
    }

    const { priceId } = req.body;

    if (!priceId) {
        return res.status(400).json({ error: { message: 'Missing priceId in request.' } });
    }

    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            mode: 'subscription',
            customer_email: req.user.email,
            metadata: { user_id: req.user.id }, // Pass user ID in metadata
            line_items: [
                {
                    price: priceId,
                    quantity: 1,
                },
            ],
            success_url: `${req.headers.origin}/dashboard?subs=success`,
            cancel_url: `${req.headers.origin}/?payment_status=cancelled`,
        });
        console.log('Metadata (User ID):', req.user.id);

        res.json({ url: session.url });
    } catch (error) {
        console.error('Stripe Error:', error.message);
        res.status(500).json({ error: { message: error.message } });
    }
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
app.get('/video', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'video.html'));
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
app.get('/questions', isLoggedIn, (req, res) => {
    const user_id = req.user.id; // Get logged-in user's ID
    res.render('questions', { user_id });
});
app.post('/questions', isLoggedIn, async (req, res) => {
    const {
        phone, location, education, field_of_study, experience,
        job_title, employer, industry, skills, career_goals, accomplishments, linkedin
    } = req.body;

    const user_id = req.user.id;

    try {
        // Insert the profile data
        await db.execute(
            `INSERT INTO user_profiles (user_id, phone, location, education, field_of_study, 
             experience, job_title, employer, industry, skills, career_goals, accomplishments, linkedin)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [user_id, phone, location, education, field_of_study, experience, job_title, employer, industry, skills, career_goals, accomplishments, linkedin]
        );

        // Mark the questionnaire as submitted
        await db.execute(
            `UPDATE users SET questionnaire_submitted = ? WHERE id = ?`,
            [true, user_id]
        );

        res.redirect('/dashboard');
    } catch (err) {
        console.error("Error saving user profile:", err);
        res.status(500).json({ error: "Failed to save user profile" });
    }
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
        const previewcssPath = 'http://localhost:3000/views/css/preview.css'; // Replace with your actual CSS path
        const fullHTML = `
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Resume</title>
                <link rel="stylesheet" href="${cssPath}">
                <link rel="stylesheet" href="${previewcssPath}">
            </head>
            <body>
                <page>
                    ${content}
                </page>
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