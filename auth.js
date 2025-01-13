const passport = require('passport');
const GoogleStrategy = require( 'passport-google-oauth2' ).Strategy;
const LocalStrategy = require('passport-local').Strategy;
const mysql = require('mysql2');
const bcrypt = require('bcrypt');



const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/google/callback",
    passReqToCallback: true
  },
  function(request, accessToken, refreshToken, profile, done) {
    console.log(profile);
    const googleId = profile.id;
    const displayName = profile.displayName;
    const email = profile.emails[0].value;
    const profilePicture = profile.photos[0].value;

    // Check if user exists
    db.query('SELECT * FROM users WHERE google_id = ?', [googleId], (err, results) => {
      if (err) {
        return done(err);
      }

      if (results.length > 0) {
        // User found, update the user info
        const updateQuery = 'UPDATE users SET display_name = ?, email = ?, profile_picture = ? WHERE google_id = ?';
        db.query(updateQuery, [displayName, email, profilePicture, googleId], (err) => {
          if (err) {
            return done(err);
          }
          return done(null, results[0]);
        });
      } else {
        // User not found, insert new user
        const insertQuery = 'INSERT INTO users (google_id, display_name, email, profile_picture) VALUES (?, ?, ?, ?)';
        db.query(insertQuery, [googleId, displayName, email, profilePicture], (err, results) => {
          if (err) {
              return done(err);
          }
          const newUser = { id: results.insertId, google_id: googleId, display_name: displayName, email: email, profile_picture: profilePicture };
          return done(null, newUser);
        });
      }
    });
  }
));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  db.query('SELECT * FROM users WHERE id = ?', [id], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return done(err);
    }
    if (results.length > 0) {
      const user = results[0];
      console.log('User found:', user);
      return done(null, user);
    } else {
      console.error('User not found with ID:', id);
      return done(new Error('User not found'));
    }
  });
});

// Configure Google Strategy
passport.use(new GoogleStrategy({
  clientID: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/google/callback",
  passReqToCallback: true
},
function(request, accessToken, refreshToken, profile, done) {
  console.log(profile);
  const googleId = profile.id;
  const displayName = profile.displayName;
  const email = profile.emails[0].value;
  const profilePicture = profile.photos[0].value;

  // Check if user exists
  db.query('SELECT * FROM users WHERE google_id = ?', [googleId], (err, results) => {
    if (err) {
      return done(err);
    }

    if (results.length > 0) {
      // User found, update the user info
      const updateQuery = 'UPDATE users SET display_name = ?, email = ?, profile_picture = ? WHERE google_id = ?';
      db.query(updateQuery, [displayName, email, profilePicture, googleId], (err) => {
        if (err) {
          return done(err);
        }
        return done(null, results[0]);
      });
    } else {
      // User not found, insert new user
      const insertQuery = 'INSERT INTO users (google_id, display_name, email, profile_picture) VALUES (?, ?, ?, ?)';
      db.query(insertQuery, [googleId, displayName, email, profilePicture], (err, results) => {
        if (err) {
          return done(err);
        }
        const newUser = { id: results.insertId, google_id: googleId, display_name: displayName, email: email, profile_picture: profilePicture };
        return done(null, newUser);
      });
    }
  });
}
));

// Configure Local Strategy for email/password login
passport.use('local-login', new LocalStrategy({
  usernameField: 'Email',     // Name of the email field in your login form
  passwordField: 'Password',  // Name of the password field in your login form
  passReqToCallback: true     // Pass the request object to the callback
},
function(req, email, password, done) {
  // Find the user in the database
  db.query('SELECT * FROM users WHERE email = ?', [email], function(err, results) {
    if (err) {
      return done(err);
    }
    if (results.length === 0) {
      // No user found with that email
      return done(null, false, { message: 'Invalid email or password.' });
    }
    const user = results[0];

    // Check if the user registered via Google
    if (user.google_id && !user.password) {
      return done(null, false, { message: 'Please log in with Google.' });
    }

    // Compare the password with the hashed password in the database
    bcrypt.compare(password, user.password, function(err, isMatch) {
      if (err) {
        return done(err);
      }
      if (!isMatch) {
        return done(null, false, { message: 'Invalid email or password.' });
      }
      // Passwords match, authentication successful
      return done(null, user);
    });
  });
}
));