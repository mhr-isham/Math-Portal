const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const helmet = require('helmet');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

app.use(helmet()); 
app.use(cors());
app.use(express.json()); 
app.use(express.static('public'));


const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: 5432,
});


const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: true,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});


const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();


app.post('/api/login', async (req, res) => {
    const { identifier, password } = req.body;

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const result = await client.query(
            `SELECT u.*, m.failed_login_attempts 
             FROM users u
             JOIN user_metadata m ON u.user_id = m.user_id
             WHERE u.email = $1 OR u.username = $1`, 
            [identifier]
        );

        if (result.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: "User not found" });
        }

        const user = result.rows[0];

        if (user.failed_login_attempts >= 5) {
            await client.query('ROLLBACK');
            return res.status(403).json({ error: "Account Locked. Too many failed attempts. Please reset your password." });
        }

        const validPass = await bcrypt.compare(password, user.password_hash);
        
        if (!validPass) {
            await client.query(
                "UPDATE user_metadata SET failed_login_attempts = failed_login_attempts + 1 WHERE user_id = $1",
                [user.user_id]
            );
            await client.query('COMMIT');
            
            const attemptsLeft = 5 - (user.failed_login_attempts + 1);
            return res.status(400).json({ error: `Invalid Credentials. ${attemptsLeft} attempts remaining.` });
        }

        if (!user.is_verified) {
            await client.query('ROLLBACK');
            return res.status(403).json({ error: "Please verify your email first." });
        }


        await client.query(
            `UPDATE user_metadata 
             SET failed_login_attempts = 0,
                 last_login_time = NOW(),
                 last_login_ip = $2,
                 last_login_device = $3
             WHERE user_id = $1`,
            [user.user_id, req.ip, req.headers['user-agent']]
        );

        await client.query('COMMIT');

        if (!user.study_level) {
            return res.json({ 
                message: "Login successful", 
                redirect: "step2", 
                username: user.username 
            });
        }

        res.json({ message: "Login successful", redirect: "dashboard", username: user.username });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: "Login Error" });
    } finally {
        client.release();
    }
});


app.post('/api/reset-request', async (req, res) => {
    const { email, username } = req.body;

    try {
        const result = await pool.query(
            "SELECT user_id FROM users WHERE email = $1 AND username = $2",
            [email, username]
        );

        if (result.rows.length === 0) {
            return res.status(400).json({ error: "No account found matching that Email and Username" });
        }

        const userId = result.rows[0].user_id;
        const otp = generateOTP();

        await pool.query(
            "UPDATE users SET otp_code = $1, otp_expires = NOW() + INTERVAL '15 minutes' WHERE user_id = $2",
            [otp, userId]
        );

        await transporter.sendMail({
            from: `"NDMC Security" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: "Your Password Reset OTP",
            html: `<h3>Password Reset Request</h3>
                   <p>Your OTP code is: <b style="font-size: 20px; color: #786fef;">${otp}</b></p>
                   <p>This code expires in 15 minutes.</p>`
        });

        res.json({ message: "OTP sent to your email." });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to send OTP" });
    }
});

app.post('/api/reset-confirm', async (req, res) => {
    const { username, otp, newPassword } = req.body;

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const check = await client.query(
            `SELECT user_id FROM users 
             WHERE username = $1 AND otp_code = $2 AND otp_expires > NOW()`,
            [username, otp]
        );

        if (check.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: "Invalid or Expired OTP" });
        }

        const userId = check.rows[0].user_id;
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(newPassword, salt);

        await client.query(
            "UPDATE users SET password_hash = $1, otp_code = NULL, otp_expires = NULL WHERE user_id = $2",
            [hash, userId]
        );

        await client.query(
            `UPDATE user_metadata 
             SET failed_login_attempts = 0, 
                 last_reset_time = NOW() 
             WHERE user_id = $1`,
            [userId]
        );

        await client.query('COMMIT');
        res.json({ message: "Password updated successfully! You can now login." });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: "Reset Failed" });
    } finally {
        client.release();
    }
});

app.post('/api/register', async (req, res) => {
    const { username, email, password, fullName } = req.body;

    if (!username || !email || !password || !fullName) {
        return res.status(400).json({ error: "All fields are required" });
    }

    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        const checkUser = await client.query(
            "SELECT email, username FROM users WHERE email = $1 OR username = $2", 
            [email, username]
        );
        
        if (checkUser.rows.length > 0) {
            const existing = checkUser.rows[0];
            await client.query('ROLLBACK');
            return res.status(409).json({ 
                error: "User exists", 
                field: existing.email === email ? "email" : "username" 
            });
        }

        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(password, salt);
        const token = crypto.randomBytes(32).toString('hex');

        const userRes = await client.query(
            `INSERT INTO users (username, email, password_hash, full_name, login_method, is_verified, verification_token) 
             VALUES ($1, $2, $3, $4, 'email', FALSE, $5) 
             RETURNING user_id`,
            [username, email, hash, fullName, token]
        );
        const userId = userRes.rows[0].user_id;

        await client.query(
            `INSERT INTO user_metadata (user_id, registration_ip, registration_device, user_category, registration_time) 
             VALUES ($1, $2, $3, '-1', NOW())`,
            [userId, req.ip, req.headers['user-agent']]
        );

        await client.query(
            `INSERT INTO user_stats (user_id, current_rating) VALUES ($1, 0)`,
            [userId]
        );

        const verifyLink = `${process.env.BASE_URL}/verify.html?token=${token}`;
        await transporter.sendMail({
            from: `"NDMC Portal" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: "Verify your NDMC Account",
            html: `<h3>Welcome ${fullName}!</h3>
                   <p>Please verify your email within 24 hours to activate your account.</p>
                   <a href="${verifyLink}" style="padding:10px 20px; background:#786fef; color:white; text-decoration:none; border-radius:5px;">Verify Email</a>`
        });

        await client.query('COMMIT');
        res.json({ message: "Registration successful! Please check your email." });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: "Server Error", details: err.message });
    } finally {
        client.release();
    }
});

app.post('/api/verify', async (req, res) => {
    const { token } = req.body;
    
    try {
        const userRes = await pool.query(
            `SELECT u.user_id, m.registration_time 
             FROM users u
             JOIN user_metadata m ON u.user_id = m.user_id
             WHERE u.verification_token = $1`, 
            [token]
        );

        if (userRes.rows.length === 0) {
            return res.status(400).json({ error: "Invalid Token" });
        }

        const user = userRes.rows[0];
        const regTime = new Date(user.registration_time);
        const now = new Date();
        const diffHours = (now - regTime) / 36e5;

        if (diffHours > 24) {
            await pool.query("DELETE FROM users WHERE user_id = $1", [user.user_id]);
            return res.status(400).json({ error: "Token expired. Registration deleted. Please register again." });
        }

        await pool.query(
            "UPDATE users SET is_verified = TRUE, verification_token = NULL WHERE user_id = $1", 
            [user.user_id]
        );

        res.json({ message: "Email Verified! You can now login." });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Verification Failed" });
    }
});

app.post('/api/complete-profile', async (req, res) => {
    const { username, studyLevel, institute, bio, phone } = req.body;

    if (!studyLevel) return res.status(400).json({ error: "Study Level is required" });
    
    const mandatoryLevels = ['1','2','3','4','5','6','7','8','9','10','bachelors','masters'];
    if (mandatoryLevels.includes(studyLevel) && !institute) {
        return res.status(400).json({ error: "Institute is required for this study level" });
    }

    try {
        await pool.query(
            `UPDATE users 
             SET study_level = $1, institute = $2, short_bio = $3, phone_no = $4 
             WHERE username = $5`,
            [studyLevel, institute, bio, phone, username]
        );

        res.json({ message: "Profile Updated", redirect: "dashboard" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Update Failed" });
    }
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});