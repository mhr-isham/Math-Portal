const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const app = express();
const port = process.env.PORT || 3000;

app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          "default-src": ["'self'"],
          "script-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
          "script-src-attr": ["'self'", "'unsafe-inline'"],
          "img-src": ["'self'", "data:", "https:"],
          "frame-src": ["'self'", "https://www.desmos.com", "https://www.geogebra.org"], 
          "font-src": ["'self'", "https://cdn.jsdelivr.net", "data:"],
        },
      },
    })
  );
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

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

app.post('/api/login', async (req, res) => {
    const { identifier, password } = req.body;
    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');
        const result = await client.query(
            `SELECT u.*, m.failed_login_attempts, m.user_category 
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
            return res.status(403).json({ error: "Account Locked. Reset password required." });
        }

        const validPass = await bcrypt.compare(password, user.password_hash);
        if (!validPass) {
            await client.query("UPDATE user_metadata SET failed_login_attempts = failed_login_attempts + 1 WHERE user_id = $1", [user.user_id]);
            await client.query('COMMIT');
            return res.status(400).json({ error: "Invalid Credentials" });
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

        const token = jwt.sign(
            { userId: user.user_id, username: user.username, category: user.user_category }, 
            process.env.JWT_SECRET, 
            { expiresIn: '2h' }
        );

        res.json({ 
            message: "Login successful", 
            token: token, 
            redirect: user.study_level ? "dashboard" : "step2",
            username: user.username
        });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: "Login Error" });
    } finally {
        client.release();
    }
});

app.get('/api/problems', authenticateToken, async (req, res) => {
    const { category, subcategory } = req.query;
    let query = `SELECT problem_id, title, category, subcategory, author_id FROM problems`;
    let params = [];
    
    if (category && category !== 'All') {
        query += ` WHERE category = $1`;
        params.push(category);
        if (subcategory) {
            query += ` AND subcategory = $2`;
            params.push(subcategory);
        }
    }
    
    query += ` ORDER BY created_at DESC`;

    try {
        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch problems" });
    }
});


app.get('/api/problems/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const problemRes = await pool.query(`
            SELECT p.*, u.username as author_name 
            FROM problems p
            JOIN users u ON p.author_id = u.user_id
            WHERE p.problem_id = $1
        `, [id]);
        
        if (problemRes.rows.length === 0) return res.status(404).json({ error: "Problem not found" });
        
        const problem = problemRes.rows[0];
        const statsRes = await pool.query(
            "SELECT liked_posts, disliked_posts FROM user_stats WHERE user_id = $1", 
            [req.user.userId]
        );
        
        
        const stats = statsRes.rows[0];

        delete problem.answer;
        const isLiked = stats.liked_posts.includes(problem.problem_id);
        const isDisliked = stats.disliked_posts.includes(problem.problem_id);

        res.json({ ...problem, userStatus: { isLiked, isDisliked } });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Error details" });
    }
});

app.post('/api/problems/upload', authenticateToken, async (req, res) => {
    if (parseInt(req.user.category) < 0) { 
        return res.status(403).json({ error: "Access denied. Academic privileges required." });
    }

    const { title, description, answer, category, subcategory, figureUrl } = req.body;
    
    if (!title) return res.status(400).json({ error: "Title is required" });

    try {
        await pool.query(
            `INSERT INTO problems (author_id, title, description, answer, category, subcategory, figure_url) 
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [req.user.userId, title, description, answer, category, subcategory, figureUrl]
        );
        res.json({ message: "Problem uploaded successfully!" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Upload failed" });
    }
});


app.post('/api/problems/:id/check', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { userAnswer } = req.body;
    const userId = req.user.userId;
    const problemId = parseInt(id);

    const client = await pool.connect();

    try {
        await client.query('BEGIN');


        const userStatsRes = await client.query(
            "SELECT solved_problems, attempted_problems FROM user_stats WHERE user_id = $1", 
            [userId]
        );
        const problemRes = await client.query("SELECT answer FROM problems WHERE problem_id = $1", [problemId]);

        if (problemRes.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: "Problem not found" });
        }

        const solvedArr = userStatsRes.rows[0].solved_problems || [];
        const attemptedArr = userStatsRes.rows[0].attempted_problems || [];
        const correctAnswer = problemRes.rows[0].answer;

        await client.query(
            "UPDATE problems SET total_attempts = total_attempts + 1 WHERE problem_id = $1", 
            [problemId]
        );

        if (!attemptedArr.includes(problemId)) {
            await client.query(
                "UPDATE problems SET unique_attempts = unique_attempts + 1 WHERE problem_id = $1", 
                [problemId]
            );
            await client.query(
                "UPDATE user_stats SET attempted_problems = array_append(attempted_problems, $1) WHERE user_id = $2",
                [problemId, userId]
            );
        }

        if (userAnswer.trim().toLowerCase() !== correctAnswer.trim().toLowerCase()) {
            await client.query('COMMIT'); 
            return res.json({ correct: false, message: "Incorrect, try again." });
        }
        
        if (solvedArr.includes(problemId)) {
            await client.query('COMMIT'); 
            return res.json({ correct: true, message: "Correct! (You already solved this)" });
        }

        await client.query(
            `UPDATE user_stats 
             SET solved_problems = array_append(solved_problems, $1),
                 last_submission_time = NOW()
             WHERE user_id = $2`,
            [problemId, userId]
        );

        await client.query(
            "UPDATE problems SET solve_count = solve_count + 1 WHERE problem_id = $1", 
            [problemId]
        );

        await client.query('COMMIT');
        res.json({ correct: true, message: "Correct Answer! 🎉" });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: "Server Error" });
    } finally {
        client.release();
    }
});

app.get('/api/my-problems', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT * FROM problems WHERE author_id = $1 ORDER BY created_at DESC", 
            [req.user.userId]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch your questions" });
    }
});

app.put('/api/problems/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { title, description, category, subcategory, figureUrl } = req.body;
    
    try {
        const check = await pool.query("SELECT author_id FROM problems WHERE problem_id = $1", [id]);
        if (check.rows.length === 0) return res.status(404).json({ error: "Problem not found" });
        if (check.rows[0].author_id !== req.user.userId) return res.status(403).json({ error: "You can only edit your own problems" });

        await pool.query(
            `UPDATE problems 
             SET title = $1, description = $2, category = $3, subcategory = $4, figure_url = $5 
             WHERE problem_id = $6`,
            [title, description, category, subcategory, figureUrl, id]
        );

        res.json({ message: "Problem updated successfully" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Update failed" });
    }
});

app.delete('/api/problems/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.userId;

    const client = await pool.connect();
    try {
        await client.query('BEGIN');


        const check = await client.query("SELECT author_id FROM problems WHERE problem_id = $1", [id]);
        if (check.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: "Problem not found" });
        }
        if (check.rows[0].author_id !== userId) {
            await client.query('ROLLBACK');
            return res.status(403).json({ error: "You can only delete your own problems" });
        }

        const problemId = parseInt(id);
        
        await client.query(`
            UPDATE user_stats 
            SET solved_problems = array_remove(solved_problems, $1),
                attempted_problems = array_remove(attempted_problems, $1),
                liked_posts = array_remove(liked_posts, $1),
                disliked_posts = array_remove(disliked_posts, $1)
        `, [problemId]);

        await client.query("DELETE FROM problems WHERE problem_id = $1", [problemId]);

        await client.query('COMMIT');
        res.json({ message: "Problem deleted and stats cleaned up." });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: "Delete failed" });
    } finally {
        client.release();
    }
});


app.get('/api/problems/:id/comments', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query(
            `SELECT c.comment_id, c.content, c.created_at, u.username, c.user_id 
             FROM comments c
             JOIN users u ON c.user_id = u.user_id
             WHERE c.problem_id = $1
             ORDER BY c.created_at ASC`,
            [id]
        );
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to load comments" });
    }
});


app.post('/api/problems/:id/comments', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { content } = req.body;
    
    if (!content || typeof content !== 'string' || content.trim() === "") {
        return res.status(400).json({ error: "Invalid comment content" });
    }

    if (content.length > 1000) {
        return res.status(400).json({ error: "Comment too long (max 1000 chars)" });
    }

    try {
        await pool.query(
            "INSERT INTO comments (problem_id, user_id, content) VALUES ($1, $2, $3)",
            [id, req.user.userId, content.trim()]
        );
        res.json({ message: "Comment added" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to post comment" });
    }
});

app.post('/api/problems/:id/vote', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { type } = req.body; 
    const userId = req.user.userId;

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const userStats = await client.query(
            "SELECT liked_posts, disliked_posts FROM user_stats WHERE user_id = $1", 
            [userId]
        );
        let { liked_posts, disliked_posts } = userStats.rows[0];
        const problemId = parseInt(id);

        const remove = (arr, val) => arr.filter(x => x !== val);

        if (type === 'like') {
            if (liked_posts.includes(problemId)) {
                liked_posts = remove(liked_posts, problemId);
                await client.query("UPDATE problems SET upvote_count = upvote_count - 1 WHERE problem_id = $1", [problemId]);
            } else {
                liked_posts.push(problemId);
                await client.query("UPDATE problems SET upvote_count = upvote_count + 1 WHERE problem_id = $1", [problemId]);
                
                if (disliked_posts.includes(problemId)) {
                    disliked_posts = remove(disliked_posts, problemId);
                    await client.query("UPDATE problems SET downvote_count = downvote_count - 1 WHERE problem_id = $1", [problemId]);
                }
            }
        } else if (type === 'dislike') {
            if (disliked_posts.includes(problemId)) {
                disliked_posts = remove(disliked_posts, problemId);
                await client.query("UPDATE problems SET downvote_count = downvote_count - 1 WHERE problem_id = $1", [problemId]);
            } else {
                disliked_posts.push(problemId);
                await client.query("UPDATE problems SET downvote_count = downvote_count + 1 WHERE problem_id = $1", [problemId]);

                if (liked_posts.includes(problemId)) {
                    liked_posts = remove(liked_posts, problemId);
                    await client.query("UPDATE problems SET upvote_count = upvote_count - 1 WHERE problem_id = $1", [problemId]);
                }
            }
        }
        await client.query(
            "UPDATE user_stats SET liked_posts = $1, disliked_posts = $2 WHERE user_id = $3",
            [liked_posts, disliked_posts, userId]
        );

        await client.query('COMMIT');
        res.json({ message: "Vote recorded" });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: "Voting failed" });
    } finally {
        client.release();
    }
});

app.get('/api/me', authenticateToken, async (req, res) => {
    res.json({ 
        userId: req.user.userId, 
        username: req.user.username, 
        category: req.user.category 
    });
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

app.post('/api/complete-profile', authenticateToken, async (req, res) => {
    const { studyLevel, institute, bio, phone } = req.body;
    
    const userId = req.user.userId; 

    if (!studyLevel) return res.status(400).json({ error: "Study Level is required" });
    const mandatoryLevels = ['1','2','3','4','5','6','7','8','9','10','bachelors','masters'];
    if (mandatoryLevels.includes(studyLevel) && !institute) {
        return res.status(400).json({ error: "Institute is required" });
    }

    try {
        await pool.query(
            `UPDATE users 
             SET study_level = $1, institute = $2, short_bio = $3, phone_no = $4 
             WHERE user_id = $5`,
            [studyLevel, institute, bio, phone, userId]
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
