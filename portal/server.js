const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const app = express();
const port = process.env.PORT || 3000;
const { OAuth2Client } = require('google-auth-library');
const { rootCertificates } = require('tls');
const { OutgoingMessage } = require('http');
const { REPL_MODE_SLOPPY } = require('repl');
const { nextTick } = require('process');
const { Stream } = require('nodemailer/lib/xoauth2');
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const profileStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        const dir = 'public/uploads';
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: function (req, file, cb) {
        cb(null, req.user.userId + '-' + Date.now() + path.extname(file.originalname));
    }
});
const uploadProfile = multer({ storage: profileStorage, limits: { fileSize: 2000000 } });

const problemStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        const dir = 'public/uploads/questions/figures';
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: function (req, file, cb) {
        cb(null, req.user.userId + '-' + Date.now() + path.extname(file.originalname));
    }
});
const uploadProblem = multer({ storage: problemStorage, limits: { fileSize: 2000000 } });
const suggestionStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = 'public/uploads/solutions';
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: (req, file, cb) => cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname))
});
const uploadSolutions = multer({ storage: suggestionStorage, limits: { fileSize: 2000000 } });


app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          "default-src": ["'self'"],
          "script-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://accounts.google.com", "https://g.notify.usercontent.com"],
          "script-src-attr": ["'self'", "'unsafe-inline'"],
          "img-src": ["'self'", "data:", "https:", "https://lh3.googleusercontent.com"], 
          "frame-src": ["'self'", "https://www.desmos.com", "https://www.geogebra.org", "https://accounts.google.com"], 
          "font-src": ["'self'", "https://cdn.jsdelivr.net", "data:", "https://fonts.gstatic.com"],
          "connect-src": ["'self'", "https://accounts.google.com", "https://www.googleapis.com"]
        },
      },
      referrerPolicy: {
        policy: "no-referrer-when-downgrade",
      },
      crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" }, 
      crossOriginEmbedderPolicy: false,
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


async function recalcUserRating(client, userId) {
    const ratingQuery = `
        SELECT COALESCE(SUM(
            p.dynamic_score * POWER(0.9, COALESCE(ac.count, 0))
        ), 0) as total
        FROM user_stats us
        JOIN problems p ON p.problem_id = ANY(us.solved_problems)
        LEFT JOIN attempt_counts ac ON ac.user_id = us.user_id AND ac.problem_id = p.problem_id
        WHERE us.user_id = $1
    `;
    const r = await client.query(ratingQuery, [userId]);
    const newRating = parseFloat(r.rows[0].total);

    await client.query("UPDATE user_stats SET current_rating = $1 WHERE user_id = $2", [newRating, userId]);
}

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));
app.get('/join', (req, res) => res.sendFile(path.join(__dirname, 'public/join.html')));
app.get('/problems', (req, res) => res.sendFile(path.join(__dirname, 'public/problems.html')));
app.get('/problems/:id', (req, res) => res.sendFile(path.join(__dirname, 'public/problem.html')));
app.get('/profile', (req, res) => res.sendFile(path.join(__dirname, 'public/profile.html')));
app.get('/academics', (req, res) => res.sendFile(path.join(__dirname, 'public/academic.html')));

app.get('/vcontest', (req, res) => res.sendFile(path.join(__dirname, 'public/vcontest.html')));
app.get('/my-contest', (req, res) => res.sendFile(path.join(__dirname, 'public/my-contest.html')));
app.get('/hypos', (req, res) => res.send('Admin Dashboard Coming Soon'));

app.get('/leaderboard', (req, res) => res.sendFile(path.join(__dirname, 'public/leaderboard.html')));
app.get('/u/:username', (req, res) => res.sendFile(path.join(__dirname, 'public/user.html')));

app.post('/api/auth/google', async (req, res) => {
    const { token } = req.body;
    
    try {
        const ticket = await googleClient.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });
        const { email, name, sub } = ticket.getPayload();

        const userRes = await pool.query(
            `SELECT u.*, m.user_category 
             FROM users u
             LEFT JOIN user_metadata m ON u.user_id = m.user_id
             WHERE u.email = $1`, 
            [email]
        );

        if (userRes.rows.length > 0) {
            const user = userRes.rows[0];
            
            if (!user.google_id) {
                let newMethod = user.login_method.includes('google') ? user.login_method : user.login_method + ',google';
                await pool.query("UPDATE users SET google_id = $1, login_method = $2 WHERE user_id = $3", [sub, newMethod, user.user_id]);
            }

            const jwtToken = jwt.sign(
                { userId: user.user_id, username: user.username, category: user.user_category },
                process.env.JWT_SECRET,
                { expiresIn: '2h' }
            );

            return res.json({ action: 'login_success', token: jwtToken });

        } else {
            return res.json({ 
                action: 'register_needed', 
                googleData: { email, name, sub } 
            });
        }

    } catch (err) {
        console.error(err);
        res.status(400).json({ error: "Invalid Google Token" });
    }
});

app.post('/api/auth/google/finalize', async (req, res) => {
    const { email, fullName, googleId, username, password } = req.body;

    const check = await pool.query("SELECT user_id FROM users WHERE username = $1", [username]);
    if (check.rows.length > 0) return res.status(409).json({ error: "Username already taken" });

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        let passwordHash = null;
        let loginMethod = 'google';

        if (password && password.trim() !== "") {
            const salt = await bcrypt.genSalt(10);
            passwordHash = await bcrypt.hash(password, salt);
            loginMethod = 'email,google';
        }

        const userRes = await client.query(
            `INSERT INTO users (username, email, password_hash, full_name, login_method, is_verified, google_id) 
             VALUES ($1, $2, $3, $4, $5, TRUE, $6) 
             RETURNING user_id`,
            [username, email, passwordHash, fullName, loginMethod, googleId]
        );
        const userId = userRes.rows[0].user_id;

        await client.query(
            `INSERT INTO user_metadata (user_id, registration_ip, registration_device, user_category, registration_time) 
             VALUES ($1, $2, $3, '-1', NOW())`,
            [userId, req.ip, req.headers['user-agent']]
        );
        await client.query("INSERT INTO user_stats (user_id, current_rating) VALUES ($1, 0)", [userId]);

        await client.query('COMMIT');

        const token = jwt.sign(
            { userId: userId, username: username, category: '-1' }, 
            process.env.JWT_SECRET, 
            { expiresIn: '2h' }
        );

        res.json({ token });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: "Registration Failed" });
    } finally {
        client.release();
    }
});

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
            redirect: user.study_level ? "/" : "step2",
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
    const { category, subcategory, sort, filter, search } = req.query;
    const page = parseInt(req.query.page) || 1;
    const limit = 20;
    const offset = (page - 1) * limit;
    
    let baseQuery = `
        FROM problems p 
        JOIN users u ON p.author_id = u.user_id 
        LEFT JOIN attempt_counts ac ON p.problem_id = ac.problem_id AND ac.user_id = $1
    `;
    let params = [req.user.userId];
    let conditions = [];

    if (search && search.trim() !== '') {
        const i = params.length + 1;
        conditions.push(`(p.title ILIKE $${i} OR p.title_bn ILIKE $${i} OR p.category ILIKE $${i})`);
        params.push(`%${search}%`);
    }

    if (category && category !== 'All') {
        conditions.push(`p.category = $${params.length + 1}`);
        params.push(category);
    }
    if (subcategory) {
        conditions.push(`p.subcategory = $${params.length + 1}`);
        params.push(subcategory);
    }

    if (filter === 'bookmarked') {
        conditions.push(`p.problem_id = ANY(SELECT UNNEST(bookmarked_problems) FROM user_stats WHERE user_id = $1)`);
    } else if (filter === 'solved') {
        conditions.push(`p.problem_id = ANY(SELECT UNNEST(solved_problems) FROM user_stats WHERE user_id = $1)`);
    } else if (filter === 'unsolved') {
        conditions.push(`NOT (p.problem_id = ANY(SELECT UNNEST(solved_problems) FROM user_stats WHERE user_id = $1))`);
    }

    if (conditions.length > 0) baseQuery += " WHERE " + conditions.join(" AND ");

    const countQuery = `SELECT COUNT(*) ${baseQuery}`;
    const countRes = await pool.query(countQuery, params);
    const totalItems = parseInt(countRes.rows[0].count);
    const totalPages = Math.ceil(totalItems / limit);

    let dataQuery = `
        SELECT p.*, u.full_name as author_name, COALESCE(ac.count, 0) as user_attempts 
        ${baseQuery}
    `;
    if (sort === 'vote_desc') dataQuery += ` ORDER BY (p.upvote_count - p.downvote_count) DESC`;
    else if (sort === 'vote_asc') dataQuery += ` ORDER BY (p.upvote_count - p.downvote_count) ASC`;
    else if (sort === 'ratio_desc') dataQuery += ` ORDER BY (CASE WHEN p.unique_attempts > 0 THEN (p.solve_count::float / p.unique_attempts) ELSE 0 END) DESC`;
    else if (sort === 'ratio_asc') dataQuery += ` ORDER BY (CASE WHEN p.unique_attempts > 0 THEN (p.solve_count::float / p.unique_attempts) ELSE 0 END) ASC`;
    else dataQuery += ` ORDER BY p.created_at DESC`;

    dataQuery += ` LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limit, offset);

    try {
        const result = await pool.query(dataQuery, params);
        const statsRes = await pool.query("SELECT solved_problems, bookmarked_problems FROM user_stats WHERE user_id = $1", [req.user.userId]);
        const solvedIds = statsRes.rows[0]?.solved_problems || [];
        const bookmarkIds = statsRes.rows[0]?.bookmarked_problems || [];
        const contestSolvedIds = statsRes.rows[0]?.contest_solved_problems || [];

        const problems = result.rows.map(p => {
            const baseline = p.initial_score * 0.5;
            let potential = parseFloat(p.dynamic_score) * Math.pow(0.9, parseInt(p.user_attempts));
            if (potential < baseline) potential = baseline;

            return {
                ...p,
                is_solved: solvedIds.includes(p.problem_id),
                is_bookmarked: bookmarkIds.includes(p.problem_id),
                is_contest_solved: contestSolvedIds.includes(p.problem_id),
                user_potential_score: potential.toFixed(2)
            };
        });

        res.json({ problems, totalPages, currentPage: page });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch problems" });
    }
});

app.get('/api/problems/search', authenticateToken, async (req, res) => {
    const { q } = req.query;
    try {
        const result = await pool.query(`
            SELECT problem_id, title, title_bn, category FROM problems 
            WHERE title ILIKE $1 OR title_bn ILIKE $1 
            LIMIT 20`, [`%${q}%`]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: "Search failed" }); }
});


app.get('/api/problems/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const problemRes = await pool.query(`
            SELECT p.*, u.full_name as author_name, u.username 
            FROM problems p
            JOIN users u ON p.author_id = u.user_id
            WHERE p.problem_id = $1
        `, [id]);
        
        if (problemRes.rows.length === 0) return res.status(404).json({ error: "Problem not found" });
        
        const problem = problemRes.rows[0];
        const statsRes = await pool.query("SELECT liked_posts, disliked_posts, bookmarked_problems, contest_solved_problems FROM user_stats WHERE user_id = $1", [req.user.userId]);
        const stats = statsRes.rows[0];
        
        const contestSolved = stats.contest_solved_problems || [];
        const attemptRes = await pool.query("SELECT count FROM attempt_counts WHERE user_id = $1 AND problem_id = $2", [req.user.userId, id]);
        const attempts = attemptRes.rows.length > 0 ? attemptRes.rows[0].count : 0;

        const prevRes = await pool.query("SELECT problem_id FROM problems WHERE problem_id < $1 ORDER BY problem_id DESC LIMIT 1", [id]);
        const nextRes = await pool.query("SELECT problem_id FROM problems WHERE problem_id > $1 ORDER BY problem_id ASC LIMIT 1", [id]);

        delete problem.answer;

        const isLiked = stats.liked_posts.includes(problem.problem_id);
        const isDisliked = stats.disliked_posts.includes(problem.problem_id);

        const baseline = problem.initial_score * 0.5;
        let potential = parseFloat(problem.dynamic_score) * Math.pow(0.9, attempts);
        if (potential < baseline) potential = baseline;

        res.json({ 
            ...problem, 
            userStatus: { 
                isLiked: stats.liked_posts.includes(problem.problem_id),
                isDisliked: stats.disliked_posts.includes(problem.problem_id),
                isBookmarked: stats.bookmarked_problems.includes(problem.problem_id)
            },
            user_potential_score: potential.toFixed(2),
            prevId: prevRes.rows.length > 0 ? prevRes.rows[0].problem_id : null,
            nextId: nextRes.rows.length > 0 ? nextRes.rows[0].problem_id : null 
        });

    } catch (err) {
        res.status(500).json({ error: "Error details" });
    }
});


app.post('/api/problems/upload', authenticateToken, uploadProblem.single('figure'), async (req, res) => {
    try {
        const userMeta = await pool.query("SELECT user_category FROM user_metadata WHERE user_id = $1", [req.user.userId]);
        if (parseInt(userMeta.rows[0]?.user_category) < 0) return res.status(403).json({ error: "Access denied." });
    } catch (err) { return res.status(500).json({ error: "Auth Error" }); }

    const { 
        title, description, answer, category, subcategory, score, 
        errorMargin, rangeStart, rangeEnd, answerType, 
        titleBn, descriptionBn 
    } = req.body;
    
    if (!title && !titleBn) return res.status(400).json({ error: "Title is required (English or Bengali)" });

    const initScore = score ? parseInt(score) : 10;
    const type = answerType || 'numeric';

    let eMargin = null, rStart = null, rEnd = null;
    if (type === 'numeric') {
        eMargin = errorMargin ? parseFloat(errorMargin) : null;
        rStart = rangeStart ? parseFloat(rangeStart) : null;
        rEnd = rangeEnd ? parseFloat(rangeEnd) : null;
    }

    let figureUrl = null;
    if (req.file) figureUrl = `/uploads/questions/figures/${req.file.filename}`;

    try {
        await pool.query(
            `INSERT INTO problems (
                author_id, title, description, answer, category, subcategory, figure_url, 
                initial_score, dynamic_score, error_margin, range_start, range_end,
                answer_type, title_bn, description_bn
            ) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, $9, $10, $11, $12, $13, $14)`, 
            [
                req.user.userId, title || null, description || null, answer, category, subcategory, figureUrl, 
                initScore, eMargin, rStart, rEnd, type, titleBn || null, descriptionBn || null
            ]
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

        const problemRes = await client.query(
            "SELECT answer, initial_score, dynamic_score, error_margin, range_start, range_end, solve_count FROM problems WHERE problem_id = $1 FOR UPDATE", 
            [problemId]
        );
        
        if (problemRes.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: "Problem not found" });
        }
        
        const prob = problemRes.rows[0];
        const oldDynamicScore = parseFloat(prob.dynamic_score);

        let isCorrect = false;
        if (userAnswer.trim().toLowerCase() === prob.answer.trim().toLowerCase()) {
            isCorrect = true;
        } else if (!isNaN(parseFloat(userAnswer))) {
            const uVal = parseFloat(userAnswer);
            if (prob.range_start !== null && prob.range_end !== null) {
                if (uVal >= parseFloat(prob.range_start) && uVal <= parseFloat(prob.range_end)) isCorrect = true;
            }
            if (!isCorrect && prob.error_margin !== null && !isNaN(parseFloat(prob.answer))) {
                if (Math.abs(uVal - parseFloat(prob.answer)) <= parseFloat(prob.error_margin)) isCorrect = true;
            }
        }

        await client.query(
            "INSERT INTO submission_logs (user_id, problem_id, is_correct, submitted_answer, submitted_at) VALUES ($1, $2, $3, $4, NOW())",
            [userId, problemId, isCorrect, userAnswer]
        );

        if (!isCorrect) {
            await client.query(
                `INSERT INTO attempt_counts (user_id, problem_id, count) VALUES ($1, $2, 1) 
                 ON CONFLICT (user_id, problem_id) DO UPDATE SET count = attempt_counts.count + 1`,
                [userId, problemId]
            );
            await client.query("UPDATE problems SET total_attempts = total_attempts + 1 WHERE problem_id = $1", [problemId]);
            
            const userStats = await client.query("SELECT attempted_problems FROM user_stats WHERE user_id = $1", [userId]);
            if (!userStats.rows[0].attempted_problems.includes(problemId)) {
                await client.query("UPDATE problems SET unique_attempts = unique_attempts + 1 WHERE problem_id = $1", [problemId]);
                await client.query("UPDATE user_stats SET attempted_problems = array_append(attempted_problems, $1) WHERE user_id = $2", [problemId, userId]);
            }
            
            await client.query('COMMIT'); 
            return res.json({ correct: false, message: "Incorrect, try again." });
        }

        const userStatsRes = await client.query("SELECT solved_problems FROM user_stats WHERE user_id = $1", [userId]);
        const solvedArr = userStatsRes.rows[0].solved_problems || [];

        if (solvedArr.includes(problemId)) {
            await client.query('COMMIT'); 
            return res.json({ correct: true, message: "Correct! (You already solved this)" });
        }
        const baseline = prob.initial_score * 0.5;
        let newDynamicScore = oldDynamicScore * 0.99;
        if (newDynamicScore < baseline) newDynamicScore = baseline;

        await client.query(
            `UPDATE problems 
             SET solve_count = solve_count + 1, 
                 total_attempts = total_attempts + 1,
                 unique_attempts = unique_attempts + 1, 
                 dynamic_score = $2
             WHERE problem_id = $1`, 
            [problemId, newDynamicScore]
        );
        await client.query(
            "UPDATE user_stats SET solved_problems = array_append(solved_problems, $1), last_submission_time = NOW() WHERE user_id = $2",
            [problemId, userId]
        );

        if (!userStatsRes.rows[0].attempted_problems?.includes(problemId)) {
             await client.query("UPDATE user_stats SET attempted_problems = array_append(attempted_problems, $1) WHERE user_id = $2", [problemId, userId]);
        }
        
        await recalcUserRating(client, userId);
        const scoreDiff = oldDynamicScore - newDynamicScore;
        
        if (scoreDiff > 0) {
            await client.query(`
                UPDATE user_stats us
                SET current_rating = current_rating - ($1 * POWER(0.9, COALESCE(ac.count, 0)))
                FROM attempt_counts ac
                WHERE us.user_id = ac.user_id 
                  AND ac.problem_id = $2 
                  AND $2 = ANY(us.solved_problems) 
                  AND us.user_id != $3
            `, [scoreDiff, problemId, userId]);
        }

        const updatedStats = await client.query("SELECT solved_problems FROM user_stats WHERE user_id = $1", [userId]);
        if (updatedStats.rows[0].solved_problems.length === 10) {
            await client.query("UPDATE users SET can_suggest = TRUE WHERE user_id = $1", [userId]);
             await client.query("INSERT INTO notifications (user_id, message, link) VALUES ($1, $2, $3)", 
                [userId, "🎉 You've solved 10 problems! You can now suggest your own problems.", "/suggest"]);
        }

        await client.query('COMMIT');
        
        const attemptsRes = await pool.query("SELECT count FROM attempt_counts WHERE user_id = $1 AND problem_id = $2", [userId, problemId]);
        const attempts = attemptsRes.rows[0]?.count || 0;
        const pointsEarned = newDynamicScore * Math.pow(0.9, attempts);

        res.json({ correct: true, message: `Correct Answer! You earned ${pointsEarned.toFixed(2)} points.` });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: "Server Error" });
    } finally {
        client.release();
    }
});

app.get('/api/auth/config', (req, res) => {
    res.json({ clientId: process.env.GOOGLE_CLIENT_ID });
});


app.get('/api/users/:username/activity', async (req, res) => {
    const { username } = req.params;
    try {
        const userRes = await pool.query("SELECT user_id FROM users WHERE username = $1", [username]);
        if (userRes.rows.length === 0) return res.status(404).json({ error: "User not found" });
        const userId = userRes.rows[0].user_id;

        const activityRes = await pool.query(`
            SELECT DATE(submitted_at)::text as date, COUNT(*) as count 
            FROM submission_logs 
            WHERE user_id = $1 AND submitted_at > NOW() - INTERVAL '1 year'
            GROUP BY DATE(submitted_at)
        `, [userId]);
        const activityMap = {};
        activityRes.rows.forEach(row => {
            activityMap[row.date] = parseInt(row.count);
        });

        res.json(activityMap);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to load activity" });
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

app.put('/api/problems/:id', authenticateToken, uploadProblem.single('figure'), async (req, res) => {
    const { id } = req.params;
    const { title, description, answer, category, subcategory, score, errorMargin, rangeStart, rangeEnd } = req.body;
    const problemId = parseInt(id);

    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');

        const check = await client.query("SELECT author_id, figure_url, answer, initial_score FROM problems WHERE problem_id = $1", [problemId]);
        if (check.rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: "Problem not found" }); }
        if (check.rows[0].author_id !== req.user.userId) { await client.query('ROLLBACK'); return res.status(403).json({ error: "Permission denied" }); }

        const oldAnswer = check.rows[0].answer;
        const oldScore = check.rows[0].initial_score;
        let figureUrl = check.rows[0].figure_url; 
        if (req.file) figureUrl = `/uploads/questions/figures/${req.file.filename}`;

        const initScore = score ? parseInt(score) : 10;
        const eMargin = errorMargin ? parseFloat(errorMargin) : null;
        const rStart = rangeStart ? parseFloat(rangeStart) : null;
        const rEnd = rangeEnd ? parseFloat(rangeEnd) : null;

        await client.query(
            `UPDATE problems 
             SET title = $1, description = $2, answer = $3, category = $4, subcategory = $5, figure_url = $6, 
                 initial_score = $7, error_margin = $8, range_start = $9, range_end = $10
             WHERE problem_id = $11`,
            [title, description, answer, category, subcategory, figureUrl, initScore, eMargin, rStart, rEnd, problemId]
        );

        const answerChanged = (answer && answer !== oldAnswer);
        const scoreChanged = (initScore !== oldScore);

        if (answerChanged || scoreChanged) {
            console.log(`Regrading Problem ${problemId}...`);
            const logs = await client.query("SELECT log_id, user_id, submitted_answer FROM submission_logs WHERE problem_id = $1", [problemId]);

            const correctUsers = new Set();
            
            for (let log of logs.rows) {
                let isCorrect = false;
                const uAns = log.submitted_answer;
                
                if (uAns) { 
                    if (uAns.trim().toLowerCase() === answer.trim().toLowerCase()) isCorrect = true;
                    else if (!isNaN(parseFloat(uAns))) {
                        const uVal = parseFloat(uAns);
                        if (rStart !== null && rEnd !== null && uVal >= rStart && uVal <= rEnd) isCorrect = true;
                        if (!isCorrect && eMargin !== null && Math.abs(uVal - parseFloat(answer)) <= eMargin) isCorrect = true;
                    }
                }
                
                await client.query("UPDATE submission_logs SET is_correct = $1 WHERE log_id = $2", [isCorrect, log.log_id]);
                if (isCorrect) correctUsers.add(log.user_id);
            }

            const solveCount = correctUsers.size;
            const baseline = initScore * 0.5;
            let newDynamic = initScore * Math.pow(0.99, solveCount);
            if (newDynamic < baseline) newDynamic = baseline;

            await client.query(
                "UPDATE problems SET solve_count = $1, dynamic_score = $2 WHERE problem_id = $3",
                [solveCount, newDynamic, problemId]
            );
            const allInteractedUsers = [...new Set(logs.rows.map(l => l.user_id))];

            for (let uid of allInteractedUsers) {
                const shouldBeSolved = correctUsers.has(uid);
                
                if (shouldBeSolved) {
                    await client.query("UPDATE user_stats SET solved_problems = array_append(solved_problems, $1) WHERE user_id = $2 AND NOT ($1 = ANY(solved_problems))", [problemId, uid]);
                } else {
                    await client.query("UPDATE user_stats SET solved_problems = array_remove(solved_problems, $1) WHERE user_id = $2", [problemId, uid]);
                }

                const failCountRes = await client.query("SELECT COUNT(*) FROM submission_logs WHERE user_id=$1 AND problem_id=$2 AND is_correct=FALSE", [uid, problemId]);
                const failCount = parseInt(failCountRes.rows[0].count);
                
                await client.query(`
                    INSERT INTO attempt_counts (user_id, problem_id, count) VALUES ($1, $2, $3)
                    ON CONFLICT (user_id, problem_id) DO UPDATE SET count = $3
                `, [uid, problemId, failCount]);
                await recalcUserRating(client, uid);
            }
        }

        await client.query('COMMIT');
        res.json({ message: "Problem updated and regraded successfully" });

    } catch (err) { 
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: "Update failed" }); 
    } finally {
        client.release();
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

app.post('/api/problems/:id/comments', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { content } = req.body;
    const userId = req.user.userId;

    if (!content || content.trim() === "") {
        return res.status(400).json({ error: "Comment cannot be empty" });
    }

    try {
        await pool.query(
            "INSERT INTO comments (problem_id, user_id, content) VALUES ($1, $2, $3)",
            [id, userId, content]
        );
        res.json({ message: "Comment posted successfully" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to post comment" });
    }
});

app.get('/api/problems/:id/comments', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query(
            `SELECT c.comment_id, c.content, c.created_at, u.username, m.profile_pic_url 
             FROM comments c
             JOIN users u ON c.user_id = u.user_id
             LEFT JOIN user_metadata m ON u.user_id = m.user_id
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

app.get('/api/profile/me', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT u.username, u.email, u.full_name, u.institute, u.study_level, u.phone_no, u.short_bio, u.can_suggest,
                   m.date_of_birth, m.profile_pic_url,
                   m.twitter_url, m.instagram_url, m.facebook_url, m.website_url
            FROM users u
            JOIN user_metadata m ON u.user_id = m.user_id
            WHERE u.user_id = $1
        `, [req.user.userId]);
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch profile" });
    }
    });

    app.post('/api/profile/update', authenticateToken, async (req, res) => {
        const { full_name, phone_no, short_bio, institute, study_level, dob, twitter, instagram, facebook, website } = req.body;
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            await client.query(
                "UPDATE users SET full_name=$1, phone_no=$2, short_bio=$3, institute=$4, study_level=$5 WHERE user_id=$6",
                [full_name, phone_no, short_bio, institute, study_level, req.user.userId]
            );
            await client.query(
                `UPDATE user_metadata 
                 SET date_of_birth=$1, twitter_url=$2, instagram_url=$3, facebook_url=$4, website_url=$5 
                 WHERE user_id=$6`,
                [dob || null, twitter, instagram, facebook, website, req.user.userId]
            );
            await client.query('COMMIT');
            res.json({ message: "Profile updated" });
        } catch (err) {
            await client.query('ROLLBACK');
            console.error(err);
            res.status(500).json({ error: "Update failed" });
        } finally { client.release(); }
    });

app.post('/api/profile/upload-photo', authenticateToken, uploadProfile.single('photo'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });
    try {
        const url = `/uploads/${req.file.filename}`;
        await pool.query("UPDATE user_metadata SET profile_pic_url = $1 WHERE user_id = $2", [url, req.user.userId]);
        res.json({ url });
    } catch (err) {
        res.status(500).json({ error: "Database error" });
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

        res.json({ message: "Profile Updated", redirect: "/" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Update Failed" });
    }
});

app.post('/api/profile/change-password', authenticateToken, async (req, res) => {
    const { oldPass, newPass } = req.body;
    try {
        const u = await pool.query("SELECT password_hash FROM users WHERE user_id = $1", [req.user.userId]);
        if (!u.rows[0].password_hash) return res.status(400).json({ error: "You use Google Login (no password set)." });

        const valid = await bcrypt.compare(oldPass, u.rows[0].password_hash);
        if (!valid) return res.status(403).json({ error: "Incorrect old password" });

        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(newPass, salt);
        await pool.query("UPDATE users SET password_hash = $1 WHERE user_id = $2", [hash, req.user.userId]);
        
        res.json({ message: "Password changed successfully" });
    } catch (err) {
        res.status(500).json({ error: "Server error" });
    }
});

app.post('/api/problems/:id/bookmark', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.userId;
    const problemId = parseInt(id);

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const userStats = await client.query("SELECT bookmarked_problems FROM user_stats WHERE user_id = $1", [userId]);
        let bookmarks = userStats.rows[0].bookmarked_problems || [];

        let isBookmarked = false;
        if (bookmarks.includes(problemId)) {
            bookmarks = bookmarks.filter(bid => bid !== problemId);
            isBookmarked = false;
        } else {
            bookmarks.push(problemId);
            isBookmarked = true;
        }


        await client.query("UPDATE user_stats SET bookmarked_problems = $1 WHERE user_id = $2", [bookmarks, userId]);
        await client.query('COMMIT');
        
        res.json({ message: isBookmarked ? "Bookmarked" : "Removed Bookmark", isBookmarked });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: "Action failed" });
    } finally {
        client.release();
    }
});

app.get('/api/leaderboard', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT u.username, u.full_name, m.profile_pic_url, s.current_rating
            FROM users u
            JOIN user_metadata m ON u.user_id = m.user_id
            JOIN user_stats s ON u.user_id = s.user_id
            ORDER BY s.current_rating DESC, m.registration_time ASC
        `);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch leaderboard" });
    }
});

app.get('/api/users/:username', async (req, res) => {
    const { username } = req.params;
    try {
        const userRes = await pool.query(`
            SELECT u.user_id, u.username, u.full_name, u.institute, u.short_bio,
                   m.profile_pic_url, m.registration_time, 
                   m.twitter_url, m.instagram_url, m.facebook_url, m.website_url,
                   s.current_rating, s.solved_problems, s.attempted_problems
            FROM users u
            JOIN user_metadata m ON u.user_id = m.user_id
            JOIN user_stats s ON u.user_id = s.user_id
            WHERE u.username = $1
        `, [username]);

        if (userRes.rows.length === 0) return res.status(404).json({ error: "User not found" });
        const user = userRes.rows[0];

        const rankRes = await pool.query(`
            SELECT COUNT(*) + 1 as rank FROM user_stats WHERE current_rating > $1
        `, [user.current_rating]);
        user.rank = rankRes.rows[0].rank;

        const authoredRes = await pool.query(`
            SELECT problem_id, title, upvote_count, created_at 
            FROM problems WHERE author_id = $1 ORDER BY created_at DESC
        `, [user.user_id]);
        user.authored_problems = authoredRes.rows;

        const commentsRes = await pool.query(`
            SELECT c.content, c.created_at, p.title as problem_title, p.problem_id
            FROM comments c
            JOIN problems p ON c.problem_id = p.problem_id
            WHERE c.user_id = $1
            ORDER BY c.created_at DESC LIMIT 10
        `, [user.user_id]);
        user.recent_comments = commentsRes.rows;

        const attemptedIds = user.attempted_problems || [];
        const solvedIds = user.solved_problems || [];
        
        let categoryStats = {};

        if (attemptedIds.length > 0) {
            const problemsRes = await pool.query(`
                SELECT problem_id, category FROM problems WHERE problem_id = ANY($1)
            `, [attemptedIds]);

            problemsRes.rows.forEach(p => {
                if (!categoryStats[p.category]) {
                    categoryStats[p.category] = { attempted: 0, solved: 0 };
                }
                categoryStats[p.category].attempted++;
                if (solvedIds.includes(p.problem_id)) {
                    categoryStats[p.category].solved++;
                }
            });
        }
        user.category_stats = categoryStats;

        res.json(user);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to load profile" });
    }
});

app.get('/api/translations/incoming', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT t.*, p.title as original_title, u.username as translator_name
            FROM problem_translations t
            JOIN problems p ON t.problem_id = p.problem_id
            JOIN users u ON t.translator_id = u.user_id
            WHERE p.author_id = $1 AND t.status = 'pending'
            ORDER BY t.created_at DESC
        `, [req.user.userId]);
        res.json(result.rows);
    } catch (err) { 
        console.error("INCOMING ERROR:", err);
        res.status(500).json({ error: err.message });
    }
});


app.get('/api/translations/outgoing', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT t.*, p.title as original_title
            FROM problem_translations t
            JOIN problems p ON t.problem_id = p.problem_id
            WHERE t.translator_id = $1
            ORDER BY t.created_at DESC
        `, [req.user.userId]);
        res.json(result.rows);
    } catch (err) { 
        console.error("OUTGOING ERROR:", err);
        res.status(500).json({ error: err.message }); 
    }
});
app.post('/api/translations/submit', authenticateToken, async (req, res) => {
    const { problemId, language, title, description } = req.body;
    try {
        const check = await pool.query("SELECT author_id FROM problems WHERE problem_id = $1", [problemId]);
        if (check.rows.length === 0) return res.status(404).json({ error: "Problem not found" });

        if (check.rows[0].author_id === req.user.userId) {
            const colTitle = language === 'bn' ? 'title_bn' : 'title';
            const colDesc = language === 'bn' ? 'description_bn' : 'description';
            await pool.query(
                `UPDATE problems SET ${colTitle} = $1, ${colDesc} = $2 WHERE problem_id = $3`,
                [title, description, problemId]
            );
            return res.json({ message: "Translation added successfully (Self-Authored)" });
        }

        await pool.query(
            `INSERT INTO problem_translations (problem_id, translator_id, language, title, description)
             VALUES ($1, $2, $3, $4, $5)`,
            [problemId, req.user.userId, language, title, description]
        );
        res.json({ message: "Translation submitted for approval" });

    } catch (err) { res.status(500).json({ error: "Submission failed" }); }
});

app.post('/api/translations/decide', authenticateToken, async (req, res) => {
    const { translationId, action, editedTitle, editedDesc } = req.body;
    
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const transRes = await client.query(`
            SELECT t.*, p.author_id 
            FROM problem_translations t
            JOIN problems p ON t.problem_id = p.problem_id
            WHERE t.translation_id = $1
        `, [translationId]);

        if (transRes.rows.length === 0) throw new Error("Not found");
        const trans = transRes.rows[0];

        if (trans.author_id !== req.user.userId) return res.status(403).json({ error: "Unauthorized" });

        if (action === 'reject') {
            await client.query("UPDATE problem_translations SET status = 'rejected' WHERE translation_id = $1", [translationId]);
        } else {
            const finalTitle = editedTitle || trans.title;
            const finalDesc = editedDesc || trans.description;
            const colTitle = trans.language === 'bn' ? 'title_bn' : 'title';
            const colDesc = trans.language === 'bn' ? 'description_bn' : 'description';

            await client.query(
                `UPDATE problems SET ${colTitle} = $1, ${colDesc} = $2 WHERE problem_id = $3`,
                [finalTitle, finalDesc, trans.problem_id]
            );
            await client.query("UPDATE problem_translations SET status = 'approved' WHERE translation_id = $1", [translationId]);
        }

        await client.query('COMMIT');
        res.json({ message: `Translation ${action}ed` });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: "Action failed" });
    } finally { client.release(); }
});


app.get('/api/notifications', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT * FROM notifications 
            WHERE user_id = $1 
            ORDER BY is_read ASC, created_at DESC 
            LIMIT 10
        `, [req.user.userId]);
        
        const countRes = await pool.query(
            "SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND is_read = FALSE", 
            [req.user.userId]
        );
        
        res.json({ 
            notifications: result.rows, 
            unreadCount: parseInt(countRes.rows[0].count) 
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to load notifications" });
    }
});

app.post('/api/notifications/mark-read', authenticateToken, async (req, res) => {
    try {
        await pool.query(
            "UPDATE notifications SET is_read = TRUE WHERE user_id = $1 AND is_read = FALSE",
            [req.user.userId]
        );
        res.json({ message: "Marked as read" });
    } catch (err) {
        res.status(500).json({ error: "Failed to update" });
    }
});
app.put('/api/notifications/:id/read', authenticateToken, async (req, res) => {
    try {
        await pool.query(
            "UPDATE notifications SET is_read = TRUE WHERE notification_id = $1 AND user_id = $2",
            [req.params.id, req.user.userId]
        );
        res.json({ message: "Marked as read" });
    } catch (err) {
        res.status(500).json({ error: "Update failed" });
    }
});

app.get('/suggest', authenticateToken, async (req, res) => {
    const u = await pool.query("SELECT can_suggest FROM users WHERE user_id = $1", [req.user.userId]);
    if(!u.rows[0]?.can_suggest) return res.redirect('/problems');
    res.sendFile(path.join(__dirname, 'public/suggest.html')); 
});

app.get('/api/my-suggestions', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT * FROM suggested_problems WHERE user_id = $1 ORDER BY created_at DESC", 
            [req.user.userId]
        );
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch your suggestions" });
    }
});


app.post('/api/suggest', authenticateToken, uploadSolutions.array('solutions', 10), async (req, res) => {
    const { title, description, answer } = req.body;
    const images = req.files.map(f => `/uploads/solutions/${f.filename}`);
    
    try {
        await pool.query(
            "INSERT INTO suggested_problems (user_id, title, description, answer, solution_images) VALUES ($1, $2, $3, $4, $5)",
            [req.user.userId, title, description, answer, images]
        );
        
        const authors = await pool.query("SELECT user_id FROM user_metadata WHERE user_category != '-1'");
        for(let a of authors.rows) {
            await pool.query("INSERT INTO notifications (user_id, message, link) VALUES ($1, $2, $3)", 
                [a.user_id, "New Problem Suggestion Pending Review", "/academics#suggestions"]);
        }
        
        res.json({ message: "Suggestion submitted for approval!" });
    } catch (err) { res.status(500).json({ error: "Submission failed" }); }
});

app.get('/api/suggestions/:id', authenticateToken, async (req, res) => {
    try {
        const sRes = await pool.query(`
            SELECT s.*, u.username, u.full_name, m.profile_pic_url 
            FROM suggested_problems s
            JOIN users u ON s.user_id = u.user_id
            LEFT JOIN user_metadata m ON u.user_id = m.user_id
            WHERE s.suggestion_id = $1
        `, [req.params.id]);

        if (sRes.rows.length === 0) return res.status(404).json({ error: "Suggestion not found" });

        if (sRes.rows[0].user_id !== req.user.userId) {
             const userMeta = await pool.query("SELECT user_category FROM user_metadata WHERE user_id = $1", [req.user.userId]);
             if (parseInt(userMeta.rows[0]?.user_category) < 0) return res.status(403).json({ error: "Unauthorized" });
        }

        const cRes = await pool.query(`
            SELECT c.*, u.username, m.profile_pic_url 
            FROM suggestion_comments c
            JOIN users u ON c.user_id = u.user_id
            LEFT JOIN user_metadata m ON u.user_id = m.user_id
            WHERE c.suggestion_id = $1 ORDER BY c.created_at ASC
        `, [req.params.id]);

        res.json({ suggestion: sRes.rows[0], comments: cRes.rows });
    } catch (err) { res.status(500).json({ error: "Error fetching details" }); }
});

app.post('/api/suggestions/:id/comments', authenticateToken, async (req, res) => {
    const { content } = req.body;
    const suggestId = req.params.id;
    
    try {
        await pool.query("INSERT INTO suggestion_comments (suggestion_id, user_id, content) VALUES ($1, $2, $3)", 
            [suggestId, req.user.userId, content]);

        const sRes = await pool.query("SELECT user_id, title FROM suggested_problems WHERE suggestion_id = $1", [suggestId]);
        const suggestion = sRes.rows[0];

        if (suggestion.user_id === req.user.userId) {
            const authors = await pool.query("SELECT user_id FROM user_metadata WHERE user_category != '-1'");
            for (let a of authors.rows) {
                await pool.query("INSERT INTO notifications (user_id, message, link) VALUES ($1, $2, $3)", 
                    [a.user_id, `💬 New comment on suggestion: "${suggestion.title}"`, "/academics#suggestions"]);
            }
        } else {
            await pool.query("INSERT INTO notifications (user_id, message, link) VALUES ($1, $2, $3)", 
                [suggestion.user_id, `💬 Author commented on your suggestion: "${suggestion.title}"`, "/suggest"]);
        }

        res.json({ message: "Comment posted" });
    } catch (err) { res.status(500).json({ error: "Comment failed" }); }
});


app.put('/api/suggestions/:id', authenticateToken, uploadSolutions.array('solutions', 10), async (req, res) => {
    const { title, description, answer } = req.body;
    const suggestId = req.params.id;

    try {
        const check = await pool.query("SELECT user_id, status FROM suggested_problems WHERE suggestion_id = $1", [suggestId]);
        if (check.rows[0].user_id !== req.user.userId) return res.status(403).json({ error: "Unauthorized" });
        if (check.rows[0].status !== 'pending') return res.status(400).json({ error: "Cannot edit processed suggestions" });

        let query = "UPDATE suggested_problems SET title=$1, description=$2, answer=$3";
        let params = [title, description, answer];
        if (req.files.length > 0) {
            const images = req.files.map(f => `/uploads/solutions/${f.filename}`);
            query += ", solution_images=$4 WHERE suggestion_id=$5";
            params.push(images, suggestId);
        } else {
            query += " WHERE suggestion_id=$4";
            params.push(suggestId);
        }

        await pool.query(query, params);
        res.json({ message: "Suggestion updated!" });
    } catch (err) { res.status(500).json({ error: "Update failed" }); }
});

app.get('/api/academic/suggestions', authenticateToken, async (req, res) => {
    const result = await pool.query(`
        SELECT s.*, u.username, 
               (SELECT COUNT(*) FROM suggestion_approvals sa WHERE sa.suggestion_id = s.suggestion_id) as approval_count
        FROM suggested_problems s
        JOIN users u ON s.user_id = u.user_id
        ORDER BY s.created_at DESC
    `);
    res.json(result.rows);
});

app.post('/api/academic/suggestions/:id/approve', authenticateToken, async (req, res) => {
    const { score } = req.body; 
    const suggestId = req.params.id;
    const authorId = req.user.userId;

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        await client.query(
            "INSERT INTO suggestion_approvals (suggestion_id, author_id, allocated_score) VALUES ($1, $2, $3)",
            [suggestId, authorId, score]
        );

        const appRes = await client.query("SELECT allocated_score FROM suggestion_approvals WHERE suggestion_id = $1", [suggestId]);
        
        if (appRes.rows.length >= 3) {
            const sRes = await client.query("SELECT * FROM suggested_problems WHERE suggestion_id = $1", [suggestId]);
            const s = sRes.rows[0];
            
            const totalScore = appRes.rows.reduce((sum, r) => sum + r.allocated_score, 0);
            const avgScore = Math.round(totalScore / appRes.rows.length);

            const newProb = await client.query(
                `INSERT INTO problems (author_id, title, description, answer, category, subcategory, initial_score, dynamic_score, answer_type)
                 VALUES ($1, $2, $3, $4, 'Community', 'User Suggested', $5, $5, 'numeric') RETURNING problem_id`,
                [s.user_id, s.title, s.description, s.answer, avgScore]
            );

            await client.query("UPDATE suggested_problems SET status = 'approved', final_problem_id = $1 WHERE suggestion_id = $2", 
                [newProb.rows[0].problem_id, suggestId]);

            await client.query("INSERT INTO notifications (user_id, message, link) VALUES ($1, $2, $3)",
                [s.user_id, `Your suggestion "${s.title}" has been accepted!`, `/problems/${newProb.rows[0].problem_id}`]);
        }

        await client.query('COMMIT');
        res.json({ message: "Approved successfully" });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: "Action failed" });
    } finally { client.release(); }
});

app.post('/api/problems/:id/edit-request', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { title, description, answer } = req.body;
    const userId = req.user.userId;
    if (!title && !description && !answer) {
        return res.status(400).json({ error: "No changes submitted. Please modify at least one field." });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const probCheck = await client.query("SELECT title FROM problems WHERE problem_id = $1", [id]);
        if (probCheck.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: "Problem not found" });
        }
        const problemTitle = probCheck.rows[0].title;
        await client.query(
            `INSERT INTO problem_edits (problem_id, user_id, new_title, new_description, new_answer)
             VALUES ($1, $2, $3, $4, $5)`,
            [id, userId, title, description, answer]
        );

        const authors = await client.query("SELECT user_id FROM user_metadata WHERE user_category != '-1'");
        
        for (let a of authors.rows) {
            await client.query(
                "INSERT INTO notifications (user_id, message, link) VALUES ($1, $2, $3)",
                [a.user_id, `📝 New Edit Request for "${problemTitle}"`, "/academics#requests"]
            );
        }

        await client.query('COMMIT');
        res.json({ message: "Edit request submitted for approval" });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Edit Request Error:", err);
        res.status(500).json({ error: "Failed to submit edit request" });
    } finally {
        client.release();
    }
});

// Friend Request APIS :START
app.get('/api/friends/status/:username', authenticateToken, async (req, res) => {
    try {
        const targetRes = await pool.query("SELECT user_id FROM users WHERE username = $1", [req.params.username]);
        if (targetRes.rows.length === 0) return res.status(404).json({ error: "User not found" });
        
        const targetId = targetRes.rows[0].user_id;
        const myId = req.user.userId;

        if (targetId === myId) return res.json({ status: 'self' });

        const friendRes = await pool.query(`
            SELECT * FROM friendships 
            WHERE (requester_id = $1 AND addressee_id = $2) 
               OR (requester_id = $2 AND addressee_id = $1)
        `, [myId, targetId]);

        if (friendRes.rows.length === 0) return res.json({ status: 'none', targetId });
        
        const rel = friendRes.rows[0];
        if (rel.status === 'accepted') return res.json({ status: 'friends', targetId });
        
        if (rel.requester_id === myId) return res.json({ status: 'pending_sent', targetId });
        return res.json({ status: 'pending_received', targetId });

    } catch (err) { res.status(500).json({ error: "Check failed" }); }
});

app.post('/api/friends/request/:id', authenticateToken, async (req, res) => {
    const targetId = req.params.id;
    const myId = req.user.userId;

    try {
        await pool.query(
            "INSERT INTO friendships (requester_id, addressee_id) VALUES ($1, $2)",
            [myId, targetId]
        );

        await pool.query(
            "INSERT INTO notifications (user_id, message, link) VALUES ($1, $2, $3)",
            [targetId, `${req.user.username} sent you a friend request`, `/u/${req.user.username}`]
        );

        res.json({ message: "Request sent" });
    } catch (err) { res.status(500).json({ error: "Request failed" }); }
});


app.post('/api/friends/accept/:id', authenticateToken, async (req, res) => {
    const targetId = req.params.id;
    const myId = req.user.userId;

    try {
        const result = await pool.query(
            "UPDATE friendships SET status = 'accepted' WHERE requester_id = $1 AND addressee_id = $2 RETURNING *",
            [targetId, myId]
        );
        
        if (result.rowCount === 0) return res.status(400).json({ error: "Request not found" });
        await pool.query(
            "INSERT INTO notifications (user_id, message, link) VALUES ($1, $2, $3)",
            [targetId, `${req.user.username} accepted your friend request`, `/u/${req.user.username}`]
        );

        res.json({ message: "Friend request accepted" });
    } catch (err) { res.status(500).json({ error: "Accept failed" }); }
});

app.delete('/api/friends/:id', authenticateToken, async (req, res) => {
    const targetId = req.params.id;
    const myId = req.user.userId;

    try {
        await pool.query(`
            DELETE FROM friendships 
            WHERE (requester_id = $1 AND addressee_id = $2) 
               OR (requester_id = $2 AND addressee_id = $1)
        `, [myId, targetId]);
        res.json({ message: "Removed" });
    } catch (err) { res.status(500).json({ error: "Remove failed" }); }
});

app.get('/api/my-friends', authenticateToken, async (req, res) => {
    try {
        const friends = await pool.query(`
            SELECT u.user_id, u.username, u.full_name, m.profile_pic_url 
            FROM friendships f
            JOIN users u ON (CASE WHEN f.requester_id = $1 THEN f.addressee_id ELSE f.requester_id END) = u.user_id
            JOIN user_metadata m ON u.user_id = m.user_id
            WHERE (f.requester_id = $1 OR f.addressee_id = $1) AND f.status = 'accepted'
        `, [req.user.userId]);
        const requests = await pool.query(`
            SELECT u.user_id, u.username, u.full_name, m.profile_pic_url 
            FROM friendships f
            JOIN users u ON f.requester_id = u.user_id
            JOIN user_metadata m ON u.user_id = m.user_id
            WHERE f.addressee_id = $1 AND f.status = 'pending'
        `, [req.user.userId]);

        res.json({ friends: friends.rows, requests: requests.rows });
    } catch (err) { res.status(500).json({ error: "Fetch failed" }); }
});
// Friend Request APIS :END


//Contest Logic APIs:START

app.post('/api/contest/create', authenticateToken, async (req, res) => {
    const { categories, subcategories, count, time, allowFallback } = req.body;
    const userId = req.user.userId;
    const reqCount = parseInt(count) || 10;

    try {
        let queryText = "SELECT problem_id FROM problems WHERE 1=1";
        const params = [];
        
        if (categories && categories.length > 0 && !categories.includes('Random')) {
            params.push(categories);
            queryText += ` AND category = ANY($${params.length})`;
        }
        if (subcategories && subcategories.length > 0) {
            params.push(subcategories);
            queryText += ` AND subcategory = ANY($${params.length})`;
        }

        const allMatchingRes = await pool.query(queryText, params);
        const allIds = allMatchingRes.rows.map(r => r.problem_id);
        const statsRes = await pool.query("SELECT solved_problems, attempted_problems FROM user_stats WHERE user_id = $1", [userId]);
        const solved = new Set(statsRes.rows[0].solved_problems || []);
        const attempted = new Set(statsRes.rows[0].attempted_problems || []);
        const unattemptedPool = allIds.filter(id => !attempted.has(id));
        const unsolvedPool = allIds.filter(id => attempted.has(id) && !solved.has(id));
        const solvedPool = allIds.filter(id => solved.has(id));

        let selectedIds = [];
        let warning = null;

        if (unattemptedPool.length >= reqCount) {
            selectedIds = unattemptedPool.sort(() => 0.5 - Math.random()).slice(0, reqCount);
        } else {

            if (!allowFallback) {
                let msg = `Only ${unattemptedPool.length} unattempted problems found.`;
                if (unsolvedPool.length > 0) msg += " We can include problems you attempted but haven't solved.";
                else if (solvedPool.length > 0) msg += " We can include problems you've already solved.";
                else msg = "No problems found matching these criteria.";
                return res.json({ status: 'confirm', message: msg, available: unattemptedPool.length });
            }

            selectedIds = [...unattemptedPool];
            const needed1 = reqCount - selectedIds.length;
            const fill1 = unsolvedPool.sort(() => 0.5 - Math.random()).slice(0, needed1);
            selectedIds = [...selectedIds, ...fill1];

            if (selectedIds.length < reqCount) {
                const needed2 = reqCount - selectedIds.length;
                const fill2 = solvedPool.sort(() => 0.5 - Math.random()).slice(0, needed2);
                selectedIds = [...selectedIds, ...fill2];
                warning = "Includes previously solved problems.";
            }
        }

        if (selectedIds.length === 0) return res.status(400).json({ error: "No problems available." });

        const config = { categories, subcategories, timeLimit: time, reqCount };
        const logRes = await pool.query(
            "INSERT INTO contest_logs (user_id, config, problem_ids) VALUES ($1, $2, $3) RETURNING contest_id",
            [userId, JSON.stringify(config), selectedIds]
        );
        const problemsRes = await pool.query(
            `SELECT problem_id, title, description, figure_url, category, answer_type, range_start, range_end 
             FROM problems WHERE problem_id = ANY($1)`,
            [selectedIds]
        );

        res.json({ 
            status: 'started', 
            contestId: logRes.rows[0].contest_id,
            problems: problemsRes.rows,
            warning 
        });

    } catch (err) { console.error(err); res.status(500).json({ error: "Creation failed" }); }
});

app.post('/api/contest/answer', authenticateToken, async (req, res) => {
    const { contestId, problemId, answer } = req.body;
    
    try {
        const check = await pool.query(
            "SELECT sub_id, edit_count, history FROM contest_submissions WHERE contest_id = $1 AND problem_id = $2",
            [contestId, problemId]
        );

        const historyEntry = { answer, time: new Date() };

        if (check.rows.length > 0) {
            if (check.rows[0].edit_count >= 3) {
                return res.status(403).json({ error: "Submission limit reached (3/3)" });
            }
            
            const newHistory = [...(check.rows[0].history || []), historyEntry];

            await pool.query(
                `UPDATE contest_submissions 
                 SET user_answer = $1, 
                     edit_count = edit_count + 1, 
                     submitted_at = NOW(),
                     history = $3
                 WHERE sub_id = $2`,
                [answer, check.rows[0].sub_id, JSON.stringify(newHistory)]
            );
            res.json({ message: "Updated", editsLeft: 2 - check.rows[0].edit_count });
        } else {
            await pool.query(
                `INSERT INTO contest_submissions (contest_id, problem_id, user_answer, edit_count, history) 
                 VALUES ($1, $2, $3, 1, $4)`,
                [contestId, problemId, answer, JSON.stringify([historyEntry])]
            );
            res.json({ message: "Saved", editsLeft: 2 });
        }
    } catch (err) { 
        console.error(err);
        res.status(500).json({ error: "Save failed" }); 
    }
});

app.post('/api/contest/finish', authenticateToken, async (req, res) => {
    const { contestId, timeTaken } = req.body;
    const userId = req.user.userId;

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const logRes = await client.query(
            `UPDATE contest_logs 
             SET end_time = NOW(), time_taken_seconds = $1 
             WHERE contest_id = $2 RETURNING public_id, problem_ids`, 
            [timeTaken, contestId]
        );

        const publicId = logRes.rows[0].public_id;
        const allProblemIds = logRes.rows[0].problem_ids || [];

        const subs = await client.query("SELECT * FROM contest_submissions WHERE contest_id = $1", [contestId]);
        const submittedProbIds = subs.rows.map(s => s.problem_id);
        const unsubmittedCount = allProblemIds.length - submittedProbIds.length;

        const probs = await client.query(
            `SELECT problem_id, title, answer, dynamic_score, initial_score, category, 
                    error_margin, range_start, range_end 
             FROM problems WHERE problem_id = ANY($1) FOR UPDATE`, 
            [submittedProbIds]
        );

        const userStatsRes = await client.query("SELECT solved_problems FROM user_stats WHERE user_id = $1", [userId]);
        const previouslySolved = new Set(userStatsRes.rows[0].solved_problems || []);

        let totalScore = 0;
        let correctCount = 0;
        let incorrectCount = 0;

        for (let sub of subs.rows) {
            const p = probs.rows.find(x => x.problem_id === sub.problem_id);
            if (!p) continue;
            let isCorrect = false;
            const uAns = sub.user_answer;
            if (uAns && uAns.trim().toLowerCase() === p.answer.trim().toLowerCase()) isCorrect = true;
            else if (uAns && !isNaN(parseFloat(uAns))) {
                const val = parseFloat(uAns);
                if (p.range_start && val >= p.range_start && val <= p.range_end) isCorrect = true;
                else if (p.error_margin && Math.abs(val - parseFloat(p.answer)) <= p.error_margin) isCorrect = true;
            }

            await client.query("UPDATE contest_submissions SET is_correct = $1 WHERE sub_id = $2", [isCorrect, sub.sub_id]);

            if (isCorrect) {
                correctCount++;
                const attRes = await client.query("SELECT count FROM attempt_counts WHERE user_id = $1 AND problem_id = $2", [userId, p.problem_id]);
                const prevAttempts = attRes.rows.length > 0 ? attRes.rows[0].count : 0;

                if (!previouslySolved.has(p.problem_id)) {
                    const oldDynamic = parseFloat(p.dynamic_score);
                    const baseline = p.initial_score * 0.5;
                    let newDynamic = oldDynamic * 0.99;
                    if (newDynamic < baseline) newDynamic = baseline;

                    await client.query(
                        `UPDATE problems SET solve_count = solve_count + 1, dynamic_score = $2 WHERE problem_id = $1`, 
                        [p.problem_id, newDynamic]
                    );

                    const scoreDiff = oldDynamic - newDynamic;
                    if (scoreDiff > 0) {
                        await client.query(`
                            UPDATE user_stats us SET current_rating = current_rating - ($1 * POWER(0.9, COALESCE(ac.count, 0)))
                            FROM attempt_counts ac WHERE us.user_id = ac.user_id AND ac.problem_id = $2 AND $2 = ANY(us.solved_problems) AND us.user_id != $3
                        `, [scoreDiff, p.problem_id, userId]);
                    }

                    await client.query("UPDATE user_stats SET solved_problems = array_append(solved_problems, $1) WHERE user_id = $2", [p.problem_id, userId]);
                    
                    const pointsEarned = newDynamic * Math.pow(0.9, prevAttempts);
                    totalScore += pointsEarned;
                } else {
                    totalScore += parseFloat(p.dynamic_score) * Math.pow(0.9, prevAttempts);
                }

                await client.query(
                    "UPDATE user_stats SET contest_solved_problems = array_append(contest_solved_problems, $1) WHERE user_id = $2 AND NOT ($1 = ANY(contest_solved_problems))",
                    [p.problem_id, userId]
                );
            } else {
                incorrectCount++;
            }
        }
        
        await recalcUserRating(client, userId);

        await client.query("UPDATE contest_logs SET score_obtained = $1 WHERE contest_id = $2", [totalScore, contestId]);
        await client.query('COMMIT');

        res.json({ 
            publicId,
            total: allProblemIds.length,
            submitted: submittedProbIds.length,
            unsubmitted: unsubmittedCount,
            correct: correctCount,
            incorrect: incorrectCount,
            score: totalScore
        });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: "Grading failed" });
    } finally { client.release(); }
});
app.get('/api/contest/overview/:publicId', async (req, res) => {
    const { publicId } = req.params;
    try {
        const logRes = await pool.query(`
            SELECT c.*, u.username, u.full_name, m.profile_pic_url 
            FROM contest_logs c
            JOIN users u ON c.user_id = u.user_id
            JOIN user_metadata m ON c.user_id = m.user_id
            WHERE c.public_id = $1
        `, [publicId]);

        if (logRes.rows.length === 0) return res.status(404).json({ error: "Contest record not found" });
        const log = logRes.rows[0];

        const subRes = await pool.query(`
            SELECT problem_id, user_answer, is_correct, history 
            FROM contest_submissions WHERE contest_id = $1
        `, [log.contest_id]);
        
        const submissionMap = {};
        subRes.rows.forEach(s => submissionMap[s.problem_id] = s);

        const probRes = await pool.query(`
            SELECT problem_id, title, category, figure_url 
            FROM problems WHERE problem_id = ANY($1)
        `, [log.problem_ids]);
        const problems = probRes.rows.map(p => {
            const sub = submissionMap[p.problem_id];
            return {
                ...p,
                status: sub ? (sub.is_correct ? 'correct' : 'wrong') : 'unsubmitted',
                user_answer: sub ? sub.user_answer : null,
                history: sub ? sub.history : [],
                is_correct: sub?.is_correct
            };
        });
        const stats = {
            total: problems.length,
            submitted: subRes.rows.length,
            unsubmitted: problems.length - subRes.rows.length,
            correct: subRes.rows.filter(s => s.is_correct).length,
            incorrect: subRes.rows.filter(s => !s.is_correct).length,
            timeTaken: log.time_taken_seconds
        };

        res.json({ 
            user: { 
                name: log.full_name, 
                username: log.username, 
                avatar: log.profile_pic_url 
            },
            stats,
            problems
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server Error" });
    }
});

app.get('/api/contest/history/:userId', async (req, res) => {
    try {
        const isOwner = req.user && req.user.userId === req.params.userId;
        let query = `
            SELECT 
                c.contest_id, 
                c.public_id, 
                c.start_time, 
                c.score_obtained, 
                c.is_public,
                array_length(c.problem_ids, 1) as total_questions,
                (SELECT COUNT(*) FROM contest_submissions s WHERE s.contest_id = c.contest_id AND s.is_correct = TRUE) as correct_count,
                (c.end_time IS NULL AND (c.start_time + ((c.config->>'timeLimit')::int * interval '1 minute')) < NOW()) as needs_finalization
            FROM contest_logs c 
            WHERE c.user_id = $1 
              AND (
                  c.end_time IS NOT NULL 
                  OR (c.start_time + ((c.config->>'timeLimit')::int * interval '1 minute')) < NOW()
              )
              ${isOwner ? '' : 'AND c.is_public = TRUE'} 
            ORDER BY c.start_time DESC
        `;
        const result = await pool.query(query, [req.params.userId]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: "Fetch failed" }); }
});

app.put('/api/contest/:id/visibility', authenticateToken, async (req, res) => {
    const { isPublic } = req.body;
    try {
        await pool.query(
            "UPDATE contest_logs SET is_public = $1 WHERE contest_id = $2 AND user_id = $3",
            [isPublic, req.params.id, req.user.userId]
        );
        res.json({ message: "Updated" });
    } catch (err) { res.status(500).json({ error: "Update failed" }); }
});
//Contest LOGIC APIS:END

app.get('/api/contest/active', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT contest_id, start_time, config 
             FROM contest_logs 
             WHERE user_id = $1 
               AND end_time IS NULL 
               AND (start_time + ((config->>'timeLimit')::int * interval '1 minute')) > NOW()
             ORDER BY start_time DESC`,
            [req.user.userId]
        );
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Fetch failed" });
    }
});

app.get('/api/contest/restore/:id', authenticateToken, async (req, res) => {
    const contestId = req.params.id;
    try {
        const logRes = await pool.query(
            "SELECT * FROM contest_logs WHERE contest_id = $1 AND user_id = $2", 
            [contestId, req.user.userId]
        );
        
        if (logRes.rows.length === 0) return res.status(404).json({ error: "Contest not found" });
        const log = logRes.rows[0];

        if (log.end_time) {
            return res.json({ status: 'finished', publicId: log.public_id });
        }

        const probs = await pool.query(
            `SELECT problem_id, title, description, figure_url, category, answer_type, range_start, range_end 
             FROM problems WHERE problem_id = ANY($1)`,
            [log.problem_ids]
        );

        const subs = await pool.query(
            "SELECT problem_id, user_answer FROM contest_submissions WHERE contest_id = $1", 
            [contestId]
        );

        res.json({
            status: 'active',
            contestId: log.contest_id,
            config: log.config,
            startTime: log.start_time,
            problems: probs.rows,
            submissions: subs.rows
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Restore failed" });
    }
});

app.get('/api/contest/active', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT contest_id, start_time, config 
             FROM contest_logs 
             WHERE user_id = $1 AND end_time IS NULL 
             ORDER BY start_time DESC`,
            [req.user.userId]
        );
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Fetch failed" });
    }
});

app.get('/api/contest/restore/:id', authenticateToken, async (req, res) => {
    const contestId = req.params.id;
    try {
        const logRes = await pool.query(
            "SELECT * FROM contest_logs WHERE contest_id = $1 AND user_id = $2", 
            [contestId, req.user.userId]
        );
        
        if (logRes.rows.length === 0) return res.status(404).json({ error: "Contest not found" });
        const log = logRes.rows[0];

        if (log.end_time) {
            return res.json({ status: 'finished', publicId: log.public_id });
        }
        const probs = await pool.query(
            `SELECT problem_id, title, description, figure_url, category, answer_type, range_start, range_end 
             FROM problems WHERE problem_id = ANY($1)`,
            [log.problem_ids]
        );
        const subs = await pool.query(
            "SELECT problem_id, user_answer FROM contest_submissions WHERE contest_id = $1", 
            [contestId]
        );

        res.json({
            status: 'active',
            contestId: log.contest_id,
            config: log.config,
            startTime: log.start_time,
            problems: probs.rows,
            submissions: subs.rows
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Restore failed" });
    }
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
