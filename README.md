# Math Portal

The **Math Portal** is a full-stack web application designed as a Math Portal. It serves as a centralized platform for hosting math problems, managing academic content, and fostering a competitive community through dynamic scoring and leaderboards. The Portal is still in it's beta stage.

## 🚀 Features

### **1. User System**
* **Authentication:** Secure login via Email/Password (with OTP verification) and Google OAuth.
* **Profile Management:** Users can customize profiles (avatar, bio, institute) and manage account security.
* **Role-Based Access:**
    * **Solvers:** Can view problems, submit answers, vote, and comment.
    * **Academic Authors:** Have access to the **Academic Dashboard** to create, edit, and manage problems.

### **2. Problem Archive**
* **Rich Content:** Problems support LaTeX math rendering (MathJax) and image/diagram attachments.
* **Organization:** Filter by Category (Number Theory, Algebra, etc.), Subcategory, and sort by Difficulty or Newest.
* **Interactivity:** Upvote/Downvote system and threaded comments for discussions.

### **3. Dynamic Scoring & Progression**
* **Base Score:** Every problem starts with a default score (e.g., 10 points).
* **Global Decay:** The problem's value decreases by **1%** for every successful solve (capped at 50% of original value).
* **User Penalty:** A user's potential score decreases by **10%** for each incorrect attempt on a specific problem.
* **Visual Cues:** Solved problems are highlighted with a green outline and "Solved" badge.

---

## 🛠️ Installation & Setup

Follow these instructions to set up the server locally.

### **1. Prerequisites**
* **Node.js** (v14 or higher)
* **PostgreSQL** (v12 or higher)

### **2. Install Dependencies**
Navigate to the project folder and install the required packages:

```bash
npm install express pg bcryptjs cors nodemailer helmet jsonwebtoken multer dotenv google-auth-library
```


### **3. Database Setup**
Create a PostgreSQL database (e.g., ndmc_db) and run the following SQL queries to set up the schema:

```bash
-- Users & Auth
CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash TEXT,
    full_name VARCHAR(100),
    google_id VARCHAR(255),
    login_method VARCHAR(50),
    is_verified BOOLEAN DEFAULT FALSE,
    verification_token TEXT,
    otp_code VARCHAR(10),
    otp_expires TIMESTAMP,
    study_level VARCHAR(20),
    institute VARCHAR(100),
    phone_no VARCHAR(20),
    short_bio TEXT
);

-- User Metadata (Roles & Logs)
CREATE TABLE user_metadata (
    user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
    user_category VARCHAR(10) DEFAULT '-1', -- '-1': Student, '0': Academic
    profile_pic_url TEXT,
    date_of_birth DATE,
    registration_time TIMESTAMP DEFAULT NOW(),
    registration_ip VARCHAR(45),
    registration_device TEXT,
    failed_login_attempts INTEGER DEFAULT 0,
    last_login_time TIMESTAMP,
    last_login_ip VARCHAR(45),
    last_login_device TEXT,
    last_reset_time TIMESTAMP
);

-- User Statistics & Progress
CREATE TABLE user_stats (
    user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
    current_rating NUMERIC DEFAULT 0,
    solved_problems INTEGER[] DEFAULT '{}',
    attempted_problems INTEGER[] DEFAULT '{}',
    liked_posts INTEGER[] DEFAULT '{}',
    disliked_posts INTEGER[] DEFAULT '{}',
    last_submission_time TIMESTAMP
);

-- Problems Table
CREATE TABLE problems (
    problem_id SERIAL PRIMARY KEY,
    author_id INTEGER REFERENCES users(user_id),
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    answer VARCHAR(255) NOT NULL,
    category VARCHAR(50),
    subcategory VARCHAR(50),
    figure_url TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    solve_count INTEGER DEFAULT 0,
    total_attempts INTEGER DEFAULT 0,
    unique_attempts INTEGER DEFAULT 0,
    upvote_count INTEGER DEFAULT 0,
    downvote_count INTEGER DEFAULT 0,
    initial_score INTEGER DEFAULT 10,
    dynamic_score NUMERIC DEFAULT 10
);

-- Comments
CREATE TABLE comments (
    comment_id SERIAL PRIMARY KEY,
    problem_id INTEGER REFERENCES problems(problem_id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Attempt Tracking (For Scoring Penalty)
CREATE TABLE attempt_counts (
    user_id INTEGER, 
    problem_id INTEGER, 
    count INTEGER DEFAULT 0, 
    PRIMARY KEY(user_id, problem_id)
);
```

### **4. Environment Configuration**
Create a .env file in the root directory:

```bash
# Server Config
PORT=3000
BASE_URL=http://localhost:3000

# Database Connection
DB_USER=postgres
DB_PASSWORD=your_password
DB_HOST=localhost
DB_NAME=ndmc_db

# Security
JWT_SECRET=your_super_secret_key_here

# Email Service (e.g., Gmail App Password)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=465
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_email_app_password

# Google Login (Optional)
GOOGLE_CLIENT_ID=your_google_client_id.apps.googleusercontent.com
```

### **5. Folder Structure**
Ensure your project directory is structured as follows:

```bash
/portal
│── server.js          # Backend logic
│── .env               # Environment variables
│── public/            # Frontend files
│   │── index.html
│   │── problems.html
│   │── problem.html
│   │── academic.html  # Author Dashboard
│   │── profile.html
│   │── join.html
│   │── css/
│   │   ├── global.css
│   │   └── theme.css
│   │── js/
│   │   └── header.js
│   └── uploads/       # Created automatically
```

### **6. Run the Server**
Start the application:

```bash
node server.js
```
The server will start at http://localhost:3000.

## 🧪 Testing Guide for Developers
### **1. User Registration**
Go to /join and create a new account.
Check the console or your email (if configured) for the verification link.
Once verified, log in.

### **2. Enabling Academic Access**
By default, new users are Standard Users. To test problem uploading:
Access your database.
Run this query to promote your user:

```bash
UPDATE user_metadata SET user_category = '0' WHERE user_id = [YOUR_USER_ID];
```

Logout and Log back in to update your session token.
You will now see "Academic Dashboard" in the navigation bar.
Submitting Category

### **3. Testing Scoring Logic**

Upload a Problem: Set the score to 100
**Scenario A (Perfect Solve):**
Solve the problem correctly on the first try.
Result: You get 100 points. Global problem score drops to 99 (1% decay).
**Scenario B (With Mistakes):**
Create a second user.
Submit an incorrect answer.
Submit the correct answer.
Result: You get 89.1 points (99 * 0.9 penalty). Global problem score drops further.

## 🤝 Contribution
Fork the project.
Create your feature branch (git checkout -b feature/AmazingFeature).
Commit your changes (git commit -m 'Add some AmazingFeature').
Push to the branch (git push origin feature/AmazingFeature).
Open a Pull Request.

## License: MIT