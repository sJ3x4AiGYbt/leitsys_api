-- data/006_quiz.sql
-- Multiple-choice quiz bank, one per user. Progress lives on the question
-- itself since nothing is shared between users.
CREATE TABLE IF NOT EXISTS quiz_questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    num INTEGER NOT NULL,
    category TEXT NOT NULL,
    prompt TEXT NOT NULL,
    options TEXT NOT NULL,
    correct TEXT NOT NULL,
    qkey TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    successes INTEGER NOT NULL DEFAULT 0,
    last_correct BOOLEAN,
    last_answered_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    modified_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, qkey),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
