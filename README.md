# Leitsys - Application Programming Interface

## 1st 

Implementation of the **Ebbinghaus spaced repetition method** for learning. Each question progresses through **steps** whose intervals increase with correct answers. An incorrect answer resets the question to the first step.

```
Question created → Step 1 (1j) → Step 2 (3j) → … → Step 7 (90j) → Archived ✓
                                           → bad answer → return Step 1
```

## 2nd option: quiz

Each user also has a private **multiple-choice quiz bank**. Quizzes are imported as plain text, and every answer updates the progress of the question (attempts, successes, last result).

```
Text import → Quiz bank → Answer → Progress updated (attempts / successes)
```

## Details

- REST API built with **Rust / Axum / SQLite**.
- The server listens on `0.0.0.0:3000` by default.
- All routes except `/auth/*` require a **JWT header**. The token is obtained via `POST /auth/login` and expires after **24 hours**.
- Swagger UI API documentation is available at: `http://localhost:3000/swagger`
