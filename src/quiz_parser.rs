//! Parser for the plain-text quiz format, ported from the original standalone
//! quiz page (`parseText` / `parseOk` / `makeQuestion`). Questions look like:
//!
//! ```text
//! Quiz 12
//! * Category : Rootkits / Detection
//! * Question : …
//! * Answer A : …
//! * Detail answer A : …
//! * Details answers B, C and D : …
//! * Correct answer : A,C
//! ---
//! ```
//!
//! Keys are matched accent- and case-insensitively, `**bold**` keys are
//! accepted, and a line without a key continues the previous field.

use std::collections::BTreeMap;

use crate::models::QuizOption;

pub const LETTERS: [char; 8] = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'];

const DEFAULT_CATEGORY: &str = "Uncategorized";

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedQuestion {
    pub num: i64,
    pub category: String,
    pub prompt: String,
    pub options: Vec<QuizOption>,
    /// Sorted, deduplicated letters of the correct options.
    pub correct: Vec<String>,
    /// Stable hash of the prompt and option texts, used to spot a question
    /// that is already in the bank.
    pub qkey: String,
}

#[derive(Debug, Default)]
pub struct ParseOutcome {
    /// Valid questions, in the order they appear in the text.
    pub questions: Vec<ParsedQuestion>,
    /// Blocks missing a prompt, two options or a correct answer.
    pub invalid: usize,
}

#[derive(Default)]
struct RawQuestion {
    num: i64,
    category: Option<String>,
    prompt: Option<String>,
    correct: Option<String>,
    answers: BTreeMap<char, String>,
    details: BTreeMap<char, String>,
}

/// Which field the following key-less lines get appended to.
enum Field {
    Category,
    Prompt,
    Correct,
    Answer(char),
    Details(Vec<char>),
}

enum Key {
    Category,
    Prompt,
    Answer(char),
    Details(Vec<char>),
    Correct,
}

pub fn parse(text: &str) -> ParseOutcome {
    let mut raws: Vec<RawQuestion> = Vec::new();
    let mut has_current = false;
    let mut field: Option<Field> = None;

    for line in text.lines() {
        if is_separator(line) {
            has_current = false;
            field = None;
            continue;
        }

        let raw = strip_bold_key(line);
        let norm = fold(&raw);

        if let Some(num) = quiz_header(&norm) {
            let num = num.unwrap_or(raws.len() as i64 + 1);
            raws.push(RawQuestion { num, ..Default::default() });
            has_current = true;
            field = None;
            continue;
        }

        let key = match_key(&norm);
        if key.is_some() && !has_current {
            raws.push(RawQuestion { num: raws.len() as i64 + 1, ..Default::default() });
            has_current = true;
        }
        if !has_current {
            continue;
        }
        let cur = raws.last_mut().expect("has_current implies a question");

        if let Some(key) = key {
            let value = raw.split_once(':').map(|(_, v)| v).unwrap_or("").trim().to_string();
            field = Some(match key {
                Key::Category => {
                    cur.category = Some(value);
                    Field::Category
                }
                Key::Prompt => {
                    cur.prompt = Some(value);
                    Field::Prompt
                }
                Key::Answer(letter) => {
                    cur.answers.insert(letter, value);
                    Field::Answer(letter)
                }
                Key::Details(letters) => {
                    for letter in &letters {
                        cur.details.insert(*letter, value.clone());
                    }
                    Field::Details(letters)
                }
                Key::Correct => {
                    cur.correct = Some(value);
                    Field::Correct
                }
            });
            continue;
        }

        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let append = |target: &mut String| {
            target.push('\n');
            target.push_str(line);
        };
        match &field {
            None => {}
            Some(Field::Category) => append(cur.category.get_or_insert_with(String::new)),
            Some(Field::Prompt) => append(cur.prompt.get_or_insert_with(String::new)),
            Some(Field::Correct) => append(cur.correct.get_or_insert_with(String::new)),
            Some(Field::Answer(letter)) => append(cur.answers.entry(*letter).or_default()),
            Some(Field::Details(letters)) => {
                for letter in letters {
                    append(cur.details.entry(*letter).or_default());
                }
            }
        }
    }

    let mut outcome = ParseOutcome::default();
    for raw in raws {
        let question = make_question(raw);
        if is_valid(&question) {
            outcome.questions.push(question);
        } else {
            outcome.invalid += 1;
        }
    }
    outcome
}

fn make_question(raw: RawQuestion) -> ParsedQuestion {
    let options: Vec<QuizOption> = LETTERS
        .iter()
        .filter_map(|letter| {
            let text = raw.answers.get(letter)?.trim();
            if text.is_empty() {
                return None;
            }
            Some(QuizOption {
                letter: letter.to_string(),
                text: text.to_string(),
                detail: raw.details.get(letter).map(|d| d.trim().to_string()).unwrap_or_default(),
            })
        })
        .collect();

    let category = raw
        .category
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| DEFAULT_CATEGORY.to_string());
    let prompt = raw.prompt.unwrap_or_default().trim().to_string();

    let correct = parse_correct(raw.correct.as_deref(), &options)
        .into_iter()
        .filter(|letter| options.iter().any(|o| &o.letter == letter))
        .collect();

    let mut key_source = prompt.clone();
    for option in &options {
        key_source.push('|');
        key_source.push_str(&option.text);
    }

    ParsedQuestion {
        num: raw.num,
        category,
        prompt,
        options,
        correct,
        qkey: hash(&key_source),
    }
}

fn is_valid(q: &ParsedQuestion) -> bool {
    !q.prompt.is_empty() && q.options.len() >= 2 && !q.correct.is_empty()
}

/// Reads the "Correct answer" value: letters (`A`, `A,C`, `A and C`,
/// `Answers B and D`, `AC`), digits 1-8, or the exact text of an option.
pub fn parse_correct(value: Option<&str>, options: &[QuizOption]) -> Vec<String> {
    let Some(value) = value else { return Vec::new() };

    let upper = fold(value).to_uppercase();
    // Noise words around the letters, e.g. "Answers B and D".
    let without_noise = remove_substrings(&upper, &["ANSWERS", "ANSWER", "CORRECT"]);
    let cleaned = remove_word(&without_noise, "AND");
    let chars: Vec<char> = cleaned.chars().collect();
    let is_word = |c: Option<&char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_');

    // Standalone letters, e.g. "A, C" or "B and D".
    let mut found: Vec<char> = chars
        .iter()
        .enumerate()
        .filter(|&(i, c)| {
            ('A'..='H').contains(c) && !is_word(i.checked_sub(1).and_then(|p| chars.get(p))) && !is_word(chars.get(i + 1))
        })
        .map(|(_, c)| *c)
        .collect();

    // Glued letters, e.g. "AC" or "A/C+D".
    if found.is_empty()
        && !chars.is_empty()
        && chars.iter().all(|c| ('A'..='H').contains(c) || c.is_whitespace() || ",;/&+".contains(*c))
    {
        found = chars.iter().copied().filter(|c| ('A'..='H').contains(c)).collect();
    }

    if found.is_empty() {
        found = chars
            .iter()
            .filter_map(|c| c.to_digit(10))
            .filter(|d| (1..=8).contains(d))
            .map(|d| LETTERS[d as usize - 1])
            .collect();
    }

    if found.is_empty() {
        let target = fold(value);
        let target = target.trim();
        if let Some(letter) = options
            .iter()
            .find(|o| fold(&o.text).trim() == target)
            .and_then(|o| o.letter.chars().next())
        {
            found.push(letter);
        }
    }

    found.sort_unstable();
    found.dedup();
    found.into_iter().map(String::from).collect()
}

/// Lowercases and strips diacritics so keys match regardless of case and
/// accents. Non-breaking spaces become plain spaces. Covers common Latin
/// accents plus stray combining marks, which is all the format needs.
pub fn fold(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars().flat_map(char::to_lowercase) {
        let mapped = match c {
            'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' => 'a',
            'ç' => 'c',
            'è' | 'é' | 'ê' | 'ë' => 'e',
            'ì' | 'í' | 'î' | 'ï' => 'i',
            'ñ' => 'n',
            'ò' | 'ó' | 'ô' | 'õ' | 'ö' => 'o',
            'ù' | 'ú' | 'û' | 'ü' => 'u',
            'ý' | 'ÿ' => 'y',
            '\u{a0}' => ' ',
            '\u{300}'..='\u{36f}' => continue,
            other => other,
        };
        out.push(mapped);
    }
    out
}

/// djb2 over UTF-16 code units, rendered in base 36 — the same key the
/// original page computed, so a bank exported from it dedupes identically.
fn hash(s: &str) -> String {
    let mut h: i32 = 5381;
    for unit in s.encode_utf16() {
        h = h.wrapping_shl(5).wrapping_add(h).wrapping_add(unit as i32);
    }
    let mut n = h as u32;
    if n == 0 {
        return "0".to_string();
    }
    let mut digits = Vec::new();
    while n > 0 {
        digits.push(std::char::from_digit(n % 36, 36).expect("digit < 36"));
        n /= 36;
    }
    digits.iter().rev().collect()
}

fn is_separator(line: &str) -> bool {
    let t = line.trim();
    t.len() >= 3 && ['-', '*', '_'].iter().any(|c| t.chars().all(|x| x == *c))
}

/// Turns `- **Category :** x` into `- Category : x`.
fn strip_bold_key(line: &str) -> String {
    let indent_len = line.len() - line.trim_start().len();
    let mut starts = Vec::new();
    let after_indent = &line[indent_len..];
    if let Some(bullet) = after_indent.chars().next().filter(|c| ['*', '-', '•'].contains(c)) {
        let rest = &after_indent[bullet.len_utf8()..];
        starts.push(line.len() - rest.trim_start().len());
    }
    starts.push(indent_len);

    for start in starts {
        let Some(inner) = line[start..].strip_prefix("**") else { continue };
        let Some(end) = inner.find('*') else { continue };
        if end > 0 && inner[end..].starts_with("**") {
            return format!("{}{}{}", &line[..start], &inner[..end], &inner[end + 2..]);
        }
    }
    line.to_string()
}

/// Matches a `Quiz N` / `## Quiz #N` header line (on folded text).
/// Returns `Some(None)` if the number doesn't fit an `i64`.
fn quiz_header(norm: &str) -> Option<Option<i64>> {
    let s = norm.trim_start();
    let s = match s.strip_prefix('#') {
        Some(_) => s.trim_start_matches('#').trim_start(),
        None => s,
    };
    let s = s.strip_prefix("quiz")?.trim_start();
    let s = s.strip_prefix('#').unwrap_or(s).trim_start();
    let digits_len = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    if digits_len == 0 {
        return None;
    }
    let next = s[digits_len..].chars().next();
    if next.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some(s[..digits_len].parse().ok())
}

/// Matches a `* Key :` prefix (on folded text).
fn match_key(norm: &str) -> Option<Key> {
    let mut s = norm.trim_start();
    if let Some(rest) = s.strip_prefix(['*', '-', '•']) {
        s = rest.trim_start();
    }

    let key = if let Some(rest) = strip_any(s, &["category"]) {
        (Key::Category, rest)
    } else if let Some(rest) = strip_any(s, &["question", "prompt"]) {
        (Key::Prompt, rest)
    } else if let Some(rest) = strip_any(s, &["details", "detail", "explanations", "explanation"]) {
        let mut rest = ws1(rest)?;
        if let Some(after) = strip_any(rest, &["for the", "for", "of the", "of"]).and_then(ws1) {
            rest = after;
        }
        let rest = strip_any(rest, &["answers", "answer", "options", "option"])?;
        let (letters, rest) = letter_list(ws1(rest)?)?;
        (Key::Details(letters), rest)
    } else if let Some(rest) = strip_any(s, &["answer", "option"]) {
        let rest = ws1(rest)?;
        let letter = rest.chars().next().filter(|c| ('a'..='h').contains(c))?;
        (Key::Answer(letter.to_ascii_uppercase()), &rest[1..])
    } else {
        let rest = s.strip_prefix("correct")?;
        let rest = strip_any(ws1(rest)?, &["answers", "answer"])?;
        (Key::Correct, rest)
    };

    key.1.trim_start().starts_with(':').then_some(key.0)
}

/// Strips the first of `prefixes` that `s` starts with. List longer
/// spellings before their own prefixes (`answers` before `answer`).
fn strip_any<'a>(s: &'a str, prefixes: &[&str]) -> Option<&'a str> {
    prefixes.iter().find_map(|p| s.strip_prefix(p))
}

/// Requires at least one whitespace character and skips all of them.
fn ws1(s: &str) -> Option<&str> {
    let rest = s.trim_start();
    (rest.len() < s.len()).then_some(rest)
}

/// `b`, `b, c and d`, `b & c`, `b/c` → `[B, C, D]`.
fn letter_list(s: &str) -> Option<(Vec<char>, &str)> {
    let is_letter = |c: char| ('a'..='h').contains(&c);
    let first = s.chars().next().filter(|c| is_letter(*c))?;
    let mut letters = vec![first.to_ascii_uppercase()];
    let mut rest = &s[1..];
    loop {
        let t = rest.trim_start();
        let after_sep = t
            .strip_prefix([',', '&', '/'])
            .or_else(|| t.strip_prefix("and"))
            .map(str::trim_start);
        match after_sep.and_then(|a| a.chars().next().filter(|c| is_letter(*c)).map(|c| (c, a))) {
            Some((c, a)) => {
                letters.push(c.to_ascii_uppercase());
                rest = &a[1..];
            }
            None => return Some((letters, rest)),
        }
    }
}

fn remove_substrings(s: &str, needles: &[&str]) -> String {
    let mut out = s.to_string();
    for needle in needles {
        out = out.replace(needle, " ");
    }
    out
}

/// Replaces `word` with a space where it stands as a whole ASCII word.
fn remove_word(s: &str, word: &str) -> String {
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let rest = &s[i..];
        let matched = rest.starts_with(word)
            && !s[..i].chars().next_back().is_some_and(is_word)
            && !rest[word.len()..].chars().next().is_some_and(is_word);
        if matched {
            out.push(' ');
            i += word.len();
        } else {
            let c = rest.chars().next().expect("i < len");
            out.push(c);
            i += c.len_utf8();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn letters(q: &ParsedQuestion) -> Vec<&str> {
        q.correct.iter().map(String::as_str).collect()
    }

    #[test]
    fn parses_a_full_question() {
        let text = "Quiz 12\n\
            * Category : Rootkits / Detection\n\
            * Question : Which tool?\n\
            * Answer A : `chkrootkit`\n\
            * Detail answer A : A scanner.\n\
            * Answer B : `ls`\n\
            * Correct answer : A\n";
        let out = parse(text);
        assert_eq!(out.invalid, 0);
        assert_eq!(out.questions.len(), 1);
        let q = &out.questions[0];
        assert_eq!(q.num, 12);
        assert_eq!(q.category, "Rootkits / Detection");
        assert_eq!(q.prompt, "Which tool?");
        assert_eq!(q.options.len(), 2);
        assert_eq!(q.options[0].text, "`chkrootkit`");
        assert_eq!(q.options[0].detail, "A scanner.");
        assert_eq!(q.options[1].detail, "");
        assert_eq!(letters(q), ["A"]);
    }

    #[test]
    fn rejects_unknown_keys() {
        let text = "* Intitulé : Q\n* Réponse A : a\n* Réponse B : b\n* Bonne réponse : A";
        let out = parse(text);
        assert!(out.questions.is_empty());
        assert_eq!(out.invalid, 0);
    }

    #[test]
    fn separators_split_questions_and_number_them() {
        let text = "* Question : Q1\n* Answer A : x\n* Answer B : y\n* Correct answer : B\n---\n\
            * Question : Q2\n* Answer A : x\n* Answer B : y\n* Correct answer : A\n";
        let out = parse(text);
        assert_eq!(out.questions.len(), 2);
        assert_eq!(out.questions[0].num, 1);
        assert_eq!(out.questions[1].num, 2);
        assert_eq!(out.questions[1].category, DEFAULT_CATEGORY);
    }

    #[test]
    fn accepts_bold_keys_and_any_case() {
        let text = "- **Category :** Network\n- **QUESTION :** SSH port?\n- **answer A :** 22\n- **Option B :** 80\n- **Correct answers :** A";
        let out = parse(text);
        assert_eq!(out.questions.len(), 1);
        assert_eq!(out.questions[0].category, "Network");
        assert_eq!(out.questions[0].prompt, "SSH port?");
        assert_eq!(out.questions[0].options[1].text, "80");
    }

    #[test]
    fn continues_multi_line_fields() {
        let text = "* Question : Line 1\nLine 2\n* Answer A : a1\na2\n* Answer B : b\n* Correct answer : A";
        let q = &parse(text).questions[0];
        assert_eq!(q.prompt, "Line 1\nLine 2");
        assert_eq!(q.options[0].text, "a1\na2");
    }

    #[test]
    fn shared_detail_applies_to_every_listed_letter() {
        let text = "* Question : Q\n* Answer A : a\n* Answer B : b\n* Answer C : c\n* Answer D : d\n\
            * Details for answers B, C and D : Wrong.\nmore\n* Correct answer : A";
        let q = &parse(text).questions[0];
        assert_eq!(q.options[0].detail, "");
        for i in 1..4 {
            assert_eq!(q.options[i].detail, "Wrong.\nmore");
        }
    }

    #[test]
    fn reads_every_correct_answer_notation() {
        let opts: Vec<QuizOption> = ["The kernel", "The shell", "The BIOS"]
            .iter()
            .zip(LETTERS)
            .map(|(t, l)| QuizOption { letter: l.to_string(), text: t.to_string(), detail: String::new() })
            .collect();
        let read = |v: &str| parse_correct(Some(v), &opts);
        assert_eq!(read("A,C"), ["A", "C"]);
        assert_eq!(read("C and A"), ["A", "C"]);
        assert_eq!(read("Answers B and C"), ["B", "C"]);
        assert_eq!(read("AC"), ["A", "C"]);
        assert_eq!(read("2"), ["B"]);
        assert_eq!(read("1, 3"), ["A", "C"]);
        assert_eq!(read("the shell"), ["B"]);
        assert!(read("no idea").is_empty());
        // Non-ASCII text must not trip the word matching.
        assert!(read("Œuvre").is_empty());
    }

    #[test]
    fn counts_invalid_blocks() {
        let text = "Quiz 1\n* Question : No answers\n* Correct answer : A\n\
            Quiz 2\n* Question : Only one\n* Answer A : x\n* Correct answer : A\n\
            Quiz 3\n* Question : No correct answer\n* Answer A : x\n* Answer B : y\n\
            Quiz 4\n* Question : Correct answer not listed\n* Answer A : x\n* Answer B : y\n* Correct answer : E\n\
            Quiz 5\n* Question : OK\n* Answer A : x\n* Answer B : y\n* Correct answer : B\n";
        let out = parse(text);
        assert_eq!(out.invalid, 4);
        assert_eq!(out.questions.len(), 1);
        assert_eq!(out.questions[0].num, 5);
    }

    #[test]
    fn quiz_header_variants() {
        assert_eq!(quiz_header("quiz 3"), Some(Some(3)));
        assert_eq!(quiz_header("## quiz #42 — network"), Some(Some(42)));
        assert_eq!(quiz_header("quizzes 3"), None);
        assert_eq!(quiz_header("quiz 3a"), None);
    }

    #[test]
    fn qkey_ignores_details_and_category_but_not_texts() {
        let base = "* Category : X\n* Question : Q\n* Answer A : a\n* Answer B : b\n* Correct answer : A";
        let other_cat = "* Category : Y\n* Question : Q\n* Answer A : a\n* Detail answer A : d\n* Answer B : b\n* Correct answer : B";
        let other_text = "* Question : Q\n* Answer A : a\n* Answer B : c\n* Correct answer : A";
        let key = |t: &str| parse(t).questions[0].qkey.clone();
        assert_eq!(key(base), key(other_cat));
        assert_ne!(key(base), key(other_text));
    }

    #[test]
    fn hash_matches_the_original_javascript() {
        // djb2: 5381 → "45h", 5381 * 33 + 97 = 177670 → "3t3a".
        assert_eq!(hash(""), "45h");
        assert_eq!(hash("a"), "3t3a");
    }
}
