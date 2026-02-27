// ═══════════════════════════════════════════════
// CYBERSECURITY QUIZ ENGINE — COMPLETE JS
// ═══════════════════════════════════════════════

const TIMER_SECONDS = 30;
const LETTERS = ['A', 'B', 'C', 'D'];

let questions = [];
let currentQ = 0;
let answers = {};
let timerInterval = null;
let timeLeft = TIMER_SECONDS;
let totalTime = 0;
let totalTimeInterval = null;

// ─── FETCH QUESTIONS ───────────────────────────
async function loadQuiz(topic, count) {
    const res = await fetch('/api/get_questions', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({topic, count})
    });
    const data = await res.json();
    questions = data.questions;
    if (questions.length === 0) {
        alert('No questions available for this topic.'); return;
    }
    document.getElementById('quiz-setup').style.display = 'none';
    document.getElementById('quiz-area').style.display = 'block';
    startTotalTimer();
    renderQuestion();
}

// ─── RENDER QUESTION ───────────────────────────
function renderQuestion() {
    const q = questions[currentQ];
    const total = questions.length;
    const pct = (currentQ / total) * 100;

    document.getElementById('q-num').textContent = `Q ${currentQ + 1} / ${total}`;
    document.getElementById('q-topic').textContent = q.topic.replace('_', ' ');
    document.getElementById('q-diff').textContent = q.difficulty;
    document.getElementById('q-diff').className = `q-badge ${q.difficulty}`;
    document.getElementById('q-text').textContent = q.text;
    document.getElementById('progress-fill').style.width = pct + '%';

    const opts = document.getElementById('options-list');
    opts.innerHTML = '';
    q.options.forEach((opt, i) => {
        const li = document.createElement('li');
        li.className = 'option-item fade-in';
        li.dataset.idx = i + 1;
        li.innerHTML = `
            <div class="option-letter">${LETTERS[i]}</div>
            <div class="option-text">${opt}</div>`;
        li.addEventListener('click', () => selectOption(i + 1, q.id));
        opts.appendChild(li);
    });

    startTimer();
}

// ─── TIMER LOGIC ───────────────────────────────
function startTimer() {
    clearInterval(timerInterval);
    timeLeft = TIMER_SECONDS;
    updateTimerDisplay();
    timerInterval = setInterval(() => {
        timeLeft--;
        updateTimerDisplay();
        if (timeLeft <= 0) {
            clearInterval(timerInterval);
            autoSubmitTimeout();
        }
    }, 1000);
}

function updateTimerDisplay() {
    const el = document.getElementById('timer-text');
    const circle = document.getElementById('timer-circle');
    if (!el || !circle) return;
    el.textContent = timeLeft;
    const pct = timeLeft / TIMER_SECONDS;
    const dash = 189;
    circle.style.strokeDashoffset = dash - (dash * pct);
    circle.className = 'progress-circle';
    if (timeLeft <= 10) circle.classList.add('danger');
    else if (timeLeft <= 15) circle.classList.add('warning');
    el.style.color = timeLeft <= 10 ? 'var(--danger)' : timeLeft <= 15 ? 'var(--warning)' : 'var(--accent)';
}

function autoSubmitTimeout() {
    const q = questions[currentQ];
    answers[q.id] = -1; // unanswered
    showTimeout();
    setTimeout(nextQuestion, 1500);
}

function showTimeout() {
    const opts = document.querySelectorAll('.option-item');
    opts.forEach(o => o.classList.add('disabled'));
    // Highlight correct
    const q = questions[currentQ];
    opts.forEach(o => {
        if (parseInt(o.dataset.idx) === q.correct) o.classList.add('correct');
    });
}

// ─── SELECT OPTION ─────────────────────────────
function selectOption(idx, qid) {
    if (document.querySelector('.option-item.disabled')) return;
    clearInterval(timerInterval);
    answers[qid] = idx;
    const opts = document.querySelectorAll('.option-item');
    opts.forEach(o => {
        o.classList.add('disabled');
        if (parseInt(o.dataset.idx) === idx) o.classList.add('selected');
    });
    setTimeout(nextQuestion, 800);
}

// ─── NEXT QUESTION ─────────────────────────────
function nextQuestion() {
    currentQ++;
    if (currentQ >= questions.length) {
        submitQuiz();
    } else {
        renderQuestion();
    }
}

// ─── TOTAL TIME ────────────────────────────────
function startTotalTimer() {
    totalTime = 0;
    totalTimeInterval = setInterval(() => totalTime++, 1000);
}

// ─── SUBMIT QUIZ ───────────────────────────────
async function submitQuiz() {
    clearInterval(timerInterval);
    clearInterval(totalTimeInterval);
    const body = { answers, time_taken: totalTime };
    const res = await fetch('/api/submit_quiz', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(body)
    });
    const data = await res.json();
    window.location.href = `/result/${data.result_id}`;
}

// ─── INIT ──────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    const startBtn = document.getElementById('start-btn');
    if (startBtn) {
        startBtn.addEventListener('click', () => {
            const topic = document.getElementById('topic-select').value;
            const count = document.getElementById('count-select').value;
            loadQuiz(topic, count);
        });
    }
});