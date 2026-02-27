from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, random
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.jinja_env.globals.update(enumerate=enumerate)
app.secret_key = 'cybersec_quiz_secret_key_2024_xK9mP2qR'
DB_PATH = os.path.join(os.path.dirname(__file__), 'database', 'cybersec.db')

# ─── DATABASE ───────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS questions (
            question_id INTEGER PRIMARY KEY AUTOINCREMENT,
            question_text TEXT NOT NULL,
            option1 TEXT NOT NULL, option2 TEXT NOT NULL,
            option3 TEXT NOT NULL, option4 TEXT NOT NULL,
            correct_option INTEGER NOT NULL,
            topic TEXT NOT NULL,
            difficulty TEXT DEFAULT 'medium',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS results (
            result_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            score INTEGER NOT NULL,
            total_questions INTEGER NOT NULL,
            percentage REAL NOT NULL,
            grade TEXT NOT NULL,
            time_taken INTEGER DEFAULT 0,
            date_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        );
        CREATE TABLE IF NOT EXISTS result_details (
            detail_id INTEGER PRIMARY KEY AUTOINCREMENT,
            result_id INTEGER NOT NULL,
            question_id INTEGER NOT NULL,
            selected_option INTEGER,
            is_correct INTEGER DEFAULT 0,
            FOREIGN KEY (result_id) REFERENCES results(result_id)
        );
    ''')
    admin_pass = generate_password_hash('Admin@123')
    try:
        c.execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",
                  ('Administrator','admin@cybersec.com',admin_pass,'admin'))
    except sqlite3.IntegrityError:
        pass
    conn.commit()
    seed_questions(conn)
    conn.close()

def seed_questions(conn):
    c = conn.cursor()
    if c.execute("SELECT COUNT(*) FROM questions").fetchone()[0] > 0:
        return
    questions = [
        # PHISHING
        ("What is phishing?","A fishing sport","An attack using deceptive emails/sites to steal info","A type of firewall","A network protocol",2,"phishing","easy"),
        ("Which is a sign of a phishing email?","Email from known sender","Urgent request to click a link to verify your account","Professional company logo","Email with no attachments",2,"phishing","easy"),
        ("What to do with a suspicious email asking for your password?","Reply with your password","Click the link to verify","Delete it and report as phishing","Forward to colleagues",3,"phishing","easy"),
        ("Spear phishing targets:","Random users","Only mobile devices","Specific individuals","Mass email lists",3,"phishing","medium"),
        ("Vishing uses:","Email","Social media","Voice calls","USB drives",3,"phishing","medium"),
        ("Smishing is phishing via:","Social media","SMS text messages","Email","Malware",2,"phishing","medium"),
        ("Which URL is likely a phishing attempt?","https://www.google.com","https://secure-bankk.com/login","https://www.amazon.com","https://github.com",2,"phishing","hard"),
        ("Whaling targets:","Large databases","High-profile executives","Random users","Government servers",2,"phishing","hard"),
        # MALWARE
        ("What is malware?","Software enhancing performance","Malicious software to damage or gain unauthorized access","A type of antivirus","A security protocol",2,"malware","easy"),
        ("Ransomware typically:","Speeds up your computer","Encrypts files and demands payment","Improves security","Removes viruses",2,"malware","easy"),
        ("A Trojan horse is:","A self-replicating virus","Malware disguised as legitimate software","A network tool","A firewall type",2,"malware","easy"),
        ("Which is NOT malware?","Worm","Rootkit","Firewall","Spyware",3,"malware","medium"),
        ("A keylogger:","Improves keyboard speed","Records keystrokes to steal passwords","Manages system logs","Optimizes disk",2,"malware","medium"),
        ("A computer worm differs from a virus because it:","Requires user interaction","Self-replicates without needing a host file","Only affects mobiles","Encrypts files",2,"malware","medium"),
        ("A botnet is:","A single malware program","A network of infected computers controlled remotely","A type of firewall","A speed booster",2,"malware","hard"),
        ("Zero-day vulnerability means:","Found 24 hours ago","Unknown flaw with no available patch","A daily security update","Expired license",2,"malware","hard"),
        # PASSWORDS
        ("Which password is strongest?","password123","MyDog2024","Tr!9kL@2024#mQ","abcdefgh",3,"passwords","easy"),
        ("How often should you change critical passwords?","Never","Every 3-6 months or after a breach","Only when forgotten","Once a year",2,"passwords","easy"),
        ("What is MFA?","Multiple passwords","Requiring more than one verification method","Multiple accounts","Different browsers",2,"passwords","easy"),
        ("A password manager:","Stores passwords in plain text","Securely stores and generates strong passwords","Shares passwords with support","Only works on mobile",2,"passwords","medium"),
        ("A bad password practice:","Using mixed characters","Using same password for multiple accounts","Using 12+ characters","Enabling 2FA",2,"passwords","easy"),
        ("Brute force attack:","Physically steals keyboard","Tries all possible combinations to crack a password","Guesses based on personal info","Uses social engineering",2,"passwords","medium"),
        ("Dictionary attack uses:","Random characters","Common words and known password lists","Keyboard patterns","Alphanumeric sequences",2,"passwords","hard"),
        # NETWORK SECURITY
        ("What does a firewall do?","Speeds up internet","Monitors and controls network traffic based on rules","Stores network data","Encrypts email",2,"network","easy"),
        ("HTTPS is more secure because:","It loads faster","It encrypts data between browser and server","It blocks all ads","It compresses files",2,"network","easy"),
        ("What is a VPN?","A type of virus","A service encrypting traffic and masking your IP","A browser plugin","A speed booster",2,"network","easy"),
        ("Man-in-the-Middle attack:","Server crashes","Attacker intercepts communication between two parties","User forgets password","Firewall blocks traffic",2,"network","medium"),
        ("What is a DDoS attack?","A type of phishing","Overwhelming a server to make it unavailable","Installing malware","Stealing credentials",2,"network","medium"),
        ("Public Wi-Fi is dangerous because:","It is slow","Data can be intercepted by attackers","High fees","Blocks secure sites",2,"network","easy"),
        ("What is SSL/TLS used for?","Speeding up connections","Encrypting data in transit between client and server","Managing IPs","Blocking malicious sites",2,"network","medium"),
        ("DNS spoofing redirects users to:","Faster DNS servers","Fake websites by corrupting DNS records","More secure connections","Backup servers",2,"network","hard"),
        # SOCIAL ENGINEERING
        ("Social engineering exploits:","Software vulnerabilities","Human psychology and trust","Hardware weaknesses","Network protocols",2,"social_engineering","easy"),
        ("Pretexting means:","Sending malicious emails","Creating a fabricated scenario to manipulate victims","Cracking passwords","Installing malware",2,"social_engineering","medium"),
        ("Tailgating in physical security:","Following while driving","Gaining unauthorized access by following authorized personnel","A network attack","A phishing technique",2,"social_engineering","medium"),
        ("Baiting involves:","Threatening with legal action","Luring victims with something enticing","Impersonating IT support","Sending spam",2,"social_engineering","medium"),
        ("Best defense against social engineering:","Strong antivirus only","Security awareness training and verification","Complex passwords","Firewall configuration",2,"social_engineering","easy"),
        # DATA PROTECTION
        ("What is data encryption?","Deleting sensitive files","Converting data to unreadable format without a key","Backing up data","Compressing files",2,"data_protection","easy"),
        ("GDPR stands for:","General Data Privacy Regulation","General Data Protection Regulation","Global Digital Privacy Rules","Government Data Protection Rights",2,"data_protection","easy"),
        ("Principle of least privilege means:","Give admin rights to all","Users have only the access needed for their job","Delete unused accounts","Share passwords with managers",2,"data_protection","medium"),
        ("What is PII?","Public Internet Interface","Personally Identifiable Information","Private IP Infrastructure","Protected Intelligence",2,"data_protection","easy"),
        ("End-to-end encryption means:","Encrypted only at server","Encrypted sender-to-recipient with no third-party access","Automatic backups","Compressed transfer",2,"data_protection","hard"),
        # BROWSING
        ("Padlock icon in browser URL means:","Site is completely safe","Connection is encrypted (HTTPS)","Password is saved","Government approved",2,"browsing","easy"),
        ("Browser cookies are:","Malware disguised as files","Small data files storing user preferences","Antivirus scan results","Network speed tests",2,"browsing","easy"),
        ("Browser extensions risk:","Slow down browser","Malicious ones can steal data and monitor activity","Use too much memory","Block legitimate sites",2,"browsing","medium"),
        ("Before entering credit card info:","Check product count","Verify HTTPS and look for privacy policy","Check load speed","Look at design",2,"browsing","easy"),
        ("Drive-by download attack:","Intentional software download","Malware installed just by visiting a compromised site","USB drive use","Email attachment",2,"browsing","medium"),
        # INCIDENT RESPONSE
        ("First step when account is hacked:","Wait and see","Change password and enable MFA immediately","Delete account","Ignore it",2,"incident_response","easy"),
        ("Security incident response plan helps:","Avoid all attacks","Systematically detect, respond to and recover from incidents","Eliminate all malware","Prevent all data loss",2,"incident_response","medium"),
        ("Digital forensics involves:","Repairing hardware","Collecting and analyzing digital evidence after an incident","Designing secure systems","Training employees",2,"incident_response","hard"),
        # GENERAL
        ("CIA in information security stands for:","Central Intelligence Agency","Confidentiality, Integrity, Availability","Cyber Intelligence Architecture","Computer Internet Access",2,"general","easy"),
        ("What is an IDS?","Speeds up network","Detects and alerts on suspicious activity or policy violations","Blocks all external connections","Encrypts data on hard drives",2,"general","medium"),
        ("2FA provides:","Double encryption","Additional verification layer beyond password","Two separate passwords","Access to two accounts",2,"general","easy"),
        ("Patch management means:","Repairing network cables","Regularly updating software to fix vulnerabilities","Creating data backups","Managing antivirus subscriptions",2,"general","easy"),
        ("Ethical hacking is:","Hacking for financial gain","Authorized testing to find vulnerabilities before attackers","Hacking with good intent but no permission","Creating malware for research",2,"general","medium"),
        ("BYOD security concern:","Employees work too much","Personal devices may lack corporate security controls","Slow internet","High hardware costs",2,"general","medium"),
        ("A honey pot is:","A reward for hackers","A decoy system to lure and study attackers","A type of encryption","A password vault",2,"general","hard"),
        ("Shoulder surfing means:","A surfing competition","Looking over shoulder to steal sensitive information","A social media hack","A DDoS attack",2,"general","easy"),
        # CRYPTOGRAPHY
        ("Digital signature is used for:","Signing physical documents","Verifying authenticity and integrity of digital messages","Encrypting email passwords","Creating certificates only",2,"cryptography","medium"),
        ("Symmetric encryption uses:","Two different keys","The same key for both encryption and decryption","Public and private key pairs","No keys",2,"cryptography","hard"),
        ("A Certificate Authority (CA):","Certifies antivirus software","Issues digital certificates to verify identities","Regulates the internet","Is a type of firewall",2,"cryptography","hard"),
        ("MD5 and SHA are examples of:","Encryption algorithms","Hash functions","Password managers","VPN protocols",2,"cryptography","hard"),
        ("What is SIEM?","Security Information Event Management","System Integrity Error Monitoring","Secure Internet Email Mgmt","Software Infrastructure Event Mgmt",1,"general","hard"),
    ]
    c.executemany(
        "INSERT INTO questions(question_text,option1,option2,option3,option4,correct_option,topic,difficulty) VALUES(?,?,?,?,?,?,?,?)",
        questions)
    conn.commit()

# ─── DECORATORS ─────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to continue.','warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Admin access required.','danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

# ─── AUTH ROUTES ─────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm = request.form['confirm_password']
        if len(password) < 8:
            flash('Password must be at least 8 characters.','danger')
            return render_template('register.html')
        if password != confirm:
            flash('Passwords do not match.','danger')
            return render_template('register.html')
        conn = get_db()
        try:
            conn.execute("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)",
                         (name, email, generate_password_hash(password)))
            conn.commit()
            flash('Account created! Please login.','success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already registered.','danger')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session.update({'user_id':user['user_id'],'name':user['name'],
                            'email':user['email'],'role':user['role']})
            return redirect(url_for('admin_dashboard') if user['role']=='admin' else url_for('dashboard'))
        flash('Invalid credentials.','danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ─── USER ROUTES ─────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    results = conn.execute("SELECT * FROM results WHERE user_id=? ORDER BY date_time DESC LIMIT 10",
                           (session['user_id'],)).fetchall()
    stats = conn.execute("""SELECT COUNT(*) as total, ROUND(AVG(percentage),1) as avg_pct,
        MAX(percentage) as best_pct,
        SUM(CASE WHEN grade='A' THEN 1 ELSE 0 END) as ga,
        SUM(CASE WHEN grade='B' THEN 1 ELSE 0 END) as gb,
        SUM(CASE WHEN grade='C' THEN 1 ELSE 0 END) as gc,
        SUM(CASE WHEN grade='D' THEN 1 ELSE 0 END) as gd
        FROM results WHERE user_id=?""",(session['user_id'],)).fetchone()
    conn.close()
    return render_template('dashboard.html', results=results, stats=stats)

@app.route('/quiz')
@login_required
def quiz():
    return render_template('quiz_start.html')

@app.route('/api/get_questions', methods=['POST'])
@login_required
def get_questions():
    data = request.get_json()
    topic = data.get('topic','all')
    count = int(data.get('count', 15))
    conn = get_db()
    if topic == 'all':
        qs = conn.execute("SELECT * FROM questions ORDER BY RANDOM() LIMIT ?", (count,)).fetchall()
    else:
        qs = conn.execute("SELECT * FROM questions WHERE topic=? ORDER BY RANDOM() LIMIT ?",
                          (topic, count)).fetchall()
    conn.close()
    return jsonify({'questions':[{
        'id': q['question_id'], 'text': q['question_text'],
        'options': [q['option1'],q['option2'],q['option3'],q['option4']],
        'topic': q['topic'], 'difficulty': q['difficulty']
    } for q in qs]})

@app.route('/api/submit_quiz', methods=['POST'])
@login_required
def submit_quiz():
    data = request.get_json()
    answers = data.get('answers', {})
    time_taken = data.get('time_taken', 0)
    conn = get_db()
    score = 0
    details = []
    for qid_str, selected in answers.items():
        qid = int(qid_str)
        q = conn.execute("SELECT * FROM questions WHERE question_id=?",(qid,)).fetchone()
        if q:
            correct = 1 if selected == q['correct_option'] else 0
            score += correct
            details.append((qid, selected, correct))
    total = len(answers)
    pct = round(score/total*100, 2) if total > 0 else 0
    grade = 'A' if pct>=90 else ('B' if pct>=75 else ('C' if pct>=50 else 'D'))
    c = conn.cursor()
    c.execute("INSERT INTO results(user_id,score,total_questions,percentage,grade,time_taken) VALUES(?,?,?,?,?,?)",
              (session['user_id'], score, total, pct, grade, time_taken))
    rid = c.lastrowid
    for qid, sel, cor in details:
        c.execute("INSERT INTO result_details(result_id,question_id,selected_option,is_correct) VALUES(?,?,?,?)",
                  (rid, qid, sel, cor))
    conn.commit(); conn.close()
    return jsonify({'score':score,'total':total,'percentage':pct,'grade':grade,
                    'result_id':rid,'certificate':grade!='D'})

@app.route('/result/<int:result_id>')
@login_required
def result(result_id):
    conn = get_db()
    res = conn.execute("""SELECT r.*,u.name FROM results r JOIN users u ON r.user_id=u.user_id
        WHERE r.result_id=? AND r.user_id=?""",(result_id, session['user_id'])).fetchone()
    if not res:
        flash('Result not found.','danger'); return redirect(url_for('dashboard'))
    details = conn.execute("""SELECT rd.*,q.question_text,q.option1,q.option2,q.option3,q.option4,
        q.correct_option,q.topic FROM result_details rd
        JOIN questions q ON rd.question_id=q.question_id WHERE rd.result_id=?""",(result_id,)).fetchall()
    conn.close()
    return render_template('result.html', res=res, details=details)

@app.route('/progress')
@login_required
def progress():
    conn = get_db()
    results = conn.execute("SELECT * FROM results WHERE user_id=? ORDER BY date_time ASC",
                           (session['user_id'],)).fetchall()
    topic_stats = conn.execute("""SELECT q.topic, COUNT(*) as total, SUM(rd.is_correct) as correct
        FROM result_details rd JOIN questions q ON rd.question_id=q.question_id
        JOIN results r ON rd.result_id=r.result_id WHERE r.user_id=? GROUP BY q.topic""",
        (session['user_id'],)).fetchall()
    conn.close()
    return render_template('progress.html', results=results, topic_stats=topic_stats)

@app.route('/certificate/<int:result_id>')
@login_required
def certificate(result_id):
    conn = get_db()
    res = conn.execute("""SELECT r.*,u.name,u.email FROM results r JOIN users u ON r.user_id=u.user_id
        WHERE r.result_id=? AND r.user_id=?""",(result_id, session['user_id'])).fetchone()
    conn.close()
    if not res or res['grade']=='D':
        flash('Certificate only for grades A, B, C.','warning'); return redirect(url_for('dashboard'))
    return render_template('certificate.html', res=res)

# ─── ADMIN ROUTES ─────────────────────────────────────────────
@app.route('/admin')
@admin_required
def admin_dashboard():
    conn = get_db()
    stats = {
        'total_users': conn.execute("SELECT COUNT(*) FROM users WHERE role='user'").fetchone()[0],
        'total_questions': conn.execute("SELECT COUNT(*) FROM questions").fetchone()[0],
        'total_results': conn.execute("SELECT COUNT(*) FROM results").fetchone()[0],
        'avg_score': conn.execute("SELECT ROUND(AVG(percentage),1) FROM results").fetchone()[0] or 0,
    }
    recent = conn.execute("""SELECT r.*,u.name,u.email FROM results r
        JOIN users u ON r.user_id=u.user_id ORDER BY r.date_time DESC LIMIT 10""").fetchall()
    grade_dist = conn.execute("SELECT grade, COUNT(*) as count FROM results GROUP BY grade").fetchall()
    conn.close()
    return render_template('admin_dashboard.html', stats=stats, recent=recent, grade_dist=grade_dist)

@app.route('/admin/questions')
@admin_required
def admin_questions():
    topic_filter = request.args.get('topic','all')
    conn = get_db()
    if topic_filter == 'all':
        qs = conn.execute("SELECT * FROM questions ORDER BY topic,question_id").fetchall()
    else:
        qs = conn.execute("SELECT * FROM questions WHERE topic=? ORDER BY question_id",(topic_filter,)).fetchall()
    topics = conn.execute("SELECT DISTINCT topic FROM questions ORDER BY topic").fetchall()
    conn.close()
    return render_template('admin_questions.html', questions=qs, topics=topics, current_topic=topic_filter)

@app.route('/admin/questions/add', methods=['GET','POST'])
@admin_required
def admin_add_question():
    if request.method == 'POST':
        conn = get_db()
        conn.execute("""INSERT INTO questions(question_text,option1,option2,option3,option4,
            correct_option,topic,difficulty) VALUES(?,?,?,?,?,?,?,?)""",
            (request.form['question_text'],request.form['option1'],request.form['option2'],
             request.form['option3'],request.form['option4'],int(request.form['correct_option']),
             request.form['topic'],request.form['difficulty']))
        conn.commit(); conn.close()
        flash('Question added successfully!','success')
        return redirect(url_for('admin_questions'))
    return render_template('admin_question_form.html', question=None, action='Add')

@app.route('/admin/questions/edit/<int:qid>', methods=['GET','POST'])
@admin_required
def admin_edit_question(qid):
    conn = get_db()
    if request.method == 'POST':
        conn.execute("""UPDATE questions SET question_text=?,option1=?,option2=?,option3=?,
            option4=?,correct_option=?,topic=?,difficulty=? WHERE question_id=?""",
            (request.form['question_text'],request.form['option1'],request.form['option2'],
             request.form['option3'],request.form['option4'],int(request.form['correct_option']),
             request.form['topic'],request.form['difficulty'],qid))
        conn.commit(); conn.close()
        flash('Question updated!','success')
        return redirect(url_for('admin_questions'))
    q = conn.execute("SELECT * FROM questions WHERE question_id=?",(qid,)).fetchone()
    conn.close()
    return render_template('admin_question_form.html', question=q, action='Edit')

@app.route('/admin/questions/delete/<int:qid>', methods=['POST'])
@admin_required
def admin_delete_question(qid):
    conn = get_db()
    conn.execute("DELETE FROM questions WHERE question_id=?",(qid,))
    conn.commit(); conn.close()
    flash('Question deleted.','success')
    return redirect(url_for('admin_questions'))

@app.route('/admin/results')
@admin_required
def admin_results():
    search = request.args.get('search','')
    grade_filter = request.args.get('grade','all')
    conn = get_db()
    query = "SELECT r.*,u.name,u.email FROM results r JOIN users u ON r.user_id=u.user_id WHERE 1=1"
    params = []
    if search:
        query += " AND (u.name LIKE ? OR u.email LIKE ?)"; params += [f'%{search}%',f'%{search}%']
    if grade_filter != 'all':
        query += " AND r.grade=?"; params.append(grade_filter)
    query += " ORDER BY r.date_time DESC"
    results = conn.execute(query, params).fetchall()
    conn.close()
    return render_template('admin_results.html', results=results, search=search, grade_filter=grade_filter)

@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_db()
    users = conn.execute("""SELECT u.*, COUNT(r.result_id) as quiz_count,
        ROUND(AVG(r.percentage),1) as avg_score
        FROM users u LEFT JOIN results r ON u.user_id=r.user_id
        GROUP BY u.user_id ORDER BY u.created_at DESC""").fetchall()
    conn.close()
    return render_template('admin_users.html', users=users)

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
