import { useMemo, useState } from "react";
import "./Academy.css";

type Course = {
  id: number; title: string; category: string; level: string; duration: string;
  lessons: number; progress: number; color: string; accent: string; icon: string;
  description: string; enrolled?: boolean; tag?: string;
};

const initialCourses: Course[] = [
  { id: 1, title: "Think Before You Click", category: "Cybersecurity Basics", level: "Beginner", duration: "2h 20m", lessons: 8, progress: 65, color: "coral", accent: "SCAM SPOTTING", icon: "🕵🏽", description: "Learn to recognise phishing, suspicious links and the small warning signs scammers hope you miss.", enrolled: true, tag: "Popular" },
  { id: 2, title: "Your Digital Identity", category: "Digital Privacy", level: "Beginner", duration: "1h 45m", lessons: 6, progress: 25, color: "violet", accent: "OWN YOUR DATA", icon: "🪪", description: "Protect your personal information, accounts and digital footprint.", enrolled: true },
  { id: 3, title: "The Art of Safe Banking", category: "Financial Safety", level: "Intermediate", duration: "3h 10m", lessons: 10, progress: 0, color: "mint", accent: "MONEY SMART", icon: "💳", description: "Understand mobile-money fraud, fake payment messages and safer transactions.", tag: "New" },
  { id: 4, title: "Decode the Caller", category: "Digital Trust", level: "Beginner", duration: "1h 30m", lessons: 5, progress: 0, color: "blue", accent: "CALLER AWARENESS", icon: "📞", description: "Explore caller impersonation, spoofing and ways to verify claims before you act." },
  { id: 5, title: "Social Media, Safely", category: "Digital Privacy", level: "Beginner", duration: "2h", lessons: 7, progress: 0, color: "yellow", accent: "SHARE WITH CARE", icon: "🌈", description: "Make smarter choices about posts, privacy settings, messages and online relationships." },
  { id: 6, title: "Build Your Cyber Defence", category: "Cybersecurity Basics", level: "Advanced", duration: "4h 15m", lessons: 12, progress: 0, color: "pink", accent: "LEVEL UP", icon: "🛡️", description: "Bring security habits together in practical scenarios and challenges." },
];

const categories = ["All courses", "Cybersecurity Basics", "Digital Privacy", "Financial Safety", "Digital Trust"];
const navItems = [
  { id: "overview", icon: "✦", label: "Overview" },
  { id: "courses", icon: "▤", label: "Explore courses" },
  { id: "my-learning", icon: "◷", label: "My learning" },
  { id: "ai-tutor", icon: "✧", label: "AI Tutor", fresh: true },
  { id: "community", icon: "◎", label: "Community" },
  { id: "live-classes", icon: "◉", label: "Live classes" },
  { id: "certificates", icon: "♜", label: "Certificates" },
  { id: "analytics", icon: "▥", label: "My progress" },
];

function Academy() {
  const [active, setActive] = useState("overview");
  const [category, setCategory] = useState("All courses");
  const [query, setQuery] = useState("");
  const [courses, setCourses] = useState(initialCourses);
  const [selected, setSelected] = useState<Course | null>(null);
  const [toast, setToast] = useState("");
  const [showAuth, setShowAuth] = useState(false);
  const [showProfile, setShowProfile] = useState(false);
  const [tutorQuestion, setTutorQuestion] = useState("");
  const [tutorMessages, setTutorMessages] = useState<{ role: string; text: string }[]>([
    { role: "assistant", text: "Hey there! 👋 I'm your CYVORA learning companion. Ask me about phishing, passwords, online safety or anything in your lessons. We'll figure it out together." },
  ]);
  const [quizAnswer, setQuizAnswer] = useState("");
  const [quizChecked, setQuizChecked] = useState(false);
  const [mobileMenu, setMobileMenu] = useState(false);

  const enrolled = courses.filter(c => c.enrolled);
  const filtered = useMemo(() => courses.filter(c =>
    (category === "All courses" || c.category === category) &&
    (c.title + c.description + c.category).toLowerCase().includes(query.toLowerCase())
  ), [courses, category, query]);

  const notify = (message: string) => {
    setToast(message);
    window.setTimeout(() => setToast(""), 2600);
  };

  const enroll = (course: Course) => {
    setCourses(prev => prev.map(c => c.id === course.id ? { ...c, enrolled: true } : c));
    setSelected(null);
    notify("You're enrolled! Your learning journey starts now ✨");
    setActive("my-learning");
  };

  const askTutor = () => {
    const q = tutorQuestion.trim();
    if (!q) return;
    setTutorMessages(prev => [...prev, { role: "user", text: q }, {
      role: "assistant",
      text: "Great question! Here's a safe starting point: pause before acting, check the sender or source independently, and never share passwords, PINs or one-time codes. I'm currently a frontend demo tutor; connect the CYVORA Academy AI service to provide personalised, lesson-aware answers."
    }]);
    setTutorQuestion("");
  };

  const pageTitle = navItems.find(n => n.id === active)?.label ?? "Overview";

  return (
    <div className="academy-shell">
      <aside className={`academy-sidebar ${mobileMenu ? "is-open" : ""}`}>
        <div className="academy-brand">
          <div className="academy-brand-mark">C<span>✦</span></div>
          <div><strong>CYVORA</strong><small>ACADEMY</small></div>
          <button className="academy-mobile-close" onClick={() => setMobileMenu(false)} aria-label="Close menu">×</button>
        </div>
        <div className="academy-side-label">LEARNING SPACE</div>
        <nav className="academy-nav">
          {navItems.map(item => <button key={item.id} className={active === item.id ? "active" : ""} onClick={() => { setActive(item.id); setMobileMenu(false); }}>
            <span className="nav-icon">{item.icon}</span><span>{item.label}</span>{item.fresh && <i>NEW</i>}
          </button>)}
        </nav>
        <div className="academy-side-card">
          <div className="side-spark">✦</div>
          <strong>Small steps.<br/>Stronger digital you.</strong>
          <p>Every lesson makes your online world a little safer.</p>
          <div className="side-progress"><span /></div>
          <small>2 of 6 courses started</small>
        </div>
        <div className="academy-sidebar-bottom"><span className="status-dot"/> Your safe learning space <span>v1.0</span></div>
      </aside>

      <main className="academy-main">
        <header className="academy-topbar">
          <button className="academy-menu-toggle" onClick={() => setMobileMenu(true)} aria-label="Open menu">☰</button>
          <div className="academy-breadcrumb">CYVORA <span>/</span> ACADEMY <span>/</span> <b>{pageTitle.toUpperCase()}</b></div>
          <div className="academy-top-actions">
            <button className="academy-streak" onClick={() => notify("Keep learning to grow your streak!")}><span>🔥</span> 4 day streak</button>
            <button className="academy-avatar" onClick={() => setShowProfile(v => !v)}>KD</button>
            {showProfile && <div className="academy-profile-pop"><strong>Welcome, learner!</strong><span>Guest learning profile</span><button onClick={() => setShowAuth(true)}>Sign in / Create account</button></div>}
          </div>
        </header>

        {active === "overview" && <section className="academy-content">
          <div className="academy-hero">
            <div className="hero-orbit orbit-one"/><div className="hero-orbit orbit-two"/>
            <div className="hero-copy">
              <div className="eyebrow light"><span/> YOUR DIGITAL CONFIDENCE STARTS HERE</div>
              <h1>Learn boldly.<br/><em>Live safer.</em></h1>
              <p>Cybersecurity isn't just for experts. Discover practical skills, unlock new confidence and make every click count.</p>
              <div className="hero-buttons"><button className="btn-white" onClick={() => setActive("courses")}>Explore courses <span>↗</span></button><button className="btn-ghost" onClick={() => setActive("ai-tutor")}>Meet your AI Tutor ✦</button></div>
              <div className="hero-social-proof"><span className="mini-avatars">K S T</span><span>Real skills for a safer digital life</span></div>
            </div>
            <div className="hero-art" aria-label="Illustration of a learner exploring digital security">
              <div className="hero-art-ring"/><div className="hero-shield">🛡️</div><div className="float-card float-lock">🔐 <span>Privacy first</span></div><div className="float-card float-star">✦ <span>Level up!</span></div><div className="float-card float-check">✓ <span>Stay curious</span></div><div className="hero-art-caption">YOUR SKILLS, YOUR SUPERPOWER</div>
            </div>
            <div className="hero-bottom-note">PROTECT <b>·</b> VERIFY <b>·</b> GROW</div>
          </div>

          <div className="academy-welcome-row"><div><div className="eyebrow">YOUR LEARNING JOURNEY</div><h2>Good to see you, <span>learner!</span> 👋</h2><p>A little progress every day adds up to something powerful.</p></div><button className="text-link" onClick={() => setActive("my-learning")}>View my learning →</button></div>
          <div className="academy-stats">
            <div className="stat-card stat-xp"><div className="stat-icon">⚡</div><div><small>TOTAL XP</small><strong>1,240</strong><span>+120 this week</span></div><div className="stat-decoration">✦</div></div>
            <div className="stat-card stat-badge"><div className="stat-icon">🏅</div><div><small>BADGES EARNED</small><strong>08</strong><span>2 more to next level</span></div><div className="stat-decoration">✧</div></div>
            <div className="stat-card stat-time"><div className="stat-icon">⏱️</div><div><small>LEARNING TIME</small><strong>6.5h</strong><span>You're on a roll</span></div><div className="stat-decoration">◷</div></div>
            <div className="stat-card stat-streak"><div className="stat-icon">🔥</div><div><small>DAY STREAK</small><strong>04</strong><span>Keep the flame alive</span></div><div className="stat-decoration">✦</div></div>
          </div>

          <div className="academy-section-heading"><div><div className="eyebrow">PICK UP WHERE YOU LEFT OFF</div><h2>Continue your adventure</h2></div><button className="text-link" onClick={() => setActive("my-learning")}>All my courses →</button></div>
          <div className="continue-grid">{enrolled.map(c => <article className={`continue-card course-${c.color}`} key={c.id}><div className="continue-art"><span>{c.icon}</span><small>{c.accent}</small><i>✦</i></div><div className="continue-info"><div className="course-meta"><span>{c.category}</span><span>{c.progress}% complete</span></div><h3>{c.title}</h3><div className="progress-track"><span style={{width:`${c.progress}%`}}/></div><button onClick={() => setSelected(c)}>Continue learning <b>→</b></button></div></article>)}</div>

          <div className="academy-section-heading explore-heading"><div><div className="eyebrow">CURIOUS MINDS WELCOME</div><h2>Find your next superpower</h2><p>Short, practical courses built for the real digital world.</p></div><button className="text-link" onClick={() => setActive("courses")}>Explore all courses →</button></div>
          <div className="course-grid">{courses.filter(c => !c.enrolled).slice(0,3).map(c => <CourseCard key={c.id} course={c} onOpen={() => setSelected(c)}/>)}</div>
          <div className="academy-bottom-banner"><div><span className="banner-kicker">A QUESTION? A BIG IDEA?</span><h2>Your AI Tutor is all ears.</h2><p>Get friendly explanations, learning hints and help when you need it.</p><button onClick={() => setActive("ai-tutor")}>Ask the AI Tutor <span>↗</span></button></div><div className="tutor-orb">✧</div></div>
        </section>}

        {active === "courses" && <section className="academy-content">
          <div className="page-intro"><div className="eyebrow">THE LEARNING LIBRARY</div><h1>Explore your <span>next skill.</span></h1><p>Choose a path, follow your curiosity and build confidence one lesson at a time.</p></div>
          <div className="course-tools"><div className="academy-search"><span>⌕</span><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search courses, skills or topics..."/></div><div className="category-pills">{categories.map(c => <button key={c} className={category===c?"selected":""} onClick={() => setCategory(c)}>{c}</button>)}</div></div>
          <div className="course-grid full-course-grid">{filtered.map(c => <CourseCard key={c.id} course={c} onOpen={() => setSelected(c)}/>)}</div>
          {filtered.length===0 && <div className="empty-state">No courses found. Try another search or category.</div>}
        </section>}

        {active === "my-learning" && <section className="academy-content">
          <div className="page-intro"><div className="eyebrow">YOUR PERSONAL LEARNING PATH</div><h1>Keep your <span>momentum.</span></h1><p>Your courses, your pace, your progress.</p></div>
          <div className="learning-summary"><div><small>IN PROGRESS</small><strong>{enrolled.length}</strong></div><div><small>LESSONS COMPLETED</small><strong>13</strong></div><div><small>XP EARNED</small><strong>1,240</strong></div><div><small>CURRENT STREAK</small><strong>🔥 4 days</strong></div></div>
          <div className="course-grid full-course-grid">{enrolled.map(c => <CourseCard key={c.id} course={c} onOpen={() => setSelected(c)}/>)}</div>
        </section>}

        {active === "ai-tutor" && <section className="academy-content tutor-page">
          <div className="page-intro"><div className="eyebrow">YOUR PERSONAL LEARNING COMPANION</div><h1>Curiosity looks good <span>on you.</span></h1><p>Ask questions. Explore ideas. Understand cybersecurity in your own words.</p></div>
          <div className="tutor-layout"><div className="tutor-panel"><div className="tutor-panel-head"><div className="tutor-avatar">✧</div><div><strong>CYVORA AI Tutor</strong><small><span className="status-dot"/> Learning companion · Demo mode</small></div><span className="tutor-spark">✦</span></div><div className="tutor-chat">{tutorMessages.map((m,i)=><div key={i} className={`tutor-message ${m.role}`}><span>{m.role==="assistant"?"✧":"You"}</span><p>{m.text}</p></div>)}</div><div className="tutor-input"><input value={tutorQuestion} onChange={e=>setTutorQuestion(e.target.value)} onKeyDown={e=>e.key==="Enter"&&askTutor()} placeholder="Ask me anything about online safety..."/><button onClick={askTutor}>Send ↗</button></div><small className="demo-disclaimer">Demo responses only. Connect the CYVORA AI Tutor service for live, personalised answers.</small></div><aside className="tutor-suggestions"><h3>Try asking…</h3>{["How do I spot a phishing message?","What makes a password strong?","What should I do after clicking a suspicious link?","Explain two-factor authentication simply."] .map(q=><button key={q} onClick={()=>setTutorQuestion(q)}>✦ {q}</button>)}<div className="tutor-tip"><strong>Learning tip</strong><p>There are no silly questions here. The best way to learn is to stay curious.</p></div></aside></div>
        </section>}

        {active === "community" && <section className="academy-content"><div className="page-intro"><div className="eyebrow">LEARN BETTER, TOGETHER</div><h1>Welcome to the <span>community.</span></h1><p>Share ideas, ask questions and learn alongside other digital explorers.</p></div><div className="community-grid"><article className="community-feature"><span className="community-emoji">🌍</span><div className="eyebrow light">COMMUNITY SPOTLIGHT</div><h2>Safer digital lives start with shared knowledge.</h2><p>Join thoughtful conversations about online safety, privacy and building a more trusted digital world.</p><button onClick={()=>notify("Community discussions will be available when the forum is connected.")}>Explore discussions ↗</button></article><div className="community-topics">{[["🛡️","Scam alerts & awareness","Share warning signs and learn together","128 discussions"],["🔐","Privacy & account safety","Practical ways to protect your digital identity","86 discussions"],["💡","Learner questions","Ask, explain and grow together","54 discussions"]].map(x=><article key={x[1]}><span>{x[0]}</span><div><strong>{x[1]}</strong><p>{x[2]}</p><small>{x[3]}</small></div><b>→</b></article>)}</div></div></section>}

        {active === "live-classes" && <section className="academy-content"><div className="page-intro"><div className="eyebrow">LEARN LIVE, ASK REAL QUESTIONS</div><h1>Bring learning <span>to life.</span></h1><p>Join expert-led sessions and learn with a community.</p></div><div className="live-feature"><div className="live-visual"><div className="live-play">▶</div><span>LIVE LEARNING EXPERIENCES</span><b>🎙️</b></div><div className="live-copy"><div className="eyebrow">UPCOMING SESSION</div><h2>Inside the scammer's playbook</h2><p>Learn how social engineering works, the red flags to look for and how to protect yourself.</p><div className="live-details"><span>◷ To be announced</span><span>◉ Online session</span></div><button onClick={()=>notify("Class registration will open when live-class scheduling is connected.")}>Notify me when available ↗</button></div></div><div className="notice-card">📅 Live class schedules and registration will appear here once the Academy events service is connected.</div></section>}

        {active === "certificates" && <section className="academy-content"><div className="page-intro"><div className="eyebrow">CELEBRATE WHAT YOU KNOW</div><h1>Proof of your <span>progress.</span></h1><p>Complete learning paths and collect certificates that recognise your achievement.</p></div><div className="certificate-empty"><div className="certificate-art">🏆<span>✦</span></div><h2>Your next achievement is waiting.</h2><p>Finish a course and pass its final assessment to earn a certificate.</p><button onClick={()=>setActive("courses")}>Find a course ↗</button></div></section>}

        {active === "analytics" && <section className="academy-content"><div className="page-intro"><div className="eyebrow">YOUR GROWTH, MADE VISIBLE</div><h1>Look how far <span>you've come.</span></h1><p>Track your learning activity and celebrate every milestone.</p></div><div className="analytics-grid"><div className="analytics-card wide"><small>WEEKLY LEARNING ACTIVITY</small><h3>You're building a habit.</h3><div className="bar-chart">{[["Mon",42],["Tue",70],["Wed",55],["Thu",90],["Fri",35],["Sat",68],["Sun",25]].map(([d,v])=><div key={d as string}><span style={{height:`${v}%`}}/><small>{d}</small></div>)}</div></div><div className="analytics-card"><small>COURSE COMPLETION</small><div className="donut"><strong>42%</strong></div><p>You're making steady progress.</p></div><div className="analytics-card"><small>SKILLS IN PROGRESS</small><h3>4 skill areas</h3><div className="skill-line"><span>Scam awareness</span><b>65%</b><i><em style={{width:"65%"}}/></i></div><div className="skill-line"><span>Digital privacy</span><b>25%</b><i><em style={{width:"25%"}}/></i></div><div className="skill-line"><span>Financial safety</span><b>0%</b><i><em style={{width:"0%"}}/></i></div></div></div><p className="demo-disclaimer">Illustrative learning data for the frontend preview. Connect authenticated learner records for real analytics.</p></section>}
      </main>

      {selected && <div className="academy-modal-backdrop" onClick={()=>setSelected(null)}><div className="course-modal" onClick={e=>e.stopPropagation()}><button className="modal-close" onClick={()=>setSelected(null)}>×</button><div className={`modal-art course-${selected.color}`}><span>{selected.icon}</span><small>{selected.accent}</small></div><div className="modal-body"><div className="course-meta"><span>{selected.category}</span><span>{selected.level}</span></div><h2>{selected.title}</h2><p>{selected.description}</p><div className="modal-facts"><span>▤ {selected.lessons} lessons</span><span>◷ {selected.duration}</span><span>✦ Practical activities</span></div>{selected.enrolled ? <button className="modal-primary" onClick={()=>{setSelected(null);notify("Lesson player integration is the next step.");}}>Continue course ↗</button> : <button className="modal-primary" onClick={()=>enroll(selected)}>Enrol in this course ↗</button>}</div></div></div>}

      {showAuth && <div className="academy-modal-backdrop" onClick={()=>setShowAuth(false)}><div className="auth-modal" onClick={e=>e.stopPropagation()}><button className="modal-close" onClick={()=>setShowAuth(false)}>×</button><div className="auth-symbol">✦</div><div className="eyebrow">YOUR JOURNEY STARTS HERE</div><h2>Make this progress yours.</h2><p>Sign in or create a CYVORA account to save courses, XP, badges and certificates across devices.</p><button className="modal-primary" onClick={()=>{setShowAuth(false);notify("Connect CYVORA authentication to enable sign-in.");}}>Continue to sign in</button><small>Authentication UI preview · backend connection required</small></div></div>}

      {toast && <div className="academy-toast">{toast}</div>}
      <button className="academy-mobile-app" onClick={()=>notify("Mobile app information will be added when the app release is planned.")}>📱 <span>Learn anywhere — mobile experience coming soon</span></button>
    </div>
  );
}

function CourseCard({ course, onOpen }: { course: Course; onOpen: () => void }) {
  return <article className="academy-course-card"><div className={`course-card-art course-${course.color}`}><span>{course.icon}</span><small>{course.accent}</small>{course.tag && <b>{course.tag}</b>}</div><div className="course-card-body"><div className="course-meta"><span>{course.category}</span><span>{course.level}</span></div><h3>{course.title}</h3><p>{course.description}</p><div className="course-card-footer"><span>▤ {course.lessons} lessons · {course.duration}</span><button onClick={onOpen}>{course.enrolled ? "Continue" : "View course"} ↗</button></div></div></article>;
}

export default Academy;
