"use client";

import { useState, useEffect, useRef } from "react";
import { ThemeToggle } from "@/components/theme-toggle";

interface QuoteForm {
  regNumber: string;
  carValue: string;
  engineCC: string;
}

// ─── Product catalogue ────────────────────────────────────────────────────────
const PRODUCTS = [
  {
    id: "motor",
    label: "Motor Insurance",
    status: "live" as const,
    tagline: "Cover your vehicle in 2 minutes.",
    description:
      "Comprehensive and third-party motor insurance for private cars and motorcycles. IDRA-regulated, issued instantly, stored in the cloud.",
    features: [
      "Comprehensive & third-party options",
      "Policy PDF issued under 2 minutes",
      "Digital claim filing, surveyor in 2 hrs",
      "Covers private cars & motorcycles",
    ],
  },
  {
    id: "overseas",
    label: "Overseas Medical",
    status: "soon" as const,
    tagline: "Travel anywhere. Stay covered.",
    description:
      "International medical insurance for Bangladeshi travellers. Covers emergency hospitalisation, repatriation, trip cancellation, and more across 190+ countries.",
    features: [
      "Emergency hospitalisation worldwide",
      "Medical evacuation & repatriation",
      "Trip cancellation & delay cover",
      "190+ countries · single & multi-trip",
    ],
  },
  {
    id: "health",
    label: "Health Insurance",
    status: "soon" as const,
    tagline: "Your health, fully protected.",
    description:
      "Individual and family health plans covering in-patient, out-patient, diagnostics, and specialist consultations at partner hospitals across Bangladesh.",
    features: [
      "In-patient & out-patient coverage",
      "Diagnostic & specialist visits",
      "Cashless claims at partner hospitals",
      "Individual & family floater plans",
    ],
  },
  {
    id: "home",
    label: "Home Insurance",
    status: "soon" as const,
    tagline: "Protect what matters most.",
    description:
      "Building and contents insurance for homeowners and renters in Bangladesh. Covers fire, flood, theft, and structural damage.",
    features: [
      "Building & contents cover",
      "Fire, flood, and theft protection",
      "Available for owners and renters",
      "Instant digital policy",
    ],
  },
  {
    id: "life",
    label: "Term Life",
    status: "soon" as const,
    tagline: "Security for every stage of life.",
    description:
      "Pure term life insurance with no investment component. Affordable premiums, high coverage, and fast claim settlement for your family.",
    features: [
      "Pure term, no hidden investment fees",
      "Coverage up to ৳2 crore",
      "Fast claim settlement",
      "Flexible policy tenures",
    ],
  },
  {
    id: "sme",
    label: "SME Business",
    status: "soon" as const,
    tagline: "Business risk, managed digitally.",
    description:
      "All-in-one business insurance for small and medium enterprises — covering property, liability, employee health, and goods in transit.",
    features: [
      "Commercial property protection",
      "Public & product liability",
      "Group employee health cover",
      "Goods-in-transit cover",
    ],
  },
];

const FAQS = [
  {
    q: "Is a digital insurance policy legally valid in Bangladesh?",
    a: "Yes. Under IDRA regulations and the Digital Bangladesh initiative, digitally-issued policies carry identical legal weight to paper documents. Your PDF is fully admissible in court and accepted by relevant authorities.",
  },
  {
    q: "What does 'Coming Soon' mean for other products?",
    a: "Guardian Stack is launching products in phases. Motor Insurance is live now. Overseas Medical, Health, Home, Term Life, and SME Business are in regulatory filing and technical development. Register your interest to be notified at launch.",
  },
  {
    q: "Can I manage all my policies in one place?",
    a: "Yes. The Guardian Stack dashboard and mobile app will consolidate all your active policies, renewal dates, claim history, and documents — regardless of which product they belong to.",
  },
  {
    q: "How do claims work?",
    a: "For Motor Insurance, file a claim in-app with photographs. A licensed surveyor contacts you within two business hours. Other products will follow product-specific processes, all managed digitally through the app.",
  },
  {
    q: "How is my personal data protected?",
    a: "Your NID number and personal data are encrypted with AES-256 at rest and in transit. We operate under ISO 27001 standards and never sell or share your information with third parties.",
  },
];

// ─── Component ────────────────────────────────────────────────────────────────

export default function GuardianStackPage() {
  const [activeProduct, setActiveProduct] = useState("motor");
  const [form, setForm] = useState<QuoteForm>({ regNumber: "", carValue: "", engineCC: "" });
  const [quoteGenerated, setQuoteGenerated] = useState(false);
  const [quoteAmount, setQuoteAmount] = useState("");
  const [exitPopup, setExitPopup] = useState(false);
  const [emailInput, setEmailInput] = useState("");
  const [emailSent, setEmailSent] = useState(false);
  const [notifyEmail, setNotifyEmail] = useState("");
  const [notifySent, setNotifySent] = useState<string | null>(null);
  const [openFaq, setOpenFaq] = useState<number | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const exitTriggered = useRef(false);

  const product = PRODUCTS.find((p) => p.id === activeProduct)!;

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 24);
    window.addEventListener("scroll", onScroll);
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    const handleMouseLeave = (e: MouseEvent) => {
      if (e.clientY <= 0 && quoteGenerated && !exitTriggered.current) {
        exitTriggered.current = true;
        setExitPopup(true);
      }
    };
    document.addEventListener("mouseleave", handleMouseLeave);
    return () => document.removeEventListener("mouseleave", handleMouseLeave);
  }, [quoteGenerated]);

  const handleGetQuote = () => {
    if (!form.regNumber || !form.carValue || !form.engineCC) return;
    setIsLoading(true);
    setTimeout(() => {
      const base = parseFloat(form.carValue.replace(/,/g, "")) || 500000;
      const cc = parseInt(form.engineCC) || 1500;
      const rate = cc <= 1000 ? 0.018 : cc <= 1500 ? 0.022 : cc <= 2000 ? 0.026 : 0.032;
      setQuoteAmount(new Intl.NumberFormat("en-BD").format(Math.round(base * rate)));
      setQuoteGenerated(true);
      setIsLoading(false);
      setTimeout(() => document.getElementById("quote-result")?.scrollIntoView({ behavior: "smooth", block: "nearest" }), 80);
    }, 1400);
  };

  const handleNotify = (productId: string) => {
    if (notifyEmail) {
      setNotifySent(productId);
    }
  };

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:ital,wght@0,300;0,400;0,500;0,600;0,700;0,800;1,400&family=Sora:wght@400;500;600;700;800&display=swap');

        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        :root {
          --orange:        #E85C0D;
          --orange-hover:  #C94D0A;
          --orange-soft:   #FEF0E8;
          --orange-border: #F9D0B4;

          --bg:     #FAFAF9;
          --bg-2:   #F3F2EF;
          --bg-3:   #ECEAE5;
          --card:   #FFFFFF;

          --t1: #111110;
          --t2: #38352F;
          --t3: #6A665E;
          --t4: #A09A90;

          --line:   #E4E1DB;
          --line-2: #CCC9C2;

          --green:    #1B7A45;
          --green-bg: #EBF6F1;

          --fh: 'Sora', system-ui, sans-serif;
          --fb: 'Plus Jakarta Sans', system-ui, sans-serif;
          --r:  10px;
          --r2: 6px;
        }

        .dark {
          --orange:        #FF7432;
          --orange-hover:  #E85C0D;
          --orange-soft:   #2B1608;
          --orange-border: #4A2510;

          --bg:   #0D0C0A;
          --bg-2: #151410;
          --bg-3: #1C1A16;
          --card: #191714;

          --t1: #F0EDE8;
          --t2: #C2BDB5;
          --t3: #857F77;
          --t4: #524E48;

          --line:   #27241E;
          --line-2: #35312A;

          --green:    #3DBA72;
          --green-bg: #0D2119;
        }

        html { scroll-behavior: smooth; }
        body {
          font-family: var(--fb);
          background: var(--bg);
          color: var(--t1);
          -webkit-font-smoothing: antialiased;
          overflow-x: hidden;
          transition: background .25s, color .25s;
        }
        ::selection { background: var(--orange); color: #fff; }
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-track { background: var(--bg-2); }
        ::-webkit-scrollbar-thumb { background: var(--line-2); border-radius: 99px; }

        /* ── Nav ───────────────────────────────────────────────────────── */
        .nav {
          position: fixed; top: 0; left: 0; right: 0; z-index: 100;
          height: 60px; display: flex; align-items: center; justify-content: space-between;
          padding: 0 40px;
          background: var(--bg);
          border-bottom: 1px solid transparent;
          transition: border-color .3s, background .25s;
        }
        .nav.stuck { border-color: var(--line); }

        .logo { display: flex; align-items: center; gap: 9px; text-decoration: none; }
        .logo-mark {
          width: 30px; height: 30px; background: var(--orange); border-radius: 8px;
          display: flex; align-items: center; justify-content: center; flex-shrink: 0;
        }
        .logo-mark svg { width: 15px; height: 15px; fill: #fff; }
        .logo-name { font-family: var(--fh); font-size: 15px; font-weight: 700; letter-spacing: -.02em; color: var(--t1); }

        .nav-links { display: flex; align-items: center; gap: 28px; }
        .nav-a { font-size: 13.5px; font-weight: 500; color: var(--t3); text-decoration: none; transition: color .2s; letter-spacing: -.005em; }
        .nav-a:hover { color: var(--t1); }

        .btn-nav {
          height: 36px; padding: 0 18px;
          background: var(--orange); color: #fff;
          font-family: var(--fb); font-size: 13px; font-weight: 600;
          border: none; border-radius: var(--r2); cursor: pointer;
          transition: background .2s, transform .15s; letter-spacing: -.01em;
        }
        .btn-nav:hover { background: var(--orange-hover); transform: translateY(-1px); }

        /* ── Wrap ──────────────────────────────────────────────────────── */
        .wrap { max-width: 1120px; margin: 0 auto; padding: 0 40px; }

        /* ── Tags & type ───────────────────────────────────────────────── */
        .tag {
          display: inline-flex; align-items: center; gap: 7px;
          font-size: 11px; font-weight: 700; letter-spacing: .1em; text-transform: uppercase;
          color: var(--orange); margin-bottom: 18px;
        }
        .tag-dot { width: 5px; height: 5px; border-radius: 50%; background: var(--orange); flex-shrink: 0; }

        .display {
          font-family: var(--fh);
          font-size: clamp(36px, 5vw, 68px);
          font-weight: 800; line-height: 1.06; letter-spacing: -.035em; color: var(--t1);
        }
        .display em { font-style: normal; color: var(--orange); }

        .h2 {
          font-family: var(--fh);
          font-size: clamp(26px, 3.2vw, 44px);
          font-weight: 700; line-height: 1.12; letter-spacing: -.03em; color: var(--t1);
        }
        .h2 em { font-style: normal; color: var(--orange); }

        .h3 { font-family: var(--fh); font-size: 18px; font-weight: 700; letter-spacing: -.02em; color: var(--t1); }

        .body-lg { font-size: 16px; line-height: 1.75; color: var(--t3); }
        .body-md { font-size: 14.5px; line-height: 1.75; color: var(--t3); }
        .body-sm { font-size: 13px; line-height: 1.72; color: var(--t3); }

        /* ── Buttons ───────────────────────────────────────────────────── */
        .btn-primary {
          display: inline-flex; align-items: center; justify-content: center; gap: 8px;
          height: 46px; padding: 0 22px; width: 100%;
          background: var(--orange); color: #fff;
          font-family: var(--fb); font-size: 14px; font-weight: 600;
          border: none; border-radius: var(--r); cursor: pointer;
          transition: background .2s, transform .15s, box-shadow .2s; letter-spacing: -.01em;
        }
        .btn-primary:hover { background: var(--orange-hover); transform: translateY(-1px); box-shadow: 0 6px 20px rgba(232,92,13,.28); }
        .btn-primary:disabled { opacity: .4; cursor: not-allowed; transform: none; box-shadow: none; }

        .btn-outline {
          display: inline-flex; align-items: center; justify-content: center; gap: 7px;
          height: 40px; padding: 0 18px;
          background: transparent; color: var(--orange);
          font-family: var(--fb); font-size: 13px; font-weight: 600;
          border: 1.5px solid var(--orange); border-radius: var(--r2); cursor: pointer;
          transition: background .2s, transform .15s; letter-spacing: -.01em; white-space: nowrap;
        }
        .btn-outline:hover { background: var(--orange-soft); transform: translateY(-1px); }

        .btn-ghost {
          display: inline-flex; align-items: center; justify-content: center;
          height: 46px; padding: 0 22px; width: 100%;
          background: transparent; color: var(--t2);
          font-family: var(--fb); font-size: 14px; font-weight: 500;
          border: 1.5px solid var(--line-2); border-radius: var(--r); cursor: pointer;
          transition: border-color .2s, color .2s; letter-spacing: -.01em;
        }
        .btn-ghost:hover { border-color: var(--t3); color: var(--t1); }

        /* ── Form ──────────────────────────────────────────────────────── */
        .field { display: flex; flex-direction: column; gap: 7px; }
        .field-label { font-size: 11.5px; font-weight: 700; color: var(--t3); letter-spacing: .06em; text-transform: uppercase; }
        .field-input {
          height: 44px; padding: 0 14px;
          background: var(--bg); border: 1.5px solid var(--line);
          border-radius: var(--r2); color: var(--t1);
          font-family: var(--fb); font-size: 14px; outline: none;
          transition: border-color .2s, background .2s; width: 100%;
          -webkit-appearance: none;
        }
        .field-input::placeholder { color: var(--t4); }
        .field-input:focus { border-color: var(--orange); background: var(--card); box-shadow: 0 0 0 3px color-mix(in srgb, var(--orange) 12%, transparent); }

        /* ── Widget ────────────────────────────────────────────────────── */
        .widget { background: var(--card); border: 1.5px solid var(--line); border-radius: 14px; overflow: hidden; }
        .widget-head {
          padding: 18px 26px; background: var(--orange);
          display: flex; align-items: center; justify-content: space-between;
        }
        .widget-body { padding: 26px; display: flex; flex-direction: column; gap: 16px; }
        .widget-soon { padding: 32px 26px; display: flex; flex-direction: column; align-items: flex-start; gap: 16px; }

        /* ── Product tabs ──────────────────────────────────────────────── */
        .prod-tabs {
          display: flex; gap: 0; overflow-x: auto; border-bottom: 1.5px solid var(--line);
          scrollbar-width: none; -ms-overflow-style: none;
        }
        .prod-tabs::-webkit-scrollbar { display: none; }

        .prod-tab {
          flex-shrink: 0; padding: 14px 20px;
          background: none; border: none; border-bottom: 2.5px solid transparent;
          margin-bottom: -1.5px;
          font-family: var(--fb); font-size: 13.5px; font-weight: 500;
          color: var(--t3); cursor: pointer;
          transition: color .2s, border-color .2s; letter-spacing: -.01em;
          display: flex; align-items: center; gap: 8px;
          white-space: nowrap;
        }
        .prod-tab:hover { color: var(--t1); }
        .prod-tab.active { color: var(--orange); border-bottom-color: var(--orange); font-weight: 600; }

        .soon-pill {
          font-size: 9.5px; font-weight: 700; letter-spacing: .07em; text-transform: uppercase;
          padding: 2px 6px; border-radius: 4px;
          background: var(--bg-3); color: var(--t4);
        }
        .live-pill {
          font-size: 9.5px; font-weight: 700; letter-spacing: .07em; text-transform: uppercase;
          padding: 2px 6px; border-radius: 4px;
          background: var(--green-bg); color: var(--green);
        }

        /* ── Product grid (catalogue) ──────────────────────────────────── */
        .prod-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; }

        .prod-card {
          padding: 28px; border-radius: var(--r);
          border: 1.5px solid var(--line);
          background: var(--card);
          display: flex; flex-direction: column; gap: 0;
          transition: border-color .2s, box-shadow .2s, transform .2s;
          position: relative; overflow: hidden;
        }
        .prod-card:hover { border-color: var(--orange-border); box-shadow: 0 8px 28px rgba(232,92,13,.09); transform: translateY(-2px); }
        .prod-card.live-card { border-color: var(--orange-border); }

        .prod-card-icon {
          width: 44px; height: 44px; border-radius: var(--r2);
          background: var(--orange-soft); border: 1px solid var(--orange-border);
          display: flex; align-items: center; justify-content: center;
          margin-bottom: 16px; flex-shrink: 0;
        }
        .prod-card-icon svg { width: 20px; height: 20px; }

        /* ── Stat ──────────────────────────────────────────────────────── */
        .stat-val { font-family: var(--fh); font-size: 40px; font-weight: 800; color: var(--t1); letter-spacing: -.04em; line-height: 1; }
        .stat-lbl { font-size: 11.5px; font-weight: 600; color: var(--t4); letter-spacing: .06em; text-transform: uppercase; margin-top: 5px; }

        /* ── Trust badge ───────────────────────────────────────────────── */
        .badge {
          display: inline-flex; align-items: center; gap: 7px;
          padding: 7px 13px; background: var(--bg-2); border: 1px solid var(--line);
          border-radius: 99px; font-size: 12.5px; font-weight: 500; color: var(--t2); white-space: nowrap;
        }
        .badge-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--green); flex-shrink: 0; }

        /* ── Pay pill ──────────────────────────────────────────────────── */
        .pay-pill { padding: 5px 11px; background: var(--bg-2); border: 1px solid var(--line); border-radius: var(--r2); font-size: 12px; font-weight: 600; color: var(--t2); letter-spacing: .01em; }

        /* ── HR ────────────────────────────────────────────────────────── */
        .hr { width: 100%; height: 1px; background: var(--line); }

        /* ── Comparison table ──────────────────────────────────────────── */
        .ctable { width: 100%; border-collapse: collapse; }
        .ctable thead th { text-align: left; padding-bottom: 14px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .08em; color: var(--t4); border-bottom: 1.5px solid var(--line); }
        .ctable tbody td { padding: 15px 0; border-bottom: 1px solid var(--line); font-size: 14px; line-height: 1.5; vertical-align: top; }
        .ctable tbody tr:last-child td { border-bottom: none; }
        .col-f { color: var(--t3); font-size: 13px; width: 28%; padding-right: 20px; padding-top: 17px; }
        .col-g { color: var(--t1); font-weight: 600; padding-right: 20px; }
        .col-t { color: var(--t4); }
        .g-dot { display: inline-flex; align-items: center; gap: 8px; }
        .g-dot::before { content: ''; width: 6px; height: 6px; border-radius: 50%; background: var(--green); display: inline-block; flex-shrink: 0; }

        /* ── FAQ ───────────────────────────────────────────────────────── */
        .faq-item { border-bottom: 1px solid var(--line); }
        .faq-item:first-child { border-top: 1px solid var(--line); }
        .faq-btn {
          width: 100%; display: flex; align-items: center; justify-content: space-between; gap: 24px;
          padding: 22px 0; background: none; border: none; text-align: left;
          font-family: var(--fb); font-size: 15px; font-weight: 500; color: var(--t1);
          cursor: pointer; transition: color .2s; letter-spacing: -.01em;
        }
        .faq-btn:hover { color: var(--orange); }
        .faq-icon {
          width: 28px; height: 28px; border-radius: 50%;
          background: var(--bg-2); border: 1px solid var(--line);
          display: flex; align-items: center; justify-content: center;
          flex-shrink: 0; font-size: 17px; font-weight: 300; color: var(--t3);
          transition: transform .3s, background .2s; line-height: 1;
        }
        .faq-icon.open { transform: rotate(45deg); background: var(--orange-soft); border-color: var(--orange-border); color: var(--orange); }
        .faq-body { padding-bottom: 22px; font-size: 14.5px; line-height: 1.78; color: var(--t3); max-width: 640px; }

        /* ── Quote result ──────────────────────────────────────────────── */
        .q-result { margin-top: 4px; padding: 22px; background: var(--orange-soft); border: 1.5px solid var(--orange-border); border-radius: var(--r); animation: slideDown .35s ease both; }

        /* ── Popup ─────────────────────────────────────────────────────── */
        .overlay { position: fixed; inset: 0; z-index: 999; background: rgba(0,0,0,.55); backdrop-filter: blur(6px); display: flex; align-items: center; justify-content: center; padding: 20px; animation: fadeIn .25s ease both; }
        .popup { background: var(--card); border: 1.5px solid var(--line); border-radius: 16px; padding: 44px 40px; max-width: 448px; width: 100%; position: relative; animation: popUp .35s cubic-bezier(.34,1.3,.64,1) both; }

        /* ── Animations ────────────────────────────────────────────────── */
        @keyframes rotate { to { transform: rotate(360deg); } }
        .spinner { width: 15px; height: 15px; border: 2px solid rgba(255,255,255,.3); border-top-color: #fff; border-radius: 50%; animation: rotate .7s linear infinite; display: inline-block; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        @keyframes slideDown { from { opacity: 0; transform: translateY(-8px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes popUp { from { opacity: 0; transform: translateY(20px) scale(.97); } to { opacity: 1; transform: translateY(0) scale(1); } }
        @keyframes fadeUp { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .fade-up { animation: fadeUp .35s ease both; }

        /* ── Responsive ────────────────────────────────────────────────── */
        @media (max-width: 960px) {
          .nav { padding: 0 20px; }
          .nav-links { display: none; }
          .wrap { padding: 0 20px; }
          .hero-grid { grid-template-columns: 1fr !important; }
          .two-col { grid-template-columns: 1fr !important; gap: 40px !important; }
          .prod-grid { grid-template-columns: 1fr 1fr !important; }
          .popup { padding: 32px 24px; }
          .stats-row { grid-template-columns: repeat(2,1fr) !important; }
        }
        @media (max-width: 600px) {
          .prod-grid { grid-template-columns: 1fr !important; }
          .prod-tab { padding: 12px 14px; font-size: 13px; }
        }
      `}</style>

      {/* ── Navbar ──────────────────────────────────────────────────────────── */}
      <nav className={`nav${scrolled ? " stuck" : ""}`}>
        <a href="#" className="logo">
          <div className="logo-mark">
            <svg viewBox="0 0 15 15"><path d="M7.5 1L2 3.5V8c0 3.3 2.4 5.8 5.5 6.5C10.6 13.8 13 11.3 13 8V3.5L7.5 1z"/></svg>
          </div>
          <span className="logo-name">Guardian Stack</span>
        </a>
        <div className="nav-links">
          {[["Products","#products"],["How it works","#how-it-works"],["Security","#security"],["FAQ","#faq"]].map(([l,h])=>(
            <a key={l} href={h} className="nav-a">{l}</a>
          ))}
        </div>
        <div style={{display:"flex",alignItems:"center",gap:10}}>
          <ThemeToggle />
          <button className="btn-nav" onClick={()=>document.getElementById("hero-quote")?.scrollIntoView({behavior:"smooth"})}>
            Get a quote
          </button>
        </div>
      </nav>

      {/* ── Hero ────────────────────────────────────────────────────────────── */}
      <section style={{paddingTop:88,background:"var(--bg)"}}>
        <div className="wrap" style={{paddingTop:56,paddingBottom:0}}>

          <div className="tag"><span className="tag-dot"/>IDRA Licensed · Bangladesh</div>

          <div className="hero-grid" style={{display:"grid",gridTemplateColumns:"1fr 416px",gap:64,alignItems:"start"}}>

            {/* Left */}
            <div>
              <h1 className="display" style={{marginBottom:22}}>
                Insurance for every<br/>part of your life,<br/><em>issued instantly.</em>
              </h1>
              <p className="body-lg" style={{maxWidth:480,marginBottom:40}}>
                Guardian Stack is Bangladesh's regulated digital insurance platform — covering motor vehicles, overseas travel, health, home, life, and business. Apply in minutes, get your policy PDF in seconds.
              </p>

              {/* Stats */}
              <div className="stats-row" style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:0,borderTop:"1.5px solid var(--line)",paddingTop:32,marginBottom:40}}>
                {[{val:"2 min",label:"Policy issued"},{val:"24/7",label:"Always on"},{val:"100%",label:"Paperless"}].map((s,i)=>(
                  <div key={s.label} style={{paddingRight:i<2?32:0,borderRight:i<2?"1px solid var(--line)":"none",paddingLeft:i>0?32:0}}>
                    <div className="stat-val">{s.val}</div>
                    <div className="stat-lbl">{s.label}</div>
                  </div>
                ))}
              </div>

              {/* Badges */}
              <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
                <span className="badge"><span className="badge-dot"/>IDRA Regulated</span>
                <span className="badge"><span className="badge-dot"/>SSLCommerz Secured</span>
                <span className="badge"><span className="badge-dot"/>ISO 27001 Certified</span>
              </div>
            </div>

            {/* Right — tabbed widget */}
            <div id="hero-quote" style={{position:"sticky",top:76}}>
              {/* Product tabs */}
              <div className="prod-tabs" style={{background:"var(--card)",border:"1.5px solid var(--line)",borderBottom:"none",borderRadius:"14px 14px 0 0",overflow:"hidden"}}>
                {PRODUCTS.map(p=>(
                  <button key={p.id} className={`prod-tab${activeProduct===p.id?" active":""}`} onClick={()=>{setActiveProduct(p.id);setQuoteGenerated(false);}}>
                    {p.label}
                    {p.status==="live" ? <span className="live-pill">Live</span> : <span className="soon-pill">Soon</span>}
                  </button>
                ))}
              </div>

              {/* Widget body */}
              <div className="widget" style={{borderRadius:"0 0 14px 14px",borderTop:"none"}}>
                {product.status === "live" ? (
                  <>
                    <div className="widget-head">
                      <div>
                        <div style={{fontSize:15,fontWeight:700,color:"#fff",letterSpacing:"-.02em",fontFamily:"var(--fh)"}}>Motor Insurance Quote</div>
                        <div style={{fontSize:12,color:"rgba(255,255,255,.72)",marginTop:2}}>No sign-up · Takes 30 seconds</div>
                      </div>
                      <span style={{fontSize:11,fontWeight:700,color:"rgba(255,255,255,.6)",letterSpacing:".06em",textTransform:"uppercase"}}>Free</span>
                    </div>
                    <div className="widget-body">
                      <div className="field">
                        <label className="field-label">Registration number</label>
                        <input className="field-input" placeholder="e.g. Dhaka Metro-GA 11-2345" value={form.regNumber} onChange={e=>setForm({...form,regNumber:e.target.value})}/>
                      </div>
                      <div className="field">
                        <label className="field-label">Vehicle value — sum insured (BDT)</label>
                        <input className="field-input" placeholder="e.g. 1,500,000" value={form.carValue} onChange={e=>setForm({...form,carValue:e.target.value})}/>
                      </div>
                      <div className="field">
                        <label className="field-label">Engine displacement (CC)</label>
                        <input className="field-input" type="number" placeholder="e.g. 1500" value={form.engineCC} onChange={e=>setForm({...form,engineCC:e.target.value})}/>
                      </div>
                      <button className="btn-primary" onClick={handleGetQuote} disabled={isLoading||!form.regNumber||!form.carValue||!form.engineCC}>
                        {isLoading?<><div className="spinner"/>Calculating…</>:"Calculate my premium"}
                      </button>

                      {quoteGenerated && (
                        <div id="quote-result" className="q-result">
                          <div style={{fontSize:11,fontWeight:700,letterSpacing:".08em",textTransform:"uppercase",color:"var(--orange)",marginBottom:6}}>Estimated annual premium</div>
                          <div style={{fontFamily:"var(--fh)",fontSize:38,fontWeight:800,color:"var(--t1)",letterSpacing:"-.04em",lineHeight:1,marginBottom:4}}>৳{quoteAmount}</div>
                          <div style={{fontSize:12,color:"var(--t3)",marginBottom:18}}>Comprehensive motor insurance · IDRA approved</div>
                          <button className="btn-primary">Proceed to secure payment</button>
                          <div style={{textAlign:"center",marginTop:10,fontSize:11.5,color:"var(--t4)"}}>Encrypted by SSLCommerz · AES-256</div>
                        </div>
                      )}

                      <div style={{display:"flex",gap:6,flexWrap:"wrap",paddingTop:4,borderTop:"1px solid var(--line)"}}>
                        {["bKash","Nagad","Visa","Mastercard"].map(p=><span key={p} className="pay-pill">{p}</span>)}
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="widget-soon">
                    <div style={{display:"inline-flex",alignItems:"center",gap:8,padding:"6px 12px",background:"var(--bg-2)",border:"1px solid var(--line)",borderRadius:99,fontSize:12,fontWeight:600,color:"var(--t3)"}}>
                      Launching soon
                    </div>
                    <h3 className="h3" style={{fontSize:20}}>{product.tagline}</h3>
                    <p className="body-sm" style={{maxWidth:320}}>{product.description}</p>
                    <div style={{display:"flex",flexDirection:"column",gap:9,width:"100%"}}>
                      {product.features.map(f=>(
                        <div key={f} style={{display:"flex",alignItems:"center",gap:10,fontSize:13.5,color:"var(--t2)"}}>
                          <span style={{width:6,height:6,borderRadius:"50%",background:"var(--orange)",display:"inline-block",flexShrink:0}}/>
                          {f}
                        </div>
                      ))}
                    </div>
                    <div style={{width:"100%",paddingTop:8}}>
                      {notifySent===product.id ? (
                        <div style={{padding:"14px 18px",background:"var(--green-bg)",border:"1.5px solid var(--green)",borderRadius:"10px"}} className="fade-up">
                          <div style={{fontSize:13.5,fontWeight:600,color:"var(--green)"}}>You're on the list.</div>
                          <div style={{fontSize:12.5,color:"var(--t3)",marginTop:3}}>We'll notify you when {product.label} launches.</div>
                        </div>
                      ) : (
                        <div style={{display:"flex",flexDirection:"column",gap:10}}>
                          <div className="field">
                            <label className="field-label">Notify me at launch</label>
                            <input type="email" className="field-input" placeholder="your@email.com" value={notifyEmail} onChange={e=>setNotifyEmail(e.target.value)} onKeyDown={e=>e.key==="Enter"&&handleNotify(product.id)}/>
                          </div>
                          <button className="btn-primary" onClick={()=>handleNotify(product.id)} disabled={!notifyEmail}>
                            Notify me at launch
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* spacer */}
      <div style={{height:72}}/>
      <div className="hr"/>

      {/* ── Product catalogue ────────────────────────────────────────────────── */}
      <section id="products" style={{paddingTop:88,paddingBottom:88,background:"var(--bg-2)"}}>
        <div className="wrap">
          <div className="tag"><span className="tag-dot"/>Our Products</div>
          <div className="two-col" style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:64,alignItems:"end",marginBottom:48}}>
            <h2 className="h2">
              One platform.<br/><em>Every insurance need.</em>
            </h2>
            <p className="body-md" style={{maxWidth:380}}>
              Guardian Stack is building Bangladesh's most complete digital insurance suite — regulated, transparent, and entirely paperless. Motor Insurance is live today. More products follow shortly.
            </p>
          </div>

          <div className="prod-grid">
            {PRODUCTS.map(p=>(
              <div key={p.id} className={`prod-card${p.status==="live"?" live-card":""}`}>
                {/* Status pill */}
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:20}}>
                  <div className="prod-card-icon">
                    {p.id==="motor"    && <svg viewBox="0 0 24 24" fill="none" stroke="var(--orange)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M5 17H3a2 2 0 01-2-2v-4l3-3h11l3 3v4a2 2 0 01-2 2h-2"/><circle cx="7.5" cy="17.5" r="2.5"/><circle cx="17.5" cy="17.5" r="2.5"/></svg>}
                    {p.id==="overseas" && <svg viewBox="0 0 24 24" fill="none" stroke="var(--orange)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>}
                    {p.id==="health"   && <svg viewBox="0 0 24 24" fill="none" stroke="var(--orange)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M20.84 4.61a5.5 5.5 0 00-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 00-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 000-7.78z"/></svg>}
                    {p.id==="home"     && <svg viewBox="0 0 24 24" fill="none" stroke="var(--orange)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M3 9.5L12 3l9 6.5V20a1 1 0 01-1 1H4a1 1 0 01-1-1V9.5z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>}
                    {p.id==="life"     && <svg viewBox="0 0 24 24" fill="none" stroke="var(--orange)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>}
                    {p.id==="sme"      && <svg viewBox="0 0 24 24" fill="none" stroke="var(--orange)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 7V5a2 2 0 00-2-2h-4a2 2 0 00-2 2v2"/><line x1="12" y1="12" x2="12" y2="16"/><line x1="10" y1="14" x2="14" y2="14"/></svg>}
                  </div>
                  {p.status==="live"
                    ? <span className="live-pill">Live</span>
                    : <span className="soon-pill">Coming soon</span>}
                </div>

                <div className="h3" style={{marginBottom:8,fontSize:16}}>{p.label}</div>
                <p className="body-sm" style={{marginBottom:20,flex:1}}>{p.description}</p>

                <div style={{display:"flex",flexDirection:"column",gap:8,marginBottom:22}}>
                  {p.features.map(f=>(
                    <div key={f} style={{display:"flex",alignItems:"flex-start",gap:9,fontSize:12.5,color:"var(--t2)"}}>
                      <span style={{width:5,height:5,borderRadius:"50%",background:"var(--green)",flexShrink:0,marginTop:5,display:"inline-block"}}/>
                      {f}
                    </div>
                  ))}
                </div>

                {p.status==="live"
                  ? <button className="btn-outline" style={{width:"100%",justifyContent:"center"}} onClick={()=>{setActiveProduct("motor");document.getElementById("hero-quote")?.scrollIntoView({behavior:"smooth"})}}>
                      Get a quote →
                    </button>
                  : <button className="btn-outline" style={{width:"100%",justifyContent:"center"}} onClick={()=>{setActiveProduct(p.id);document.getElementById("hero-quote")?.scrollIntoView({behavior:"smooth"})}}>
                      Notify me at launch
                    </button>
                }
              </div>
            ))}
          </div>
        </div>
      </section>

      <div className="hr"/>

      {/* ── How it works ─────────────────────────────────────────────────────── */}
      <section id="how-it-works" style={{paddingTop:88,paddingBottom:88,background:"var(--bg)"}}>
        <div className="wrap">
          <div className="tag"><span className="tag-dot"/>Process</div>
          <div className="two-col" style={{display:"grid",gridTemplateColumns:"320px 1fr",gap:72,alignItems:"start"}}>
            <div>
              <h2 className="h2" style={{marginBottom:18}}>Three steps.<br/><em>Two minutes.</em></h2>
              <p className="body-md" style={{maxWidth:280}}>
                We stripped every unnecessary step from the traditional insurance process. Details, payment, policy. Nothing more.
              </p>
            </div>
            <div style={{display:"flex",flexDirection:"column"}}>
              {[
                {n:"01",title:"Enter your details",body:"Provide the information relevant to your chosen product — vehicle details for motor, travel dates for overseas medical, and so on. Sourced from your existing documents."},
                {n:"02",title:"Pay via your preferred method",body:"Complete payment using bKash, Nagad, or any bank card. Transactions are processed through SSLCommerz with PCI DSS Level 1 certification."},
                {n:"03",title:"Receive your policy PDF",body:"Your IDRA-compliant digital policy arrives in your email immediately after payment — with full legal validity across Bangladesh."},
              ].map((step,i)=>(
                <div key={i} style={{display:"flex",gap:20,padding:"28px 0",borderTop:i===0?"1px solid var(--line)":"none",borderBottom:"1px solid var(--line)"}}>
                  <div style={{width:36,height:36,borderRadius:"50%",background:"var(--orange-soft)",border:"1.5px solid var(--orange-border)",color:"var(--orange)",fontFamily:"var(--fh)",fontSize:13,fontWeight:800,display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0}}>
                    {step.n}
                  </div>
                  <div>
                    <div style={{fontSize:15,fontWeight:600,color:"var(--t1)",marginBottom:8,letterSpacing:"-.01em"}}>{step.title}</div>
                    <div className="body-sm">{step.body}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <div className="hr"/>

      {/* ── Motor comparison ─────────────────────────────────────────────────── */}
      <section style={{paddingTop:88,paddingBottom:88,background:"var(--bg-2)"}}>
        <div className="wrap">
          <div className="tag"><span className="tag-dot"/>Motor Insurance</div>
          <div className="two-col" style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:80,alignItems:"end",marginBottom:52}}>
            <h2 className="h2">Guardian Stack vs.<br/><em>the traditional agent.</em></h2>
            <p className="body-md" style={{maxWidth:360}}>The agent model was built on paper, office visits, and opacity. We replaced every step with software.</p>
          </div>
          <table className="ctable">
            <thead>
              <tr>
                <th>Feature</th>
                <th>Guardian Stack</th>
                <th>Traditional agent</th>
              </tr>
            </thead>
            <tbody>
              {[
                {f:"Policy issuance",  g:"Under 2 minutes",       t:"2–3 business days"},
                {f:"Documentation",    g:"Fully digital",          t:"Physical forms required"},
                {f:"Pricing",          g:"Fixed, transparent",     t:"Negotiable, agent fee added"},
                {f:"Availability",     g:"24 hours, 7 days",       t:"Office hours only"},
                {f:"Claim filing",     g:"In-app, same day",       t:"In-person, weeks-long"},
                {f:"Policy access",    g:"Cloud, always available",t:"Paper copy required"},
              ].map((row,i)=>(
                <tr key={i}>
                  <td className="col-f">{row.f}</td>
                  <td className="col-g"><span className="g-dot">{row.g}</span></td>
                  <td className="col-t">{row.t}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <div className="hr"/>

      {/* ── Security ─────────────────────────────────────────────────────────── */}
      <section id="security" style={{paddingTop:88,paddingBottom:88,background:"var(--bg)"}}>
        <div className="wrap">
          <div className="tag"><span className="tag-dot"/>Compliance & Security</div>
          <div className="two-col" style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:80,alignItems:"start"}}>
            <div>
              <h2 className="h2" style={{marginBottom:20}}>Built on<br/><em>regulatory trust.</em></h2>
              <p className="body-md" style={{marginBottom:40,maxWidth:400}}>
                Every product on Guardian Stack is governed by the Insurance Development and Regulatory Authority of Bangladesh. We are a licensed insurer — not a marketplace.
              </p>
              {[
                {title:"IDRA regulatory compliance", body:"All policies are filed with and approved by IDRA. Your policy is enforceable in any Bangladeshi court of law."},
                {title:"Payment security", body:"Payments handled exclusively through SSLCommerz — Bangladesh's PCI DSS Level 1 certified gateway. We never store card data."},
                {title:"Data privacy", body:"NID numbers, personal details, and policy data are AES-256 encrypted at rest and in transit. ISO 27001 audited."},
              ].map((item,i)=>(
                <div key={i} style={{padding:"24px 0",borderTop:"1px solid var(--line)",display:"flex",gap:16}}>
                  <div style={{width:3,flexShrink:0,borderRadius:4,background:"var(--orange)",margin:"3px 0"}}/>
                  <div>
                    <div style={{fontSize:14,fontWeight:600,color:"var(--t1)",marginBottom:7,letterSpacing:"-.01em"}}>{item.title}</div>
                    <div className="body-sm">{item.body}</div>
                  </div>
                </div>
              ))}
            </div>
            <div style={{display:"flex",flexDirection:"column",gap:16}}>
              <div style={{padding:28,border:"1.5px solid var(--line)",borderRadius:"10px",background:"var(--card)"}}>
                <div style={{fontSize:11,fontWeight:700,letterSpacing:".08em",textTransform:"uppercase",color:"var(--t4)",marginBottom:14}}>Regulator</div>
                <div style={{fontFamily:"var(--fh)",fontSize:19,fontWeight:700,color:"var(--t1)",marginBottom:10,letterSpacing:"-.02em",lineHeight:1.25}}>Insurance Development &amp;<br/>Regulatory Authority</div>
                <div className="body-sm">IDRA was established under the Insurance Act 2010. All Guardian Stack policies are IDRA-filed and legally valid nationwide.</div>
              </div>
              <div style={{padding:28,border:"1.5px solid var(--line)",borderRadius:"10px",background:"var(--card)"}}>
                <div style={{fontSize:11,fontWeight:700,letterSpacing:".08em",textTransform:"uppercase",color:"var(--t4)",marginBottom:14}}>Accepted payments</div>
                <div style={{display:"flex",gap:7,flexWrap:"wrap",marginBottom:14}}>
                  {["bKash","Nagad","Visa","Mastercard","Amex","Rocket"].map(p=><span key={p} className="pay-pill">{p}</span>)}
                </div>
                <div className="body-sm">Processed by SSLCommerz — PCI DSS Level 1 certified.</div>
              </div>
              <div style={{padding:"18px 20px",background:"var(--orange-soft)",border:"1.5px solid var(--orange-border)",borderRadius:"10px"}}>
                <div style={{fontSize:13.5,color:"var(--t2)",lineHeight:1.7}}>
                  <span style={{fontWeight:700,color:"var(--orange)"}}>Your data is yours.</span>{" "}Guardian Stack does not sell, share, or monetise your personal information. All data is encrypted and strictly access-controlled.
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <div className="hr"/>

      {/* ── FAQ ──────────────────────────────────────────────────────────────── */}
      <section id="faq" style={{paddingTop:88,paddingBottom:88,background:"var(--bg-2)"}}>
        <div className="wrap">
          <div style={{display:"grid",gridTemplateColumns:"280px 1fr",gap:80,alignItems:"start"}} className="two-col">
            <div style={{position:"sticky",top:80}}>
              <div className="tag"><span className="tag-dot"/>FAQ</div>
              <h2 className="h2" style={{marginBottom:14,fontSize:"clamp(24px,3vw,38px)"}}>Questions<br/>we hear often.</h2>
              <p className="body-sm" style={{marginBottom:20}}>Can't find your answer?</p>
              <a href="mailto:support@guardianstack.com.bd" style={{fontSize:13.5,fontWeight:600,color:"var(--orange)",textDecoration:"none",letterSpacing:"-.01em"}}>
                support@guardianstack.com.bd →
              </a>
            </div>
            <div>
              {FAQS.map((faq,i)=>(
                <div key={i} className="faq-item">
                  <button className="faq-btn" onClick={()=>setOpenFaq(openFaq===i?null:i)}>
                    <span>{faq.q}</span>
                    <span className={`faq-icon${openFaq===i?" open":""}`}>+</span>
                  </button>
                  {openFaq===i && <div className="faq-body fade-up">{faq.a}</div>}
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <div className="hr"/>

      {/* ── Final CTA ────────────────────────────────────────────────────────── */}
      <section style={{paddingTop:88,paddingBottom:88,background:"var(--orange)"}}>
        <div className="wrap">
          <div className="two-col" style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:80,alignItems:"center"}}>
            <div>
              <h2 style={{fontFamily:"var(--fh)",fontSize:"clamp(28px,3.8vw,50px)",fontWeight:800,lineHeight:1.08,letterSpacing:"-.035em",color:"#fff",marginBottom:14}}>
                Get your first policy in the next two minutes.
              </h2>
              <p style={{fontSize:15,lineHeight:1.72,color:"rgba(255,255,255,.68)"}}>
                Motor Insurance is live now. Overseas Medical, Health, Home, Life, and SME products are launching shortly. One account, every policy.
              </p>
            </div>
            <div style={{display:"flex",flexDirection:"column",gap:12}}>
              <button
                style={{height:52,padding:"0 28px",background:"#fff",color:"var(--orange)",fontFamily:"var(--fb)",fontSize:14,fontWeight:700,border:"none",borderRadius:"10px",cursor:"pointer",letterSpacing:"-.01em",transition:"opacity .2s, transform .15s"}}
                onClick={()=>document.getElementById("hero-quote")?.scrollIntoView({behavior:"smooth"})}
                onMouseOver={e=>{(e.currentTarget as HTMLElement).style.opacity=".88";(e.currentTarget as HTMLElement).style.transform="translateY(-1px)";}}
                onMouseOut={e=>{(e.currentTarget as HTMLElement).style.opacity="1";(e.currentTarget as HTMLElement).style.transform="translateY(0)";}}
              >
                Get a free quote now
              </button>
              <div style={{textAlign:"center",fontSize:12,color:"rgba(255,255,255,.5)"}}>
                No account required · Policy in under 2 minutes
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── Footer ───────────────────────────────────────────────────────────── */}
      <footer style={{background:"var(--bg)",borderTop:"1px solid var(--line)",paddingTop:52,paddingBottom:52}}>
        <div className="wrap">
          <div style={{display:"grid",gridTemplateColumns:"2fr 1fr 1fr 1fr",gap:48,marginBottom:48}} className="two-col">
            <div>
              <div style={{display:"flex",alignItems:"center",gap:9,marginBottom:14}}>
                <div className="logo-mark"><svg viewBox="0 0 15 15" fill="white"><path d="M7.5 1L2 3.5V8c0 3.3 2.4 5.8 5.5 6.5C10.6 13.8 13 11.3 13 8V3.5L7.5 1z"/></svg></div>
                <span className="logo-name">Guardian Stack</span>
              </div>
              <p style={{fontSize:13,lineHeight:1.75,color:"var(--t4)",maxWidth:220}}>
                Bangladesh's regulated digital insurance platform. Motor, health, travel, home, life, and business — all in one place.
              </p>
            </div>
            {[
              {title:"Products", links:["Motor Insurance","Overseas Medical","Health Insurance","Home Insurance","Term Life","SME Business"]},
              {title:"Company",  links:["About","Blog","Careers","Press"]},
              {title:"Legal",    links:["Privacy policy","Terms of service","IDRA filing","Cookie policy"]},
            ].map(col=>(
              <div key={col.title}>
                <div style={{fontSize:11,fontWeight:700,letterSpacing:".08em",textTransform:"uppercase",color:"var(--t4)",marginBottom:16}}>{col.title}</div>
                <div style={{display:"flex",flexDirection:"column",gap:11}}>
                  {col.links.map(link=>(
                    <a key={link} href="#" style={{fontSize:13.5,color:"var(--t3)",textDecoration:"none",transition:"color .2s",letterSpacing:"-.005em"}}
                      onMouseOver={e=>(e.currentTarget.style.color="var(--orange)")}
                      onMouseOut={e=>(e.currentTarget.style.color="var(--t3)")}
                    >{link}</a>
                  ))}
                </div>
              </div>
            ))}
          </div>
          <div style={{paddingTop:24,borderTop:"1px solid var(--line)",display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:12}}>
            <span style={{fontSize:12,color:"var(--t4)"}}>© 2025 Guardian Stack Ltd. IDRA License No. GS-2025-XXXX. All rights reserved.</span>
            <div style={{display:"flex",gap:8}}>
              <span className="badge"><span className="badge-dot"/>IDRA Regulated</span>
              <span className="badge"><span className="badge-dot"/>SSL Secured</span>
            </div>
          </div>
        </div>
      </footer>

      {/* ── Exit intent popup ────────────────────────────────────────────────── */}
      {exitPopup && (
        <div className="overlay" onClick={()=>setExitPopup(false)}>
          <div className="popup" onClick={e=>e.stopPropagation()}>
            <div style={{position:"absolute",top:0,left:0,right:0,height:4,background:"var(--orange)",borderRadius:"16px 16px 0 0"}}/>
            <button onClick={()=>setExitPopup(false)} style={{position:"absolute",top:16,right:20,background:"none",border:"none",fontSize:22,color:"var(--t4)",cursor:"pointer",lineHeight:1,padding:4}}>×</button>
            <div style={{marginBottom:28}}>
              <div className="tag" style={{marginBottom:14}}><span className="tag-dot"/>Before you leave</div>
              <h3 style={{fontFamily:"var(--fh)",fontSize:24,fontWeight:700,letterSpacing:"-.03em",lineHeight:1.2,color:"var(--t1)",marginBottom:12}}>Save your quote for later.</h3>
              <p className="body-md">We'll hold this price for 24 hours. Enter your email and we'll send you a link to resume exactly where you left off.</p>
            </div>
            {!emailSent ? (
              <div style={{display:"flex",flexDirection:"column",gap:10}}>
                <div className="field">
                  <label className="field-label">Your email address</label>
                  <input type="email" className="field-input" placeholder="name@example.com" value={emailInput} onChange={e=>setEmailInput(e.target.value)} onKeyDown={e=>e.key==="Enter"&&emailInput&&setEmailSent(true)}/>
                </div>
                <button className="btn-primary" onClick={()=>{if(emailInput)setEmailSent(true);}}>Send my quote link</button>
                <button className="btn-ghost" onClick={()=>setExitPopup(false)}>No thanks, I'll start over</button>
              </div>
            ) : (
              <div style={{padding:"28px 24px",background:"var(--green-bg)",border:"1.5px solid var(--green)",borderRadius:10,textAlign:"center"}} className="fade-up">
                <div style={{fontFamily:"var(--fh)",fontSize:19,fontWeight:700,color:"var(--t1)",marginBottom:8,letterSpacing:"-.02em"}}>Quote sent.</div>
                <div style={{fontSize:13.5,color:"var(--t3)"}}>Check your inbox at <strong style={{fontWeight:600,color:"var(--t1)"}}>{emailInput}</strong>. Valid for 24 hours.</div>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}