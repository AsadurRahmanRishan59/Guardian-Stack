"use client";

/**
 * app/(marketing)/page.tsx  — Guardian Stack landing page
 *
 * · Pure Tailwind utility classes — zero <style> injection
 * · All colours via tailwind.config.ts brand/surface/t1-t4 extensions
 *   which resolve to gs-tokens.css CSS variables
 * · Dark mode via the .dark class (next-themes)
 * · Fonts loaded via next/font or a global @import in globals.css
 *   (add to globals.css: @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=Sora:wght@400;500;600;700;800&display=swap');)
 */

import { useState, useEffect, useRef } from "react";
import { ThemeToggle } from "@/components/theme-toggle";

interface QuoteForm {
  regNumber: string;
  carValue:  string;
  engineCC:  string;
}

const PRODUCTS = [
  {
    id: "motor", label: "Motor Insurance", status: "live" as const,
    tagline: "Cover your vehicle in 2 minutes.",
    description: "Comprehensive and third-party motor insurance for private cars and motorcycles. IDRA-regulated, issued instantly, stored in the cloud.",
    features: ["Comprehensive & third-party options","Policy PDF issued under 2 minutes","Digital claim filing, surveyor in 2 hrs","Covers private cars & motorcycles"],
  },
  {
    id: "overseas", label: "Overseas Medical", status: "soon" as const,
    tagline: "Travel anywhere. Stay covered.",
    description: "International medical insurance for Bangladeshi travellers. Covers emergency hospitalisation, repatriation, trip cancellation, and more across 190+ countries.",
    features: ["Emergency hospitalisation worldwide","Medical evacuation & repatriation","Trip cancellation & delay cover","190+ countries · single & multi-trip"],
  },
  {
    id: "health", label: "Health Insurance", status: "soon" as const,
    tagline: "Your health, fully protected.",
    description: "Individual and family health plans covering in-patient, out-patient, diagnostics, and specialist consultations at partner hospitals across Bangladesh.",
    features: ["In-patient & out-patient coverage","Diagnostic & specialist visits","Cashless claims at partner hospitals","Individual & family floater plans"],
  },
  {
    id: "home", label: "Home Insurance", status: "soon" as const,
    tagline: "Protect what matters most.",
    description: "Building and contents insurance for homeowners and renters in Bangladesh. Covers fire, flood, theft, and structural damage.",
    features: ["Building & contents cover","Fire, flood, and theft protection","Available for owners and renters","Instant digital policy"],
  },
  {
    id: "life", label: "Term Life", status: "soon" as const,
    tagline: "Security for every stage of life.",
    description: "Pure term life insurance with no investment component. Affordable premiums, high coverage, and fast claim settlement for your family.",
    features: ["Pure term, no hidden investment fees","Coverage up to ৳2 crore","Fast claim settlement","Flexible policy tenures"],
  },
  {
    id: "sme", label: "SME Business", status: "soon" as const,
    tagline: "Business risk, managed digitally.",
    description: "All-in-one business insurance for small and medium enterprises — covering property, liability, employee health, and goods in transit.",
    features: ["Commercial property protection","Public & product liability","Group employee health cover","Goods-in-transit cover"],
  },
] as const;

type ProductId = typeof PRODUCTS[number]["id"];

const COMPARISON = [
  { f: "Policy issuance",  g: "Under 2 minutes",        t: "2–3 business days" },
  { f: "Documentation",    g: "Fully digital",           t: "Physical forms required" },
  { f: "Pricing",          g: "Fixed, transparent",      t: "Negotiable, agent fee added" },
  { f: "Availability",     g: "24 hours, 7 days",        t: "Office hours only" },
  { f: "Claim filing",     g: "In-app, same day",        t: "In-person, weeks-long" },
  { f: "Policy access",    g: "Cloud, always available", t: "Paper copy required" },
];

const FAQS = [
  { q: "Is a digital insurance policy legally valid in Bangladesh?",
    a: "Yes. Under IDRA regulations and the Digital Bangladesh initiative, digitally-issued policies carry identical legal weight to paper documents. Your PDF is fully admissible in court and accepted by relevant authorities." },
  { q: "What does 'Coming Soon' mean for other products?",
    a: "Guardian Stack is launching products in phases. Motor Insurance is live now. Overseas Medical, Health, Home, Term Life, and SME Business are in regulatory filing and technical development. Register your interest to be notified at launch." },
  { q: "Can I manage all my policies in one place?",
    a: "Yes. The Guardian Stack dashboard and mobile app will consolidate all your active policies, renewal dates, claim history, and documents — regardless of which product they belong to." },
  { q: "How do claims work?",
    a: "For Motor Insurance, file a claim in-app with photographs. A licensed surveyor contacts you within two business hours. Other products will follow product-specific processes, all managed digitally through the app." },
  { q: "How is my personal data protected?",
    a: "Your NID number and personal data are encrypted with AES-256 at rest and in transit. We operate under ISO 27001 standards and never sell or share your information with third parties." },
];

// ─── SVG icons for product cards ─────────────────────────────────────────────

function ProductIcon({ id }: { id: string }) {
  const cls = "w-5 h-5 stroke-brand";
  const props = { viewBox: "0 0 24 24", fill: "none", strokeWidth: 1.8, strokeLinecap: "round" as const, strokeLinejoin: "round" as const, className: cls };
  if (id === "motor")    return <svg {...props}><path d="M5 17H3a2 2 0 01-2-2v-4l3-3h11l3 3v4a2 2 0 01-2 2h-2"/><circle cx="7.5" cy="17.5" r="2.5"/><circle cx="17.5" cy="17.5" r="2.5"/></svg>;
  if (id === "overseas") return <svg {...props}><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>;
  if (id === "health")   return <svg {...props}><path d="M20.84 4.61a5.5 5.5 0 00-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 00-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 000-7.78z"/></svg>;
  if (id === "home")     return <svg {...props}><path d="M3 9.5L12 3l9 6.5V20a1 1 0 01-1 1H4a1 1 0 01-1-1V9.5z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>;
  if (id === "life")     return <svg {...props}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>;
  return <svg {...props}><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 7V5a2 2 0 00-2-2h-4a2 2 0 00-2 2v2"/><line x1="12" y1="12" x2="12" y2="16"/><line x1="10" y1="14" x2="14" y2="14"/></svg>;
}

// ─── Shield logo ──────────────────────────────────────────────────────────────

function ShieldLogo() {
  return (
    <svg viewBox="0 0 15 15" className="w-[15px] h-[15px] fill-white">
      <path d="M7.5 1L2 3.5V8c0 3.3 2.4 5.8 5.5 6.5C10.6 13.8 13 11.3 13 8V3.5L7.5 1z"/>
    </svg>
  );
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function GuardianStackPage() {
  const [activeProduct, setActiveProduct] = useState<ProductId>("motor");
  const [form,            setForm]           = useState<QuoteForm>({ regNumber: "", carValue: "", engineCC: "" });
  const [quoteGenerated,  setQuoteGenerated]  = useState(false);
  const [quoteAmount,     setQuoteAmount]     = useState("");
  const [exitPopup,       setExitPopup]       = useState(false);
  const [emailInput,      setEmailInput]      = useState("");
  const [emailSent,       setEmailSent]       = useState(false);
  const [notifyEmail,     setNotifyEmail]     = useState("");
  const [notifySent,      setNotifySent]      = useState<string | null>(null);
  const [openFaq,         setOpenFaq]         = useState<number | null>(null);
  const [isLoading,       setIsLoading]       = useState(false);
  const [scrolled,        setScrolled]        = useState(false);
  const exitTriggered = useRef(false);

  const product = PRODUCTS.find((p) => p.id === activeProduct)!;

  useEffect(() => {
    const fn = () => setScrolled(window.scrollY > 24);
    window.addEventListener("scroll", fn);
    return () => window.removeEventListener("scroll", fn);
  }, []);

  useEffect(() => {
    const fn = (e: MouseEvent) => {
      if (e.clientY <= 0 && quoteGenerated && !exitTriggered.current) {
        exitTriggered.current = true;
        setExitPopup(true);
      }
    };
    document.addEventListener("mouseleave", fn);
    return () => document.removeEventListener("mouseleave", fn);
  }, [quoteGenerated]);

  const handleGetQuote = () => {
    if (!form.regNumber || !form.carValue || !form.engineCC) return;
    setIsLoading(true);
    setTimeout(() => {
      const base = parseFloat(form.carValue.replace(/,/g, "")) || 500000;
      const cc   = parseInt(form.engineCC) || 1500;
      const rate = cc <= 1000 ? 0.018 : cc <= 1500 ? 0.022 : cc <= 2000 ? 0.026 : 0.032;
      setQuoteAmount(new Intl.NumberFormat("en-BD").format(Math.round(base * rate)));
      setQuoteGenerated(true);
      setIsLoading(false);
      setTimeout(() => document.getElementById("quote-result")?.scrollIntoView({ behavior: "smooth", block: "nearest" }), 80);
    }, 1400);
  };

  // ── Shared class snippets ────────────────────────────────────────────────────
  const INPUT_CLS = "w-full h-11 px-3.5 rounded-gs-sm border border-gs-line bg-surface text-t1 text-sm font-body placeholder:text-t4 outline-none transition-all duration-200 focus:border-brand focus:ring-2 focus:ring-brand/10 focus:bg-surface-card";
  const LABEL_CLS = "block text-[11px] font-semibold uppercase tracking-[0.06em] text-t3 mb-1.5";

  return (
    <div className="min-h-screen bg-surface font-body text-t1 antialiased overflow-x-hidden">

      {/* ── Navbar ──────────────────────────────────────────────────────────── */}
      <nav className={`fixed top-0 left-0 right-0 z-50 h-[60px] flex items-center justify-between px-10 bg-surface transition-all duration-300 ${scrolled ? "border-b border-gs-line" : "border-b border-transparent"}`}>

        <a href="#" className="flex items-center gap-2.5 no-underline">
          <div className="w-[30px] h-[30px] bg-brand rounded-[8px] flex items-center justify-center shrink-0">
            <ShieldLogo />
          </div>
          <span className="font-head text-[15px] font-bold tracking-tight text-t1">Guardian Stack</span>
        </a>

        <div className="hidden md:flex items-center gap-7">
          {[["Products","#products"],["How it works","#how-it-works"],["Security","#security"],["FAQ","#faq"]].map(([l,h]) => (
            <a key={l} href={h} className="text-[13.5px] font-medium text-t3 hover:text-t1 transition-colors no-underline">{l}</a>
          ))}
        </div>

        <div className="flex items-center gap-2.5">
          <ThemeToggle />
          <button
            onClick={() => document.getElementById("hero-quote")?.scrollIntoView({ behavior: "smooth" })}
            className="h-9 px-[18px] bg-brand hover:bg-brand-hover text-white text-[13px] font-semibold rounded-gs-sm transition-all duration-200 hover:-translate-y-px border-none cursor-pointer"
          >
            Get a quote
          </button>
        </div>
      </nav>

      {/* ── Hero ────────────────────────────────────────────────────────────── */}
      <section className="pt-[88px] pb-0 bg-surface">
        <div className="max-w-[1120px] mx-auto px-10 pt-14">

          {/* Overline tag */}
          <div className="inline-flex items-center gap-2 mb-5">
            <span className="w-[5px] h-[5px] rounded-full bg-brand shrink-0" />
            <span className="text-[11px] font-bold tracking-[0.1em] uppercase text-brand">IDRA Licensed · Bangladesh</span>
          </div>

          {/* Hero grid */}
          <div className="grid grid-cols-1 lg:grid-cols-[1fr_416px] gap-16 items-start">

            {/* Left */}
            <div>
              <h1 className="font-head text-[clamp(36px,5vw,68px)] font-extrabold leading-[1.06] tracking-[-0.035em] text-t1 mb-5">
                Insurance for every<br/>part of your life,<br/>
                <span className="text-brand">issued instantly.</span>
              </h1>
              <p className="text-[16px] leading-[1.75] text-t3 max-w-[480px] mb-10">
                Guardian Stack is Bangladesh's regulated digital insurance platform — covering motor vehicles, overseas travel, health, home, life, and business. Apply in minutes, get your policy PDF in seconds.
              </p>

              {/* Stats row */}
              <div className="grid grid-cols-3 border-t border-gs-line pt-8 mb-10">
                {[
                  { val: "2 min",  label: "Policy issued" },
                  { val: "24/7",   label: "Always on" },
                  { val: "100%",   label: "Paperless" },
                ].map((s, i) => (
                  <div key={s.label} className={`${i > 0 ? "pl-8 border-l border-gs-line" : ""} ${i < 2 ? "pr-8" : ""}`}>
                    <div className="font-head text-[40px] font-extrabold tracking-[-0.04em] leading-none text-t1">{s.val}</div>
                    <div className="text-[11.5px] font-semibold tracking-[0.06em] uppercase text-t4 mt-1.5">{s.label}</div>
                  </div>
                ))}
              </div>

              {/* Trust badges */}
              <div className="flex flex-wrap gap-2.5">
                {["IDRA Regulated","SSLCommerz Secured","ISO 27001 Certified"].map(b => (
                  <span key={b} className="inline-flex items-center gap-2 px-3.5 py-[7px] bg-surface-2 border border-gs-line rounded-full text-[12.5px] font-medium text-t2 whitespace-nowrap">
                    <span className="w-1.5 h-1.5 rounded-full bg-gs-green shrink-0" />
                    {b}
                  </span>
                ))}
              </div>
            </div>

            {/* Right — tabbed quote widget */}
            <div id="hero-quote" className="sticky top-[76px]">

              {/* Product tabs */}
              <div className="flex overflow-x-auto scrollbar-hide bg-surface-card border border-gs-line border-b-0 rounded-t-[14px]">
                {PRODUCTS.map(p => (
                  <button
                    key={p.id}
                    onClick={() => { setActiveProduct(p.id); setQuoteGenerated(false); }}
                    className={`shrink-0 flex items-center gap-2 px-5 py-[14px] text-[13px] font-medium border-b-[2.5px] -mb-px whitespace-nowrap transition-all duration-150 bg-transparent cursor-pointer
                      ${activeProduct === p.id
                        ? "text-brand border-brand font-semibold"
                        : "text-t3 border-transparent hover:text-t1"}`}
                  >
                    {p.label}
                    {p.status === "live"
                      ? <span className="text-[9.5px] font-bold tracking-[0.07em] uppercase px-1.5 py-0.5 rounded bg-gs-green-bg text-gs-green">Live</span>
                      : <span className="text-[9.5px] font-bold tracking-[0.07em] uppercase px-1.5 py-0.5 rounded bg-surface-3 text-t4">Soon</span>}
                  </button>
                ))}
              </div>

              {/* Widget body */}
              <div className="bg-surface-card border border-gs-line border-t-0 rounded-b-[14px] overflow-hidden">

                {product.status === "live" ? (
                  <>
                    {/* Orange header band */}
                    <div className="px-6 py-[18px] bg-brand flex items-center justify-between">
                      <div>
                        <div className="text-[15px] font-bold text-white font-head tracking-tight">Motor Insurance Quote</div>
                        <div className="text-[12px] text-white/70 mt-0.5">No sign-up · Takes 30 seconds</div>
                      </div>
                      <span className="text-[11px] font-bold text-white/55 tracking-[0.06em] uppercase">Free</span>
                    </div>

                    <div className="p-6 flex flex-col gap-4">
                      {/* Fields */}
                      <div>
                        <label className={LABEL_CLS}>Registration number</label>
                        <input className={INPUT_CLS} placeholder="e.g. Dhaka Metro-GA 11-2345" value={form.regNumber} onChange={e => setForm({ ...form, regNumber: e.target.value })} />
                      </div>
                      <div>
                        <label className={LABEL_CLS}>Vehicle value — sum insured (BDT)</label>
                        <input className={INPUT_CLS} placeholder="e.g. 1,500,000" value={form.carValue} onChange={e => setForm({ ...form, carValue: e.target.value })} />
                      </div>
                      <div>
                        <label className={LABEL_CLS}>Engine displacement (CC)</label>
                        <input type="number" className={INPUT_CLS} placeholder="e.g. 1500" value={form.engineCC} onChange={e => setForm({ ...form, engineCC: e.target.value })} />
                      </div>

                      {/* CTA */}
                      <button
                        onClick={handleGetQuote}
                        disabled={isLoading || !form.regNumber || !form.carValue || !form.engineCC}
                        className="w-full h-11 bg-brand hover:bg-brand-hover disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-semibold rounded-gs flex items-center justify-center gap-2 transition-all duration-200 hover:-translate-y-px hover:shadow-[0_6px_20px_rgba(232,92,13,0.28)] cursor-pointer border-none"
                      >
                        {isLoading
                          ? <><span className="w-[15px] h-[15px] border-2 border-white/30 border-t-white rounded-full animate-spin-gs inline-block" />Calculating…</>
                          : "Calculate my premium"}
                      </button>

                      {/* Quote result */}
                      {quoteGenerated && (
                        <div id="quote-result" className="p-5 bg-brand-soft border border-brand-border rounded-gs animate-slide-down">
                          <div className="text-[11px] font-bold tracking-[0.08em] uppercase text-brand mb-1.5">Estimated annual premium</div>
                          <div className="font-head text-[38px] font-extrabold tracking-[-0.04em] leading-none text-t1 mb-1">৳{quoteAmount}</div>
                          <div className="text-[12px] text-t3 mb-4">Comprehensive motor insurance · IDRA approved</div>
                          <button className="w-full h-11 bg-brand hover:bg-brand-hover text-white text-sm font-semibold rounded-gs transition-all duration-200 border-none cursor-pointer">
                            Proceed to secure payment
                          </button>
                          <div className="text-center mt-2.5 text-[11.5px] text-t4">Encrypted by SSLCommerz · AES-256</div>
                        </div>
                      )}

                      {/* Payment methods */}
                      <div className="flex flex-wrap gap-1.5 pt-1 border-t border-gs-line">
                        {["bKash","Nagad","Visa","Mastercard"].map(p => (
                          <span key={p} className="px-2.5 py-1 bg-surface-2 border border-gs-line rounded-gs-sm text-[12px] font-semibold text-t2">{p}</span>
                        ))}
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="p-6 flex flex-col items-start gap-4">
                    <span className="inline-flex items-center gap-2 px-3 py-1.5 bg-surface-2 border border-gs-line rounded-full text-[12px] font-semibold text-t3">
                      Launching soon
                    </span>
                    <h3 className="font-head text-[20px] font-bold tracking-tight text-t1">{product.tagline}</h3>
                    <p className="text-[13px] leading-[1.72] text-t3 max-w-[320px]">{product.description}</p>
                    <div className="flex flex-col gap-2 w-full">
                      {product.features.map(f => (
                        <div key={f} className="flex items-center gap-2.5 text-[13.5px] text-t2">
                          <span className="w-1.5 h-1.5 rounded-full bg-brand shrink-0" />{f}
                        </div>
                      ))}
                    </div>
                    <div className="w-full pt-2">
                      {notifySent === product.id ? (
                        <div className="p-4 bg-gs-green-bg border border-gs-green rounded-gs animate-fade-up">
                          <div className="text-[13.5px] font-semibold text-gs-green">You're on the list.</div>
                          <div className="text-[12.5px] text-t3 mt-1">We'll notify you when {product.label} launches.</div>
                        </div>
                      ) : (
                        <div className="flex flex-col gap-2.5">
                          <div>
                            <label className={LABEL_CLS}>Notify me at launch</label>
                            <input type="email" className={INPUT_CLS} placeholder="your@email.com" value={notifyEmail} onChange={e => setNotifyEmail(e.target.value)} onKeyDown={e => e.key === "Enter" && notifyEmail && setNotifySent(product.id)} />
                          </div>
                          <button
                            disabled={!notifyEmail}
                            onClick={() => notifyEmail && setNotifySent(product.id)}
                            className="w-full h-11 bg-brand hover:bg-brand-hover disabled:opacity-40 text-white text-sm font-semibold rounded-gs transition-all duration-200 border-none cursor-pointer"
                          >
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

      {/* spacer + divider */}
      <div className="h-16" />
      <div className="w-full h-px bg-gs-line" />

      {/* ── Product catalogue ────────────────────────────────────────────────── */}
      <section id="products" className="py-22 bg-surface-2">
        <div className="max-w-[1120px] mx-auto px-10">
          <div className="inline-flex items-center gap-2 mb-5">
            <span className="w-[5px] h-[5px] rounded-full bg-brand shrink-0" />
            <span className="text-[11px] font-bold tracking-[0.1em] uppercase text-brand">Our Products</span>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-end mb-12">
            <h2 className="font-head text-[clamp(26px,3.2vw,44px)] font-bold tracking-[-0.03em] text-t1 leading-[1.12]">
              One platform.<br/><span className="text-brand">Every insurance need.</span>
            </h2>
            <p className="text-[14.5px] leading-[1.75] text-t3 max-w-[380px]">
              Guardian Stack is building Bangladesh's most complete digital insurance suite — regulated, transparent, and entirely paperless.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
            {PRODUCTS.map(p => (
              <div
                key={p.id}
                className={`p-7 rounded-gs border bg-surface-card flex flex-col transition-all duration-200 hover:-translate-y-0.5 hover:shadow-[0_8px_28px_rgba(232,92,13,0.09)] cursor-pointer
                  ${p.status === "live" ? "border-brand-border" : "border-gs-line hover:border-brand-border"}`}
              >
                {/* Icon + status */}
                <div className="flex justify-between items-start mb-5">
                  <div className="w-11 h-11 rounded-gs-sm bg-brand-soft border border-brand-border flex items-center justify-center shrink-0">
                    <ProductIcon id={p.id} />
                  </div>
                  {p.status === "live"
                    ? <span className="text-[9.5px] font-bold tracking-[0.07em] uppercase px-1.5 py-0.5 rounded bg-gs-green-bg text-gs-green">Live</span>
                    : <span className="text-[9.5px] font-bold tracking-[0.07em] uppercase px-1.5 py-0.5 rounded bg-surface-3 text-t4">Coming soon</span>}
                </div>

                <div className="font-head text-[16px] font-bold tracking-tight text-t1 mb-2">{p.label}</div>
                <p className="text-[13px] leading-[1.72] text-t3 mb-5 flex-1">{p.description}</p>

                <div className="flex flex-col gap-2 mb-6">
                  {p.features.map(f => (
                    <div key={f} className="flex items-start gap-2.5 text-[12.5px] text-t2">
                      <span className="w-[5px] h-[5px] rounded-full bg-gs-green shrink-0 mt-1.5" />{f}
                    </div>
                  ))}
                </div>

                <button
                  onClick={() => { setActiveProduct(p.id); document.getElementById("hero-quote")?.scrollIntoView({ behavior: "smooth" }); }}
                  className="w-full h-10 border border-brand text-brand text-[13px] font-semibold rounded-gs-sm hover:bg-brand-soft transition-all duration-200 bg-transparent cursor-pointer"
                >
                  {p.status === "live" ? "Get a quote →" : "Notify me at launch"}
                </button>
              </div>
            ))}
          </div>
        </div>
      </section>

      <div className="w-full h-px bg-gs-line" />

      {/* ── How it works ─────────────────────────────────────────────────────── */}
      <section id="how-it-works" className="py-22 bg-surface">
        <div className="max-w-[1120px] mx-auto px-10">
          <div className="inline-flex items-center gap-2 mb-5">
            <span className="w-[5px] h-[5px] rounded-full bg-brand shrink-0" />
            <span className="text-[11px] font-bold tracking-[0.1em] uppercase text-brand">Process</span>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-[320px_1fr] gap-[72px] items-start">
            <div>
              <h2 className="font-head text-[clamp(26px,3.2vw,44px)] font-bold tracking-[-0.03em] text-t1 leading-[1.12] mb-4">
                Three steps.<br/><span className="text-brand">Two minutes.</span>
              </h2>
              <p className="text-[14.5px] leading-[1.75] text-t3 max-w-[280px]">We stripped every unnecessary step from the traditional insurance process. Details, payment, policy.</p>
            </div>
            <div>
              {[
                { n: "01", title: "Enter your details",          body: "Provide the information relevant to your chosen product — vehicle details for motor, travel dates for overseas medical, and so on." },
                { n: "02", title: "Pay via your preferred method",body: "Complete payment using bKash, Nagad, or any bank card through SSLCommerz PCI DSS Level 1 certification." },
                { n: "03", title: "Receive your policy PDF",     body: "Your IDRA-compliant digital policy arrives in your email immediately after payment — with full legal validity across Bangladesh." },
              ].map((step, i) => (
                <div key={i} className={`flex gap-5 py-7 border-b border-gs-line ${i === 0 ? "border-t" : ""}`}>
                  <div className="w-9 h-9 rounded-full bg-brand-soft border border-brand-border text-brand font-head text-[13px] font-extrabold flex items-center justify-center shrink-0">{step.n}</div>
                  <div>
                    <div className="text-[15px] font-semibold text-t1 tracking-tight mb-2">{step.title}</div>
                    <div className="text-[13px] leading-[1.72] text-t3">{step.body}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <div className="w-full h-px bg-gs-line" />

      {/* ── Comparison ───────────────────────────────────────────────────────── */}
      <section className="py-22 bg-surface-2">
        <div className="max-w-[1120px] mx-auto px-10">
          <div className="inline-flex items-center gap-2 mb-5">
            <span className="w-[5px] h-[5px] rounded-full bg-brand shrink-0" />
            <span className="text-[11px] font-bold tracking-[0.1em] uppercase text-brand">Motor Insurance</span>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-20 items-end mb-12">
            <h2 className="font-head text-[clamp(26px,3.2vw,44px)] font-bold tracking-[-0.03em] text-t1 leading-[1.12]">
              Guardian Stack vs.<br/><span className="text-brand">the traditional agent.</span>
            </h2>
            <p className="text-[14.5px] leading-[1.75] text-t3 max-w-[360px]">The agent model was built on paper, office visits, and opacity. We replaced every step with software.</p>
          </div>
          <table className="w-full border-collapse">
            <thead>
              <tr>
                {["Feature","Guardian Stack","Traditional agent"].map(h => (
                  <th key={h} className="text-left pb-3.5 text-[11px] font-bold uppercase tracking-[0.08em] text-t4 border-b-[1.5px] border-gs-line">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {COMPARISON.map((row, i) => (
                <tr key={i}>
                  <td className="py-[15px] border-b border-gs-line text-[13px] text-t3 w-[28%] pr-5 align-top pt-[17px]">{row.f}</td>
                  <td className="py-[15px] border-b border-gs-line text-[14px] font-semibold text-t1 pr-5">
                    <span className="inline-flex items-center gap-2 before:content-[''] before:w-1.5 before:h-1.5 before:rounded-full before:bg-gs-green before:shrink-0">{row.g}</span>
                  </td>
                  <td className="py-[15px] border-b border-gs-line text-[14px] text-t4">{row.t}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <div className="w-full h-px bg-gs-line" />

      {/* ── Security ─────────────────────────────────────────────────────────── */}
      <section id="security" className="py-22 bg-surface">
        <div className="max-w-[1120px] mx-auto px-10">
          <div className="inline-flex items-center gap-2 mb-5">
            <span className="w-[5px] h-[5px] rounded-full bg-brand shrink-0" />
            <span className="text-[11px] font-bold tracking-[0.1em] uppercase text-brand">Compliance & Security</span>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-20 items-start">
            <div>
              <h2 className="font-head text-[clamp(26px,3.2vw,44px)] font-bold tracking-[-0.03em] text-t1 leading-[1.12] mb-5">
                Built on<br/><span className="text-brand">regulatory trust.</span>
              </h2>
              <p className="text-[14.5px] leading-[1.75] text-t3 max-w-[400px] mb-10">
                Every product on Guardian Stack is governed by the Insurance Development and Regulatory Authority of Bangladesh. We are a licensed insurer — not a marketplace.
              </p>
              {[
                { title: "IDRA regulatory compliance", body: "All policies are filed with and approved by IDRA. Your policy is enforceable in any Bangladeshi court of law." },
                { title: "Payment security",           body: "Payments handled exclusively through SSLCommerz — Bangladesh's PCI DSS Level 1 certified gateway. We never store card data." },
                { title: "Data privacy",               body: "NID numbers and personal data are AES-256 encrypted at rest and in transit. ISO 27001 audited infrastructure." },
              ].map((item, i) => (
                <div key={i} className="flex gap-4 py-6 border-t border-gs-line">
                  <div className="w-[3px] rounded-sm bg-brand shrink-0 my-[3px]" />
                  <div>
                    <div className="text-[14px] font-semibold text-t1 tracking-tight mb-1.5">{item.title}</div>
                    <div className="text-[13px] leading-[1.72] text-t3">{item.body}</div>
                  </div>
                </div>
              ))}
            </div>
            <div className="flex flex-col gap-4">
              <div className="p-7 border border-gs-line rounded-gs bg-surface-card">
                <div className="text-[11px] font-bold tracking-[0.08em] uppercase text-t4 mb-3.5">Regulator</div>
                <div className="font-head text-[19px] font-bold tracking-tight text-t1 leading-[1.25] mb-2.5">Insurance Development &amp;<br/>Regulatory Authority</div>
                <div className="text-[13px] leading-[1.72] text-t3">IDRA was established under the Insurance Act 2010. All Guardian Stack policies are IDRA-filed and legally valid nationwide.</div>
              </div>
              <div className="p-7 border border-gs-line rounded-gs bg-surface-card">
                <div className="text-[11px] font-bold tracking-[0.08em] uppercase text-t4 mb-3.5">Accepted payments</div>
                <div className="flex flex-wrap gap-1.5 mb-3.5">
                  {["bKash","Nagad","Visa","Mastercard","Amex","Rocket"].map(p => (
                    <span key={p} className="px-2.5 py-1 bg-surface-2 border border-gs-line rounded-gs-sm text-[12px] font-semibold text-t2">{p}</span>
                  ))}
                </div>
                <div className="text-[13px] leading-[1.72] text-t3">Processed by SSLCommerz — PCI DSS Level 1 certified.</div>
              </div>
              <div className="p-5 bg-brand-soft border border-brand-border rounded-gs">
                <p className="text-[13.5px] leading-[1.7] text-t2">
                  <span className="font-bold text-brand">Your data is yours.</span>{" "}
                  Guardian Stack does not sell, share, or monetise your personal information. All data is encrypted and strictly access-controlled.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <div className="w-full h-px bg-gs-line" />

      {/* ── FAQ ──────────────────────────────────────────────────────────────── */}
      <section id="faq" className="py-22 bg-surface-2">
        <div className="max-w-[1120px] mx-auto px-10">
          <div className="grid grid-cols-1 lg:grid-cols-[280px_1fr] gap-20 items-start">
            <div className="lg:sticky lg:top-20">
              <div className="inline-flex items-center gap-2 mb-5">
                <span className="w-[5px] h-[5px] rounded-full bg-brand shrink-0" />
                <span className="text-[11px] font-bold tracking-[0.1em] uppercase text-brand">FAQ</span>
              </div>
              <h2 className="font-head text-[clamp(24px,3vw,38px)] font-bold tracking-[-0.03em] text-t1 leading-[1.12] mb-3.5">Questions<br/>we hear often.</h2>
              <p className="text-[13px] leading-[1.72] text-t3 mb-5">Can't find your answer?</p>
              <a href="mailto:support@guardianstack.com.bd" className="text-[13.5px] font-semibold text-brand no-underline">
                support@guardianstack.com.bd →
              </a>
            </div>
            <div>
              {FAQS.map((faq, i) => (
                <div key={i} className={`border-b border-gs-line ${i === 0 ? "border-t" : ""}`}>
                  <button
                    onClick={() => setOpenFaq(openFaq === i ? null : i)}
                    className="w-full flex items-center justify-between gap-6 py-5 bg-transparent border-none text-left cursor-pointer group"
                  >
                    <span className="text-[15px] font-medium text-t1 group-hover:text-brand transition-colors tracking-tight">{faq.q}</span>
                    <span className={`w-7 h-7 rounded-full bg-surface-2 border border-gs-line flex items-center justify-center text-[17px] font-light text-t3 shrink-0 transition-all duration-300
                      ${openFaq === i ? "rotate-45 bg-brand-soft border-brand-border text-brand" : ""}`}>+</span>
                  </button>
                  {openFaq === i && (
                    <div className="pb-5 text-[14.5px] leading-[1.78] text-t3 max-w-[640px] animate-fade-up">{faq.a}</div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <div className="w-full h-px bg-gs-line" />

      {/* ── Final CTA ────────────────────────────────────────────────────────── */}
      <section className="py-22 bg-brand">
        <div className="max-w-[1120px] mx-auto px-10">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-20 items-center">
            <div>
              <h2 className="font-head text-[clamp(28px,3.8vw,50px)] font-extrabold tracking-[-0.035em] text-white leading-[1.08] mb-3.5">
                Get your first policy in the next two minutes.
              </h2>
              <p className="text-[15px] leading-[1.72] text-white/65">
                Motor Insurance is live now. Overseas Medical, Health, Home, Life, and SME products launching shortly. One account, every policy.
              </p>
            </div>
            <div className="flex flex-col gap-3">
              <button
                onClick={() => document.getElementById("hero-quote")?.scrollIntoView({ behavior: "smooth" })}
                className="h-[52px] bg-white text-brand text-[14px] font-bold rounded-gs hover:opacity-85 transition-all duration-200 hover:-translate-y-px border-none cursor-pointer"
              >
                Get a free quote now
              </button>
              <div className="text-center text-[12px] text-white/50">No account required · Policy in under 2 minutes</div>
            </div>
          </div>
        </div>
      </section>

      {/* ── Footer ───────────────────────────────────────────────────────────── */}
      <footer className="bg-surface border-t border-gs-line py-14">
        <div className="max-w-[1120px] mx-auto px-10">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-[2fr_1fr_1fr_1fr] gap-12 mb-12">
            <div>
              <div className="flex items-center gap-2.5 mb-3.5">
                <div className="w-[30px] h-[30px] bg-brand rounded-[8px] flex items-center justify-center shrink-0"><ShieldLogo /></div>
                <span className="font-head text-[15px] font-bold tracking-tight text-t1">Guardian Stack</span>
              </div>
              <p className="text-[13px] leading-[1.75] text-t4 max-w-[220px]">Bangladesh's regulated digital insurance platform. Motor, health, travel, home, life, and business — all in one place.</p>
            </div>
            {[
              { title: "Products", links: ["Motor Insurance","Overseas Medical","Health Insurance","Home Insurance","Term Life","SME Business"] },
              { title: "Company",  links: ["About","Blog","Careers","Press"] },
              { title: "Legal",    links: ["Privacy policy","Terms of service","IDRA filing","Cookie policy"] },
            ].map(col => (
              <div key={col.title}>
                <div className="text-[11px] font-bold tracking-[0.08em] uppercase text-t4 mb-4">{col.title}</div>
                <div className="flex flex-col gap-2.5">
                  {col.links.map(link => (
                    <a key={link} href="#" className="text-[13.5px] text-t3 no-underline hover:text-brand transition-colors">{link}</a>
                  ))}
                </div>
              </div>
            ))}
          </div>
          <div className="pt-6 border-t border-gs-line flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
            <span className="text-[12px] text-t4">© 2025 Guardian Stack Ltd. IDRA License No. GS-2025-XXXX. All rights reserved.</span>
            <div className="flex gap-2">
              {["IDRA Regulated","SSL Secured"].map(b => (
                <span key={b} className="inline-flex items-center gap-2 px-3 py-[6px] bg-surface-2 border border-gs-line rounded-full text-[12px] font-medium text-t2">
                  <span className="w-1.5 h-1.5 rounded-full bg-gs-green shrink-0" />{b}
                </span>
              ))}
            </div>
          </div>
        </div>
      </footer>

      {/* ── Exit intent popup ────────────────────────────────────────────────── */}
      {exitPopup && (
        <div
          className="fixed inset-0 z-[999] bg-black/55 backdrop-blur-md flex items-center justify-center p-5 animate-fade-up"
          onClick={() => setExitPopup(false)}
        >
          <div
            className="bg-surface-card border border-gs-line rounded-2xl p-11 max-w-[448px] w-full relative animate-pop-up"
            onClick={e => e.stopPropagation()}
          >
            {/* Orange top accent */}
            <div className="absolute top-0 left-0 right-0 h-1 bg-brand rounded-t-2xl" />
            <button onClick={() => setExitPopup(false)} className="absolute top-4 right-5 bg-transparent border-none text-[22px] text-t4 cursor-pointer leading-none p-1">×</button>

            <div className="mb-7">
              <div className="inline-flex items-center gap-2 mb-3.5">
                <span className="w-[5px] h-[5px] rounded-full bg-brand shrink-0" />
                <span className="text-[11px] font-bold tracking-[0.1em] uppercase text-brand">Before you leave</span>
              </div>
              <h3 className="font-head text-[24px] font-bold tracking-tight text-t1 leading-[1.2] mb-3">Save your quote for later.</h3>
              <p className="text-[14.5px] leading-[1.75] text-t3">We'll hold this price for 24 hours. Enter your email and we'll send you a link to resume exactly where you left off.</p>
            </div>

            {!emailSent ? (
              <div className="flex flex-col gap-2.5">
                <div>
                  <label className={LABEL_CLS}>Your email address</label>
                  <input
                    type="email" className={INPUT_CLS} placeholder="name@example.com"
                    value={emailInput} onChange={e => setEmailInput(e.target.value)}
                    onKeyDown={e => e.key === "Enter" && emailInput && setEmailSent(true)}
                  />
                </div>
                <button
                  onClick={() => emailInput && setEmailSent(true)}
                  className="w-full h-11 bg-brand hover:bg-brand-hover text-white text-sm font-semibold rounded-gs transition-all duration-200 border-none cursor-pointer"
                >
                  Send my quote link
                </button>
                <button
                  onClick={() => setExitPopup(false)}
                  className="w-full h-11 bg-transparent border border-gs-line-2 text-t2 text-sm font-medium rounded-gs hover:border-t3 hover:text-t1 transition-colors cursor-pointer"
                >
                  No thanks, I'll start over
                </button>
              </div>
            ) : (
              <div className="p-7 bg-gs-green-bg border border-gs-green rounded-gs text-center animate-fade-up">
                <div className="font-head text-[19px] font-bold text-t1 mb-2 tracking-tight">Quote sent.</div>
                <div className="text-[13.5px] text-t3">
                  Check your inbox at <strong className="font-semibold text-t1">{emailInput}</strong>. Valid for 24 hours.
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}