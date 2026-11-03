/* Matonge Coin (MC) — centrale, server-autoritaire wallet.
   Het saldo staat uitsluitend hier (Netlify Blobs). De browser kan het nooit zelf wijzigen:
   alle regels, bedragen, limieten en cooldowns worden op de server afgedwongen. */
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

/* ---------------- regels (alleen hier aanpasbaar) ---------------- */
const GAMES = ["mudkings", "league", "ashfall", "blokken", "drift", "savanne", "bordspellen", "meme"];
const CFG = {
  dailyBase: 10, dailyStreakStep: 2, dailyStreakMax: 7, dailyWeekBonus: 40,
  gameCoinPerMin: 1, gameSessionCap: 20, gameDayCap: 100, pingMaxGap: 45, signupBonus: 25,
  maxTx: 300,
};
const MISSIONS = [ // dagelijks, resetten elke dag
  { id: "d_claim", title: "Pak je dagelijkse beloning", reward: 5, goal: 1, stat: "claimedToday" },
  { id: "d_play3", title: "Speel 3 minuten", reward: 10, goal: 180, stat: "playToday", unit: "sec" },
  { id: "d_two", title: "Speel 2 verschillende games", reward: 15, goal: 2, stat: "gamesToday" },
];
const CHALLENGES = [ // blijvend
  { id: "c_hour", title: "Speel in totaal 1 uur", reward: 100, goal: 3600, stat: "playTotal", unit: "sec" },
  { id: "c_all", title: "Probeer alle 8 games", reward: 150, goal: GAMES.length, stat: "gamesTried" },
  { id: "c_streak5", title: "Haal een streak van 5 dagen", reward: 60, goal: 5, stat: "bestStreak" },
];
const ACHIEVEMENTS = [
  { id: "a_first", title: "Eerste stap", desc: "Speel je eerste game", reward: 20, test: s => s.gamesTried >= 1 },
  { id: "a_streak3", title: "Op dreef", desc: "3 dagen op rij inloggen", reward: 30, test: s => s.bestStreak >= 3 },
  { id: "a_streak7", title: "Onstopbaar", desc: "7 dagen op rij", reward: 75, test: s => s.bestStreak >= 7 },
  { id: "a_marathon", title: "Marathon", desc: "2 uur speeltijd", reward: 80, test: s => s.playTotal >= 7200 },
  { id: "a_explorer", title: "Ontdekker", desc: "Speel 5 verschillende games", reward: 50, test: s => s.gamesTried >= 5 },
  { id: "a_rich", title: "Goudkoorts", desc: "Bezit 500 MC", reward: 100, test: s => s.balance >= 500 },
  { id: "a_shopper", title: "Stijlvol", desc: "Koop je eerste item", reward: 25, test: s => s.items >= 1 },
];
const SHOP = [
  { id: "title_pioneer", name: "Titel: Pionier", price: 60, desc: "Toon 'Pionier' naast je naam" },
  { id: "title_legend", name: "Titel: Legende", price: 250, desc: "Toon 'Legende' naast je naam" },
  { id: "frame_gold", name: "Gouden profielrand", price: 150, desc: "Een gouden rand om je avatar" },
  { id: "boost_daily", name: "Dagbonus +5", price: 400, desc: "Je dagelijkse beloning wordt blijvend +5 MC" },
];
const EVENTS = [ // eenmalig te claimen binnen het tijdvenster (UTC-datums)
  { id: "ev_launch", title: "Lancering Matonge Coin", desc: "Welkom in de nieuwe economie van Matonge Universe!", reward: 100, from: "2026-11-01", to: "2026-12-06" },
  { id: "ev_blackfriday", title: "Black & Gold Friday", desc: "Dubbele feestvreugde op Black Friday.", reward: 75, from: "2026-11-27", to: "2026-11-30" },
  { id: "ev_winter", title: "Wintervakantie-cadeau", desc: "Een gouden kerstpakket voor trouwe spelers.", reward: 120, from: "2026-12-20", to: "2027-01-04" },
];

/* ---------------- helpers ---------------- */
const TZ = "Europe/Brussels";
const dayKey = (t = Date.now()) => new Intl.DateTimeFormat("sv-SE", { timeZone: TZ }).format(new Date(t)); // YYYY-MM-DD
const dayDiff = (a, b) => Math.round((Date.parse(b) - Date.parse(a)) / 864e5);
const isoDay = t => new Date(t).toISOString().slice(0, 10);
const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const fail = (code, msg) => { const e = new Error(msg); e.code = code; return e; };
const store = () => getStore({ name: "matonge-coin", consistency: "strong" });

async function secret() {
  if (process.env.MC_SECRET) return process.env.MC_SECRET;
  const st = store(); let s = await st.get("config:secret");
  if (!s) { s = crypto.randomBytes(32).toString("hex"); await st.set("config:secret", s, { onlyIfNew: true }); s = await st.get("config:secret"); }
  return s;
}
async function sign(user) {
  const body = Buffer.from(JSON.stringify({ u: user, e: Date.now() + 30 * 864e5 })).toString("base64url");
  return body + "." + crypto.createHmac("sha256", await secret()).update(body).digest("base64url");
}
async function verify(tok) {
  if (!tok || typeof tok !== "string" || !tok.includes(".")) return null;
  const [body, sig] = tok.split(".");
  const good = crypto.createHmac("sha256", await secret()).update(body).digest("base64url");
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  try { const p = JSON.parse(Buffer.from(body, "base64url").toString()); return p.e > Date.now() ? p.u : null; } catch { return null; }
}
const hash = (pw, salt) => new Promise((res, rej) => crypto.pbkdf2(pw, salt, 120000, 32, "sha256", (e, k) => e ? rej(e) : res(k.toString("hex"))));

/* Atomisch lezen-wijzigen-schrijven met etag (voorkomt dubbel claimen bij gelijktijdige verzoeken) */
async function mutate(user, fn) {
  const st = store(), key = "u:" + user;
  for (let i = 0; i < 8; i++) {
    const cur = await st.getWithMetadata(key, { type: "json" });
    if (!cur) throw fail(404, "Account niet gevonden");
    const doc = cur.data; const out = await fn(doc);
    const r = await st.setJSON(key, doc, { onlyIfMatch: cur.etag });
    if (r.modified !== false) return out;
  }
  throw fail(409, "Even druk, probeer opnieuw");
}
function credit(doc, amount, type, label) {
  amount = Math.floor(amount); if (!(amount > 0)) return 0;
  doc.balance += amount; doc.earned += amount; pushTx(doc, amount, type, label); return amount;
}
function debit(doc, amount, type, label) {
  if (doc.balance < amount) throw fail(402, "Onvoldoende Matonge Coins");
  doc.balance -= amount; doc.spent += amount; pushTx(doc, -amount, type, label);
}
function pushTx(doc, amount, type, label) {
  doc.tx.unshift({ id: crypto.randomBytes(5).toString("hex"), t: Date.now(), a: amount, type, label, bal: doc.balance });
  if (doc.tx.length > CFG.maxTx) doc.tx.length = CFG.maxTx;
}
function fresh(user, hashed, salt) {
  return { user, salt, hash: hashed, created: Date.now(), balance: 0, earned: 0, spent: 0, tx: [], streak: 0, bestStreak: 0, lastClaim: null,
    playTotal: 0, games: {}, day: { k: dayKey(), play: 0, games: [], gameCoins: 0 }, done: {}, ach: {}, items: [], events: {}, session: null, fails: 0, lockUntil: 0 };
}
function rollDay(doc) { const k = dayKey(); if (doc.day.k !== k) { doc.day = { k, play: 0, games: [], gameCoins: 0 }; doc.done = Object.fromEntries(Object.entries(doc.done).filter(([id]) => id.startsWith("c_"))); } }
function stats(doc) {
  return { balance: doc.balance, playTotal: doc.playTotal, playToday: doc.day.play, gamesToday: doc.day.games.length,
    gamesTried: Object.keys(doc.games).length, bestStreak: doc.bestStreak, claimedToday: doc.lastClaim === dayKey() ? 1 : 0, items: doc.items.length };
}
function checkAchievements(doc) { // automatisch toekennen
  const s = stats(doc); const got = [];
  for (const a of ACHIEVEMENTS) if (!doc.ach[a.id] && a.test(s)) { doc.ach[a.id] = Date.now(); credit(doc, a.reward, "achievement", "Achievement: " + a.title); got.push(a.title); s.balance = doc.balance; }
  return got;
}
function finishSession(doc) {
  const s = doc.session; if (!s) return 0; doc.session = null;
  const secs = Math.min(Math.floor(s.active), 4 * 3600); if (secs < 1) return 0;
  doc.playTotal += secs; doc.day.play += secs;
  doc.games[s.game] = (doc.games[s.game] || 0) + secs;
  if (!doc.day.games.includes(s.game)) doc.day.games.push(s.game);
  const want = Math.min(Math.floor(secs / 60) * CFG.gameCoinPerMin, CFG.gameSessionCap, CFG.gameDayCap - doc.day.gameCoins);
  if (want > 0) { doc.day.gameCoins += want; credit(doc, want, "game", "Gespeeld: " + s.game); }
  return Math.max(want, 0);
}
function view(doc, extra = {}) {
  rollDay(doc); const s = stats(doc);
  const prog = m => Math.min(s[m.stat], m.goal);
  const mk = m => ({ id: m.id, title: m.title, reward: m.reward, goal: m.goal, unit: m.unit || "", progress: prog(m), done: !!doc.done[m.id], ready: !doc.done[m.id] && s[m.stat] >= m.goal });
  const today = dayKey();
  return { user: doc.user, balance: doc.balance, earned: doc.earned, spent: doc.spent, streak: doc.lastClaim && dayDiff(doc.lastClaim, today) <= 1 ? doc.streak : 0,
    canClaim: doc.lastClaim !== today, dailyNext: dailyAmount(doc, doc.lastClaim && dayDiff(doc.lastClaim, today) <= 1 ? doc.streak + 1 : 1),
    earnedToday: doc.tx.filter(t => t.a > 0 && dayKey(t.t) === today).reduce((n, t) => n + t.a, 0),
    gameCoinsToday: doc.day.gameCoins, gameDayCap: CFG.gameDayCap, playTotal: doc.playTotal,
    missions: MISSIONS.map(mk), challenges: CHALLENGES.map(mk),
    achievements: ACHIEVEMENTS.map(a => ({ id: a.id, title: a.title, desc: a.desc, reward: a.reward, unlocked: !!doc.ach[a.id] })),
    events: EVENTS.map(e => { const t = isoDay(Date.now()); return { id: e.id, title: e.title, desc: e.desc, reward: e.reward, from: e.from, to: e.to, active: t >= e.from && t <= e.to, claimed: !!doc.events[e.id] }; }),
    shop: SHOP.map(i => ({ ...i, owned: doc.items.includes(i.id) })), items: doc.items, tx: doc.tx.slice(0, 100), ...extra };
}
function dailyAmount(doc, streak) {
  const n = ((streak - 1) % CFG.dailyStreakMax) + 1;
  return CFG.dailyBase + (doc.items.includes("boost_daily") ? 5 : 0) + (n - 1) * CFG.dailyStreakStep + (n === CFG.dailyStreakMax ? CFG.dailyWeekBonus : 0);
}

/* ---------------- acties ---------------- */
const open = {
  async register({ username, password }) {
    const u = String(username || "").trim().toLowerCase();
    if (!/^[a-z0-9_]{3,20}$/.test(u)) throw fail(400, "Gebruikersnaam: 3–20 tekens (letters, cijfers, _)");
    if (typeof password !== "string" || password.length < 6 || password.length > 100) throw fail(400, "Wachtwoord: minstens 6 tekens");
    const salt = crypto.randomBytes(16).toString("hex");
    const doc = fresh(u, await hash(password, salt), salt);
    credit(doc, CFG.signupBonus, "bonus", "Welkomstbonus");
    const r = await store().setJSON("u:" + u, doc, { onlyIfNew: true });
    if (r.modified === false) throw fail(409, "Deze gebruikersnaam bestaat al");
    return { token: await sign(u), state: view(doc) };
  },
  async login({ username, password }) {
    const u = String(username || "").trim().toLowerCase(); const st = store();
    const cur = await st.getWithMetadata("u:" + u, { type: "json" });
    if (!cur) throw fail(401, "Onjuiste gebruikersnaam of wachtwoord");
    if (cur.data.lockUntil > Date.now()) throw fail(429, "Te veel pogingen. Probeer over enkele minuten opnieuw.");
    const ok = crypto.timingSafeEqual(Buffer.from(await hash(String(password || ""), cur.data.salt)), Buffer.from(cur.data.hash));
    if (!ok) {
      await mutate(u, d => { d.fails = (d.fails || 0) + 1; if (d.fails >= 6) { d.lockUntil = Date.now() + 5 * 60e3; d.fails = 0; } });
      throw fail(401, "Onjuiste gebruikersnaam of wachtwoord");
    }
    const state = await mutate(u, d => { d.fails = 0; return view(d); });
    return { token: await sign(u), state };
  },
};
const authed = {
  async state(_, doc) { checkAchievements(doc); return view(doc); },
  async claimDaily(_, doc) {
    const today = dayKey(); if (doc.lastClaim === today) throw fail(409, "Je hebt vandaag al geclaimd");
    doc.streak = doc.lastClaim && dayDiff(doc.lastClaim, today) === 1 ? doc.streak + 1 : 1;
    doc.bestStreak = Math.max(doc.bestStreak, doc.streak); doc.lastClaim = today;
    const n = credit(doc, dailyAmount(doc, doc.streak), "daily", "Dagelijkse beloning (dag " + doc.streak + ")");
    return view(doc, { gained: n, toast: checkAchievements(doc) });
  },
  async gameStart({ game }, doc) {
    if (!GAMES.includes(game)) throw fail(400, "Onbekende game");
    finishSession(doc);
    doc.session = { id: crypto.randomBytes(6).toString("hex"), game, last: Date.now(), active: 0 };
    return view(doc, { sid: doc.session.id });
  },
  async gamePing({ sid }, doc) {
    const s = doc.session; if (!s || s.id !== sid) return view(doc);
    const now = Date.now(); s.active += Math.min((now - s.last) / 1000, CFG.pingMaxGap); s.last = now; return view(doc);
  },
  async gameEnd({ sid }, doc) {
    const s = doc.session; if (!s || s.id !== sid) return view(doc);
    s.active += Math.min((Date.now() - s.last) / 1000, CFG.pingMaxGap);
    const n = finishSession(doc); return view(doc, { gained: n, toast: checkAchievements(doc) });
  },
  async claimMission({ id }, doc) {
    const m = [...MISSIONS, ...CHALLENGES].find(x => x.id === id); if (!m) throw fail(400, "Onbekende missie");
    if (doc.done[id]) throw fail(409, "Al geclaimd"); const s = stats(doc);
    if (s[m.stat] < m.goal) throw fail(400, "Nog niet voltooid");
    doc.done[id] = Date.now(); const n = credit(doc, m.reward, "mission", "Missie: " + m.title);
    return view(doc, { gained: n, toast: checkAchievements(doc) });
  },
  async claimEvent({ id }, doc) {
    const e = EVENTS.find(x => x.id === id); if (!e) throw fail(400, "Onbekend evenement");
    const t = isoDay(Date.now()); if (t < e.from || t > e.to) throw fail(400, "Dit evenement is niet actief");
    if (doc.events[id]) throw fail(409, "Al geclaimd"); doc.events[id] = Date.now();
    const n = credit(doc, e.reward, "event", "Evenement: " + e.title);
    return view(doc, { gained: n, toast: checkAchievements(doc) });
  },
  async spend({ item }, doc) { // winkel; games/shop kunnen later dezelfde logica gebruiken
    const it = SHOP.find(x => x.id === item); if (!it) throw fail(400, "Onbekend item");
    if (doc.items.includes(it.id)) throw fail(409, "Je bezit dit al");
    debit(doc, it.price, "spend", "Gekocht: " + it.name); doc.items.push(it.id);
    return view(doc, { toast: checkAchievements(doc) });
  },
};

export default async (req) => {
  if (req.method !== "POST") return json({ error: "POST vereist" }, 405);
  let b; try { b = await req.json(); } catch { return json({ error: "Ongeldige aanvraag" }, 400); }
  try {
    if (open[b.action]) return json(await open[b.action](b));
    if (!authed[b.action]) return json({ error: "Onbekende actie" }, 400);
    const u = await verify(b.token); if (!u) return json({ error: "Sessie verlopen, log opnieuw in", auth: true }, 401);
    return json(await mutate(u, async doc => { rollDay(doc); return authed[b.action](b, doc); }));
  } catch (e) {
    if (e.code) return json({ error: e.message }, e.code);
    console.error(e); return json({ error: "Serverfout" }, 500);
  }
};
