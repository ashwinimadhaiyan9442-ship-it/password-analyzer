/* ═══════════════════════════════════════════════════════════════
   PASSWORD STRENGTH ANALYZER — MAIN APPLICATION
   Author: AI-generated portfolio project
   Tech:   Vanilla JS + Web Crypto API (zero dependencies)
   Note:   100% client-side — passwords never leave the browser
═══════════════════════════════════════════════════════════════ */

"use strict";

/* ══════════════════════════════════════════════════════════
   MODULE 1: COMMON PASSWORD DATABASE
   Top leaked passwords + structural variants
══════════════════════════════════════════════════════════ */
const COMMON_PASSWORDS = new Set([
  'password','password1','123456','12345678','qwerty','abc123','111111','1234567',
  'iloveyou','admin','letmein','monkey','1234','sunshine','princess','welcome',
  'shadow','superman','master','michael','password123','dragon','123456789',
  'baseball','football','soccer','hockey','solo','pass','test','temp','root',
  'toor','login','hello','changeme','password2','qwerty123','qwertyuiop',
  'asdfghjkl','zxcvbnm','1q2w3e4r','1qaz2wsx','qazwsx','google','linkedin',
  'twitter','facebook','instagram','yahoo','email','user','guest','system',
  'manager','administrator','service','support','default','backup','public',
  'private','secure','access','secret','passwd','pass123','p@ssword','P@ssword',
  'P@ssw0rd','p@ssw0rd','Passw0rd','passw0rd','Pa$$word','pa$$word','Pa$$w0rd',
  'abc','abcd','abcde','abcdef','1111','2222','3333','4444','5555','6666',
  'password!','Password!','Password1','Password1!','123qwe','qwe123',
  'trustno1','starwars','mustang','letmein!','monkey123','princess1'
]);

/* ══════════════════════════════════════════════════════════
   MODULE 2: PATTERN DETECTORS
   Keyboard walks, l33tspeak, sequences, dictionary words
══════════════════════════════════════════════════════════ */
const KEYBOARD_ROWS = ['qwertyuiop','asdfghjkl','zxcvbnm','1234567890'];
const KEYBOARD_TRIGRAMS = new Set();
KEYBOARD_ROWS.forEach(row => {
  for (let i = 0; i < row.length - 2; i++) {
    KEYBOARD_TRIGRAMS.add(row.slice(i, i + 3));
  }
});

const DICT_WORDS = [
  'the','and','for','are','but','not','you','all','any','can','her',
  'was','one','our','out','use','man','day','get','has','him','his','how','its',
  'let','new','now','old','see','two','way','who','boy','did','big','going',
  'love','life','home','time','work','hand','part','just','know','take','over',
  'into','only','come','back','pass','word','name','good','show','give','most',
  'text','also','than','then','them','well','were','will','with','have','from',
  'they','that','this','what','when','your','about','other','right','there'
];

/**
 * Detects structural and semantic weaknesses in a password.
 * Returns array of { type: 'critical'|'bad'|'warn', text: string }
 */
function detectPatterns(pw) {
  const issues = [];
  const lower = pw.toLowerCase();

  // --- Breach database check ---
  if (COMMON_PASSWORDS.has(lower) || COMMON_PASSWORDS.has(pw)) {
    issues.push({ type: 'critical', text: 'This exact password appears in breach databases — it would be cracked instantly.' });
  }

  // --- Repeated characters ---
  if (/(.)\1{2,}/.test(pw)) {
    issues.push({ type: 'bad', text: 'Repeated characters detected (e.g., "aaa" or "111").' });
  }

  // --- Ascending sequences ---
  if (/(?:0123|1234|2345|3456|4567|5678|6789|7890|abcd|bcde|cdef|defg|efgh)/.test(lower)) {
    issues.push({ type: 'bad', text: 'Sequential ascending pattern detected.' });
  }

  // --- Descending sequences ---
  if (/(?:9876|8765|7654|6543|5432|4321|3210|dcba|edcb|fedc)/.test(lower)) {
    issues.push({ type: 'bad', text: 'Sequential descending pattern detected.' });
  }

  // --- Keyboard walks ---
  let hasKeyboard = false;
  for (const pat of KEYBOARD_TRIGRAMS) {
    if (lower.includes(pat)) { hasKeyboard = true; break; }
  }
  if (hasKeyboard) {
    issues.push({ type: 'bad', text: 'Keyboard walk pattern found (e.g., "qwerty", "asdf").' });
  }

  // --- L33tspeak substitutions ---
  if (/[@4][a-z]|[0oO][a-z]|[1l!][a-z]|[3e][a-z]|[5s$][a-z]/i.test(pw)) {
    issues.push({ type: 'warn', text: 'L33tspeak substitutions detected (e.g., "@" for "a", "0" for "o"). These are well-known to attackers.' });
  }

  // --- Dictionary word embedding ---
  let foundWord = '';
  for (const w of DICT_WORDS) {
    if (lower.includes(w) && w.length >= 4) { foundWord = w; break; }
  }
  if (foundWord) {
    issues.push({ type: 'warn', text: `Dictionary word "${foundWord}" found embedded in password.` });
  }

  // --- Year patterns ---
  if (/(?:19|20)\d{2}/.test(pw)) {
    issues.push({ type: 'warn', text: 'Year pattern detected — birth years and recent years are commonly tried.' });
  }

  // --- Date patterns ---
  if (/\b(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{2,4}\b/.test(pw)) {
    issues.push({ type: 'warn', text: 'Date pattern detected. Personal dates are high-priority in targeted attacks.' });
  }

  // --- Predictable structure (Capital + word + number/symbol) ---
  const capitalFirst = /^[A-Z][a-z]/.test(pw);
  const trailNum = /\d{1,4}$/.test(pw);
  const trailSym = /[!@#$%^&*]$/.test(pw);
  if (capitalFirst && (trailNum || trailSym)) {
    issues.push({ type: 'warn', text: 'Predictable structure: Capital first + word + number/symbol is the most common "complex" password pattern.' });
  }

  return issues;
}

/* ══════════════════════════════════════════════════════════
   MODULE 3: ENTROPY CALCULATION
   Shannon entropy + keyspace entropy
══════════════════════════════════════════════════════════ */

/**
 * Shannon entropy: measures character-level unpredictability.
 * Returns bits per character (higher = more random).
 */
function calcShannonEntropy(pw) {
  if (!pw.length) return 0;
  const freq = {};
  for (const c of pw) freq[c] = (freq[c] || 0) + 1;
  let entropy = 0;
  for (const c in freq) {
    const p = freq[c] / pw.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Keyspace entropy: log2(pool^length) total bits.
 * Measures the theoretical brute-force search space.
 */
function calcKeyspaceEntropy(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[!@#$%^&*()_+\-=\[\]{}|;':",.<>?\/\\`~]/.test(pw)) pool += 32;
  if (pool === 0) pool = 26;
  return Math.log2(pool) * pw.length;
}

/**
 * Per-character entropy contributions (for visualization).
 */
function getCharEntropies(pw) {
  const freq = {};
  for (const c of pw) freq[c] = (freq[c] || 0) + 1;
  return pw.split('').map(c => {
    const p = freq[c] / pw.length;
    return -(p * Math.log2(p));
  });
}

/**
 * Classify a character into its type group.
 */
function getCharType(c) {
  if (/[a-z]/.test(c)) return 'lower';
  if (/[A-Z]/.test(c)) return 'upper';
  if (/\d/.test(c)) return 'digit';
  return 'symbol';
}

/* ══════════════════════════════════════════════════════════
   MODULE 4: SCORING ENGINE (0–100)
   Combines length, keyspace, Shannon entropy,
   complexity, uniqueness, and penalty deductions
══════════════════════════════════════════════════════════ */

/**
 * Returns a score 0–100 representing password strength.
 */
function calcScore(pw) {
  if (!pw.length) return 0;
  let score = 0;
  const len = pw.length;

  // Length contribution (max 35 pts)
  score += Math.min(35, len * 2.5);

  // Keyspace entropy contribution (max 25 pts)
  const ksEntropy = calcKeyspaceEntropy(pw);
  score += Math.min(25, ksEntropy / 4);

  // Shannon entropy contribution (max 20 pts)
  const shanEnt = calcShannonEntropy(pw);
  score += Math.min(20, shanEnt * 5);

  // Character class bonuses (max 13 pts)
  if (/[a-z]/.test(pw)) score += 2;
  if (/[A-Z]/.test(pw)) score += 3;
  if (/\d/.test(pw)) score += 3;
  if (/[!@#$%^&*()_+\-=\[\]{}|;':",.<>?\/\\`~]/.test(pw)) score += 5;

  // Unicode bonus (max 2 pts)
  if (/[^\x00-\x7F]/.test(pw)) score += 2;

  // Unique character ratio bonus (max 5 pts)
  const uniqueRatio = new Set(pw).size / pw.length;
  score += Math.min(5, uniqueRatio * 5);

  // ─── Penalties ───
  if (COMMON_PASSWORDS.has(pw.toLowerCase())) score = Math.min(score, 5);
  if (len < 6) score = Math.min(score, 20);
  if (len < 8) score = Math.min(score, 35);

  const patterns = detectPatterns(pw);
  const criticals = patterns.filter(p => p.type === 'critical').length;
  const bads = patterns.filter(p => p.type === 'bad').length;
  score -= criticals * 40;
  score -= bads * 10;

  return Math.max(0, Math.min(100, Math.round(score)));
}

/* ══════════════════════════════════════════════════════════
   MODULE 5: CRACK TIME ESTIMATION
   Models: online throttled → nation-state cluster
══════════════════════════════════════════════════════════ */
const ATTACK_MODELS = [
  { name: 'Online (throttled)',    speed: 1e3,  label: '10³/s · web login w/ throttling' },
  { name: 'Online (unthrottled)', speed: 1e5,  label: '10⁵/s · no rate limiting' },
  { name: 'Offline (bcrypt)',     speed: 1e4,  label: '10⁴/s · GPU bcrypt' },
  { name: 'Offline (SHA-256)',    speed: 1e9,  label: '10⁹/s · GPU SHA-256' },
  { name: 'Offline (MD5)',        speed: 1e10, label: '10¹⁰/s · GPU MD5' },
  { name: 'Nation-state cluster', speed: 1e13, label: '10¹³/s · specialized hardware' },
];

/**
 * Converts a time in seconds to a human-readable string.
 */
function formatTime(seconds) {
  if (seconds < 1e-3)           return 'instantly';
  if (seconds < 1)              return '< 1 second';
  if (seconds < 60)             return Math.round(seconds) + ' seconds';
  if (seconds < 3600)           return Math.round(seconds / 60) + ' minutes';
  if (seconds < 86400)          return Math.round(seconds / 3600) + ' hours';
  if (seconds < 86400 * 365)    return Math.round(seconds / 86400) + ' days';
  if (seconds < 86400*365*100)  return Math.round(seconds / (86400*365)) + ' years';
  if (seconds < 86400*365*1e6)  return Math.round(seconds / (86400*365*1000)) + 'k years';
  if (seconds < 86400*365*1e9)  return Math.round(seconds / (86400*365*1e6)) + 'M years';
  return '> 1 billion years';
}

/* ══════════════════════════════════════════════════════════
   MODULE 6: FEEDBACK GENERATOR
   Human-like, context-aware security advice
══════════════════════════════════════════════════════════ */

/**
 * Produces an array of feedback items combining pattern findings
 * with entropy analysis and overall recommendations.
 */
function generateFeedback(pw, score, patterns) {
  const items = [];
  if (!pw.length) return items;

  const ksEntropy = calcKeyspaceEntropy(pw);
  const shanEntropy = calcShannonEntropy(pw);

  // Include pattern findings first
  for (const p of patterns) {
    items.push({ type: p.type, icon: p.type === 'critical' ? '✕' : p.type === 'bad' ? '⚠' : '◆', text: p.text });
  }

  // Length feedback
  if (pw.length >= 20) {
    items.push({ type: 'ok', icon: '✓', text: 'Excellent length (20+ characters) — length is the single most effective factor.' });
  } else if (pw.length >= 14) {
    items.push({ type: 'ok', icon: '✓', text: 'Good length (14+ characters) provides strong brute-force resistance.' });
  } else if (pw.length < 10) {
    items.push({ type: 'bad', icon: '⚠', text: `Only ${pw.length} characters. Attackers try short passwords first — aim for 14+.` });
  }

  // Keyspace feedback
  if (ksEntropy > 80) {
    items.push({ type: 'ok', icon: '✓', text: `High keyspace entropy (${Math.round(ksEntropy)} bits) — large character pool, hard to exhaust.` });
  }

  // Shannon entropy feedback
  if (shanEntropy < 1.5 && pw.length > 5) {
    items.push({ type: 'warn', icon: '◆', text: `Low Shannon entropy (${shanEntropy.toFixed(2)} bits/char) — many characters repeat, reducing true randomness.` });
  } else if (shanEntropy > 3.5) {
    items.push({ type: 'ok', icon: '✓', text: `High character-level entropy (${shanEntropy.toFixed(2)} bits/char) — excellent distribution, few repeats.` });
  }

  // Uniqueness
  const uniqueRatio = new Set(pw).size / pw.length;
  if (uniqueRatio < 0.5 && pw.length > 6) {
    items.push({ type: 'warn', icon: '◆', text: 'Less than half of characters are unique — high repetition reduces effective entropy.' });
  }

  // Character class mix
  const hasUpper = /[A-Z]/.test(pw);
  const hasLower = /[a-z]/.test(pw);
  const hasDigit = /\d/.test(pw);
  const hasSym = /[!@#$%^&*()_+\-=\[\]{}|;':",.<>?\/\\`~]/.test(pw);
  const types = [hasUpper, hasLower, hasDigit, hasSym].filter(Boolean).length;

  if (types >= 4) {
    items.push({ type: 'ok', icon: '✓', text: 'Uses all four character classes (upper, lower, digits, symbols).' });
  } else if (types === 3) {
    items.push({ type: 'ok', icon: '✓', text: 'Uses three character classes. Adding a fourth would further increase strength.' });
  } else {
    const missing = [];
    if (!hasUpper) missing.push('uppercase letters');
    if (!hasLower) missing.push('lowercase letters');
    if (!hasDigit) missing.push('digits');
    if (!hasSym) missing.push('symbols');
    items.push({ type: 'warn', icon: '◆', text: `Missing character classes: ${missing.join(', ')}.` });
  }

  // Overall summary
  if (score >= 80) {
    items.push({ type: 'ok', icon: '✓', text: 'Overall: Strong password. Store it in a password manager and never reuse it.' });
  } else if (score >= 50) {
    items.push({ type: 'warn', icon: '◆', text: 'Overall: Moderate strength. Consider extending length or using a passphrase.' });
  } else {
    items.push({ type: 'bad', icon: '⚠', text: 'Overall: This password would likely be cracked quickly. Please use a generated one.' });
  }

  return items;
}

/* ══════════════════════════════════════════════════════════
   MODULE 7: ATTACKER SIMULATION
   Sequential multi-phase attack scenario
══════════════════════════════════════════════════════════ */

/**
 * Simulates an adversary's attack phases and returns
 * an array of terminal log lines.
 */
function runAttackerSim(pw) {
  const lines = [];
  const lower = pw.toLowerCase();

  lines.push({ t: 'cmd',  text: '> [*] Initializing attack sequence on target hash...' });
  lines.push({ t: 'info', text: '> [i] Attack mode: multi-vector (dictionary → hybrid → brute)' });
  lines.push({ t: 'cmd',  text: '> [1] Phase 1: Common password list (rockyou.txt, 1.4M entries)' });

  if (COMMON_PASSWORDS.has(lower) || COMMON_PASSWORDS.has(pw)) {
    lines.push({ t: 'found', text: `> [+] MATCH FOUND in dictionary! Password cracked: "${pw}"` });
    lines.push({ t: 'found', text: '> [+] Elapsed time: 0.003s | Attempts: ~1,400' });
    return lines;
  }

  lines.push({ t: 'info', text: '> [-] No match in common list. Proceeding...' });
  lines.push({ t: 'cmd',  text: '> [2] Phase 2: Dictionary + rule-based (l33t substitution, append/prepend)' });

  let foundDict = false;
  for (const w of DICT_WORDS) {
    if (lower.includes(w) && w.length >= 4) {
      const leetVariant = w.replace(/a/g,'@').replace(/e/g,'3').replace(/o/g,'0').replace(/s/g,'$');
      lines.push({ t: 'warn', text: `> [~] Weak signal: base word "${w}" detected via pattern matching` });
      lines.push({ t: 'info', text: `> [i] Generating l33t variants: ${w} → ${leetVariant}` });
      foundDict = true;
      break;
    }
  }
  if (!foundDict) lines.push({ t: 'info', text: '> [-] No dictionary base word found.' });

  if (/[@4]|[0oO][a-z]|[1l!]|[3e]|[5s$]/.test(pw)) {
    lines.push({ t: 'warn', text: '> [~] L33tspeak pattern detected — expanding attack wordlist with substitution rules' });
  }

  if (/(?:19|20)\d{2}/.test(pw)) {
    lines.push({ t: 'warn', text: '> [~] Year pattern — covered by common digit append/prepend hybrid rules' });
  }

  lines.push({ t: 'cmd',  text: '> [3] Phase 3: Markov chain / PCFG probabilistic attack' });
  const score = calcScore(pw);
  if (score < 40) {
    lines.push({ t: 'warn', text: '> [~] Low entropy detected — Markov model converging, expected match soon' });
  } else {
    lines.push({ t: 'info', text: '> [-] Markov probability too low — skipping full Markov walk' });
  }

  lines.push({ t: 'cmd',  text: '> [4] Phase 4: Mask attack (bruteforce with charset constraints)' });
  const bits = Math.round(calcKeyspaceEntropy(pw));
  lines.push({ t: 'info', text: `> [i] Estimated keyspace: 2^${bits} (~${bits < 50 ? 'feasible attack surface' : 'too large for basic brute-force'})` });

  if (bits < 40) {
    lines.push({ t: 'found', text: `> [+] Keyspace exhausted in estimated: ${formatTime(Math.pow(2, bits) / 1e9)}` });
    lines.push({ t: 'found', text: '> [+] Password cracked via brute-force mask attack.' });
  } else if (bits < 60) {
    lines.push({ t: 'warn', text: `> [~] Brute-force feasible with GPU cluster: est. ${formatTime(Math.pow(2, bits) / 1e10)}` });
    lines.push({ t: 'info', text: '> [-] Requires dedicated hardware. Opportunistic attackers would likely abandon.' });
  } else {
    lines.push({ t: 'info', text: `> [-] Keyspace 2^${bits} — est. ${formatTime(Math.pow(2, bits) / 1e10)} even at 10^10/s` });
    lines.push({ t: 'info', text: '> [i] Password is brute-force resistant — only social engineering viable' });
  }

  lines.push({ t: 'cmd', text: '> [*] Attack simulation complete.' });
  return lines;
}

/* ══════════════════════════════════════════════════════════
   MODULE 8: SECURE PASSWORD GENERATOR
   Random, passphrase, and pronounceable modes
══════════════════════════════════════════════════════════ */
const WORDLIST = [
  'correct','horse','battery','staple','cloud','river','forest','storm',
  'pixel','matrix','random','cosmic','gravity','hollow','lantern','bridge',
  'silver','amber','frozen','velvet','crimson','echo','prism','nova','marble',
  'cipher','delta','atlas','orbit','flux','zenith','phantom','vector','nexus',
  'radiant','cobalt','ember','spiral','glacier','torrent','swift','lunar',
  'solar','arctic','sonic','static','pulse','fractal','drift','vortex','quartz',
  'blaze','shade','frost','storm','crest','ridge','peak','vale','grove','bay'
];

/**
 * Cryptographically secure random integer 0..max-1
 */
function secureRandom(max) {
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  return arr[0] % max;
}

/**
 * Generate a fully random high-entropy password
 */
function genRandomPassword(len = 18) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?';
  let pw = '';
  for (let i = 0; i < len; i++) pw += chars[secureRandom(chars.length)];
  return pw;
}

/**
 * Generate a passphrase (correct-horse-battery-staple style)
 */
function genPassphrase(words = 4) {
  const chosen = [];
  for (let i = 0; i < words; i++) chosen.push(WORDLIST[secureRandom(WORDLIST.length)]);
  return chosen.join('-') + '-' + secureRandom(999);
}

/**
 * Generate a pronounceable password (consonant-vowel alternating)
 */
function genPronounceable(len = 14) {
  const consonants = 'bcdfghjklmnprstvwxz';
  const vowels = 'aeiou';
  const specials = '!@#$';
  let pw = '';
  for (let i = 0; i < Math.floor(len / 2) - 1; i++) {
    pw += consonants[secureRandom(consonants.length)];
    pw += vowels[secureRandom(vowels.length)];
  }
  pw += String(secureRandom(90) + 10);
  pw += specials[secureRandom(specials.length)];
  return pw.charAt(0).toUpperCase() + pw.slice(1);
}

/* ══════════════════════════════════════════════════════════
   MODULE 9: HASH DEMONSTRATION
   Educational — shows hashing concepts in-browser
══════════════════════════════════════════════════════════ */

/**
 * Real SHA-256 via Web Crypto API
 */
async function sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Deterministic fake MD5 for demonstration purposes (NOT real MD5)
 */
function fakeMd5(str) {
  let h = 0xd1d2d3d4;
  for (let i = 0; i < str.length; i++) {
    h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
    h ^= (h >>> 16);
  }
  const parts = [];
  let seed = h >>> 0;
  for (let i = 0; i < 4; i++) {
    seed = (Math.imul(seed, 0x5851f42d) + 0xc0b18ccf) | 0;
    parts.push((seed >>> 0).toString(16).padStart(8, '0'));
  }
  return parts.join('');
}

/**
 * BCrypt format simulation (educational — not real bcrypt)
 */
function fakeBcrypt(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = (Math.imul(h, 31) + str.charCodeAt(i)) | 0;
  const salt = Math.abs(h ^ 0xfeed1234).toString(36).padStart(22, 'a').slice(0, 22);
  const hash = Math.abs(h ^ 0xdeadbeef).toString(36).padStart(31, 'b').slice(0, 31);
  return `$2b$12$${salt}${hash}`;
}

/* ══════════════════════════════════════════════════════════
   MODULE 10: UI CONTROLLER
   DOM updates, tab switching, event handling
══════════════════════════════════════════════════════════ */

let activeTab = 'analysis';
let currentPw = '';
let showingPw = false;

/** Map score → visual style metadata */
function strengthMeta(score) {
  if (score >= 80) return { label: 'Strong',   color: '#06d6a0', bg: '#06d6a018', border: '#06d6a033' };
  if (score >= 60) return { label: 'Good',     color: '#4f9eff', bg: '#4f9eff18', border: '#4f9eff33' };
  if (score >= 40) return { label: 'Moderate', color: '#ffd32a', bg: '#ffd32a18', border: '#ffd32a33' };
  if (score >= 20) return { label: 'Weak',     color: '#ff7849', bg: '#ff784918', border: '#ff784933' };
  return            { label: 'Critical', color: '#ff4757', bg: '#ff475718', border: '#ff475733' };
}

/** Update the strength meter bar and score display */
function updateMeter(pw) {
  const score = calcScore(pw);
  const meta = strengthMeta(score);
  const fill = document.getElementById('meterFill');
  fill.style.width = (pw.length ? score : 0) + '%';
  fill.style.background = pw.length
    ? `linear-gradient(90deg,${score < 40 ? '#ff4757' : score < 60 ? '#ffd32a' : '#06d6a0'},${meta.color})`
    : '';
  const sv = document.getElementById('scoreVal');
  sv.textContent = pw.length ? score : '—';
  sv.style.color = pw.length ? meta.color : '';
  const sl = document.getElementById('strengthLabel');
  sl.textContent = pw.length ? meta.label : 'Enter password';
  sl.style.cssText = pw.length
    ? `background:${meta.bg};border:1px solid ${meta.border};color:${meta.color};padding:2px 10px`
    : '';
  return score;
}

/** Update the 4-stat summary grid */
function updateStats(pw) {
  const grid = document.getElementById('statsGrid');
  if (!pw.length) { grid.style.display = 'none'; return; }
  const ks = calcKeyspaceEntropy(pw);
  const sh = calcShannonEntropy(pw);
  const uq = new Set(pw).size;
  const types = [/[a-z]/, /[A-Z]/, /\d/, /[!@#$%^&*()_+\-=\[\]{};':",.<>?\/\\`~]/].filter(r => r.test(pw)).length;
  grid.style.display = 'grid';
  grid.innerHTML = `
    <div class="stat-card"><div class="stat-label">Length</div><div class="stat-val" style="color:#4f9eff">${pw.length}</div><div class="stat-sub">${uq} unique chars</div></div>
    <div class="stat-card"><div class="stat-label">Keyspace Entropy</div><div class="stat-val" style="color:#7c3aed">${Math.round(ks)}</div><div class="stat-sub">bits total</div></div>
    <div class="stat-card"><div class="stat-label">Shannon Entropy</div><div class="stat-val" style="color:#06d6a0">${sh.toFixed(2)}</div><div class="stat-sub">bits/char</div></div>
    <div class="stat-card"><div class="stat-label">Char Classes</div><div class="stat-val" style="color:#ffd32a">${types}/4</div><div class="stat-sub">lower·upper·digit·sym</div></div>
  `;
}

/** Update the AI feedback list */
function updateAnalysis(pw) {
  if (!pw.length) return;
  const score = calcScore(pw);
  const patterns = detectPatterns(pw);
  const feedback = generateFeedback(pw, score, patterns);
  document.getElementById('feedbackList').innerHTML = feedback.map(f => `
    <li class="feedback-item ${f.type === 'critical' || f.type === 'bad' ? 'bad' : f.type === 'warn' ? 'warn' : 'ok'}">
      <span class="fi-icon">${f.icon}</span>
      <span>${f.text}</span>
    </li>`).join('');
}

/** Render per-character entropy visualization */
function updateEntropy(pw) {
  if (!pw.length || activeTab !== 'entropy') return;
  const entropies = getCharEntropies(pw);
  const maxE = Math.max(...entropies, 0.001);
  const typeColors = { lower: '#4f9eff', upper: '#7c3aed', digit: '#ffd32a', symbol: '#06d6a0' };

  document.getElementById('charGrid').innerHTML = pw.split('').map((c, i) => {
    const t = getCharType(c);
    const col = typeColors[t];
    const alpha = 0.2 + 0.7 * (entropies[i] / maxE);
    const hex = Math.round(alpha * 255).toString(16).padStart(2, '0');
    return `<div class="char-box" style="background:${col}${hex};color:${col};border:1px solid ${col}44" title="${t} · ${entropies[i].toFixed(2)} bits">${c === ' ' ? '_' : c}</div>`;
  }).join('');

  document.getElementById('entropyBars').innerHTML = pw.split('').map((c, i) => {
    const h = Math.max(4, Math.round((entropies[i] / maxE) * 56));
    const t = getCharType(c);
    return `<div class="ebar" style="height:${h}px;background:${typeColors[t]}" title="${c}: ${entropies[i].toFixed(2)} bits"></div>`;
  }).join('');
}

/** Render crack-time estimates for all attack models */
function updateCrack(pw) {
  if (!pw.length || activeTab !== 'crack') return;
  const ks = calcKeyspaceEntropy(pw);
  const guesses = Math.pow(2, ks);
  document.getElementById('attackRows').innerHTML = ATTACK_MODELS.map(m => {
    const secs = guesses / (m.speed * 2); // average case = half keyspace
    const pct = Math.min(98, Math.max(2, (1 - (Math.log10(secs + 1) / Math.log10(1e15))) * 100));
    const barColor = secs < 3600 ? '#ff4757' : secs < 86400 * 365 ? '#ffd32a' : '#06d6a0';
    return `<div class="attack-row">
      <div class="attack-name">${m.name}<div style="font-size:10px;color:var(--text3);font-weight:400">${m.label}</div></div>
      <div class="attack-bar-wrap"><div class="attack-bar" style="width:${100 - pct}%;background:${barColor}"></div></div>
      <div class="attack-time" style="color:${barColor}">${formatTime(secs)}</div>
    </div>`;
  }).join('');
}

/** Render attacker simulation terminal */
function updateSim(pw) {
  if (!pw.length || activeTab !== 'attacker') return;
  const lines = runAttackerSim(pw);
  const term = document.getElementById('simTerminal');
  term.innerHTML = lines.map(l => `<div class="sim-line ${l.t}">${l.text}</div>`).join('');
  term.scrollTop = term.scrollHeight;
}

/** Render password suggestions */
function generateSuggestions() {
  if (activeTab !== 'suggest') return;
  const options = [
    { pw: genRandomPassword(20), type: 'Random · 20 chars' },
    { pw: genRandomPassword(24), type: 'Random · 24 chars' },
    { pw: genPassphrase(4),      type: 'Passphrase · 4 words' },
    { pw: genPassphrase(5),      type: 'Passphrase · 5 words' },
    { pw: genPronounceable(14),  type: 'Pronounceable · 14 chars' },
    { pw: genPronounceable(16),  type: 'Pronounceable · 16 chars' },
  ];
  document.getElementById('suggestList').innerHTML = options.map(o => `
    <div class="pw-option" onclick="copyPassword(this,'${o.pw.replace(/\\/g,'\\\\').replace(/'/g,"\\'")}')">
      <span class="pw-option-text">${o.pw}</span>
      <span class="pw-option-badge">${o.type}</span>
    </div>`).join('');
}

/** Copy a suggested password to clipboard */
function copyPassword(el, pw) {
  navigator.clipboard.writeText(pw).then(() => {
    const badge = el.querySelector('.pw-option-badge');
    const orig = badge.textContent;
    el.style.borderColor = '#06d6a044';
    badge.textContent = 'Copied!';
    setTimeout(() => {
      el.style.borderColor = '';
      badge.textContent = orig;
    }, 1500);
  });
}

/** Compute and display hashes */
async function updateHashes(pw) {
  if (!pw.length || activeTab !== 'hash') return;
  document.getElementById('hashSha256').textContent = 'computing...';
  document.getElementById('hashMd5').textContent = fakeMd5(pw);
  document.getElementById('hashBcrypt').textContent = fakeBcrypt(pw);
  const real = await sha256(pw);
  document.getElementById('hashSha256').textContent = real;
}

/** Switch between analysis tabs */
function showTab(name) {
  document.querySelectorAll('.tab').forEach((t, i) => {
    const tabs = ['analysis','entropy','crack','attacker','suggest','hash'];
    t.classList.toggle('active', tabs[i] === name);
  });
  ['analysis','entropy','crack','attacker','suggest','hash'].forEach(t => {
    const el = document.getElementById('tab-' + t);
    if (el) el.style.display = t === name ? 'block' : 'none';
  });
  activeTab = name;
  if (currentPw) {
    if (name === 'entropy')  updateEntropy(currentPw);
    if (name === 'crack')    updateCrack(currentPw);
    if (name === 'attacker') updateSim(currentPw);
    if (name === 'suggest')  generateSuggestions();
    if (name === 'hash')     updateHashes(currentPw);
  }
}

/** Master analysis function — called on every keystroke */
function analyze(pw) {
  currentPw = pw;
  const isEmpty = !pw.length;
  document.getElementById('mainContent').style.display = isEmpty ? 'none' : 'block';
  document.getElementById('emptyState').style.display = isEmpty ? 'block' : 'none';

  if (isEmpty) {
    document.getElementById('statsGrid').style.display = 'none';
    document.getElementById('meterFill').style.cssText = 'width:0%';
    document.getElementById('scoreVal').textContent = '—';
    document.getElementById('scoreVal').style.color = '';
    document.getElementById('strengthLabel').textContent = 'Enter password';
    document.getElementById('strengthLabel').style.cssText = '';
    return;
  }

  updateMeter(pw);
  updateStats(pw);
  updateAnalysis(pw);
  if (activeTab === 'entropy')  updateEntropy(pw);
  if (activeTab === 'crack')    updateCrack(pw);
  if (activeTab === 'attacker') updateSim(pw);
  if (activeTab === 'hash')     updateHashes(pw);
}

/* ── Event Listeners ── */
document.getElementById('pwInput').addEventListener('input', e => analyze(e.target.value));

document.getElementById('toggleBtn').addEventListener('click', () => {
  showingPw = !showingPw;
  document.getElementById('pwInput').type = showingPw ? 'text' : 'password';
  document.getElementById('toggleBtn').textContent = showingPw ? '🙈' : '👁';
});

document.getElementById('clearBtn').addEventListener('click', () => {
  document.getElementById('pwInput').value = '';
  analyze('');
});

// Expose showTab and other functions globally for onclick handlers
window.showTab = showTab;
window.generateSuggestions = generateSuggestions;
window.copyPassword = copyPassword;
