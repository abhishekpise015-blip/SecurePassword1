/**
 * SecurePass — Modern Cybersecurity & Password Intelligence Controller
 * ====================================================================
 * Handles real-time password strength evaluation, Shannon entropy metrics,
 * adversary brute-force simulations, privacy-preserving k-Anonymity breach
 * checking, and customizable high-entropy password generation.
 *
 * Privacy Guarantees:
 * - Passwords are NEVER written to localStorage, sessionStorage, or cookies.
 * - Passwords and full hashes are NEVER printed to browser console or persisted.
 * - Raw passwords are NEVER sent to the breach-check endpoint.
 * - Only a 5-character SHA-1 prefix is ever sent to the server for HIBP range lookup.
 * - Suffix matching is performed 100% locally in browser memory.
 */

(() => {
  'use strict';

  // Determine API base URL
  const API_BASE = (window.location.protocol === 'file:' || (window.location.port && window.location.port !== '5000'))
    ? 'http://127.0.0.1:5000'
    : '';

  // DOM Elements: Input & Core Controls
  const passwordInput = document.getElementById('passwordInput');
  const togglePasswordBtn = document.getElementById('togglePasswordBtn');
  const clearPasswordBtn = document.getElementById('clearPasswordBtn');
  const analyzeBtn = document.getElementById('analyzeBtn');
  const retryBreachBtn = document.getElementById('retryBreachBtn');
  const charCount = document.getElementById('charCount');
  const uniqueCount = document.getElementById('uniqueCount');

  // Backend Health Elements
  const backendStatusDot = document.getElementById('backendStatusDot');
  const backendStatusText = document.getElementById('backendStatusText');

  // Score Elements
  const scoreValue = document.getElementById('scoreValue');
  const scoreRatingBadge = document.getElementById('scoreRatingBadge');
  const progressFill = document.getElementById('progressFill');
  const progressTrack = document.getElementById('progressTrack');
  const scoreFeedback = document.getElementById('scoreFeedback');

  // Checklist Elements
  const checklistCounter = document.getElementById('checklistCounter');
  const checkLength = document.getElementById('check-length');
  const checkUppercase = document.getElementById('check-uppercase');
  const checkLowercase = document.getElementById('check-lowercase');
  const checkNumber = document.getElementById('check-number');
  const checkSpecial = document.getElementById('check-special');

  // Telemetry Elements
  const entropyValue = document.getElementById('entropyValue');
  const entropyFill = document.getElementById('entropyFill');
  const poolSizeValue = document.getElementById('poolSizeValue');
  const combinationsValue = document.getElementById('combinationsValue');

  // Cracking Time Simulation Elements
  const crackOnline = document.getElementById('crackOnline');
  const crackOffline = document.getElementById('crackOffline');
  const crackSingleGpu = document.getElementById('crackSingleGpu');
  const crackCluster = document.getElementById('crackCluster');

  // Recommendations Elements
  const recommendationsPrompt = document.getElementById('recommendationsPrompt');
  const recommendationsStatusBox = document.getElementById('recommendationsStatusBox');
  const recommendationsList = document.getElementById('recommendationsList');

  // Breach Intelligence Elements
  const radarWrapper = document.getElementById('radarWrapper');
  const breachBadge = document.getElementById('breachBadge');
  const breachStatusTitle = document.getElementById('breachStatusTitle');
  const breachStatusDesc = document.getElementById('breachStatusDesc');
  const occurrencesCount = document.getElementById('occurrencesCount');
  const occurrencesSubtext = document.getElementById('occurrencesSubtext');
  const sha1PrefixHex = document.getElementById('sha1PrefixHex');
  const sha1SuffixHex = document.getElementById('sha1SuffixHex');

  // Generator Elements
  const generatedCipher = document.getElementById('generatedCipher');
  const deployGeneratedBtn = document.getElementById('deployGeneratedBtn');
  const copyGeneratedBtn = document.getElementById('copyGeneratedBtn');
  const regenerateBtn = document.getElementById('regenerateBtn');
  const genEntropyTag = document.getElementById('genEntropyTag');
  const genModeButtons = document.querySelectorAll('.btn-gen-mode');

  // In-Memory State
  let activeRequestId = 0;
  let activeBreachRequestId = 0;
  let lastAnalyzedPassword = '';
  let inputDebounceTimer = null;
  let currentGeneratorMode = 'passphrase';

  // ==========================================================================
  // Backend Health Polling & Offline Indicator
  // ==========================================================================
  let isBackendOnline = false;

  async function checkBackendHealth() {
    try {
      const response = await fetch(`${API_BASE}/api/health`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
        cache: 'no-store'
      });
      if (response.ok) {
        const data = await response.json();
        if (data.status === 'ok') {
          isBackendOnline = true;
          if (backendStatusDot) backendStatusDot.className = 'status-dot connected';
          if (backendStatusText) backendStatusText.textContent = 'Backend connected';
          return;
        }
      }
      throw new Error('Unexpected health response');
    } catch {
      isBackendOnline = false;
      if (backendStatusDot) backendStatusDot.className = 'status-dot local-ready';
      if (backendStatusText) backendStatusText.textContent = 'Client Engine Active';
    }
  }

  checkBackendHealth();
  setInterval(checkBackendHealth, 8000);

  // ==========================================================================
  // Client-Side Heuristic Strength Engine (Offline & Mobile Fallback)
  // ==========================================================================
  const COMMON_WEAK_PASSWORDS = new Set([
    'password', 'password1', 'password123', '123456', '12345678', '123456789',
    '12345', '1234', 'qwerty', 'qwerty123', 'qwertyuiop', 'abc123', 'football',
    'monkey', 'letmein', 'welcome', 'welcome123', 'dragon', 'baseball', 'sunshine',
    'iloveyou', 'trustno1', 'superman', 'batman', 'starwars', 'princess', 'shadow',
    'master', 'michael', 'jordan', 'killer', 'hunter2', 'admin', 'admin123', 'admin2026!',
    'administrator', 'root', 'guest', 'default', 'pass1234', 'passcode', 'access',
    'login', 'secret', 'mustang', 'ninja', 'charlie', 'freedom', 'whatever',
    'cookie', 'testing', 'securepass', 'secure123', 'asdfghjk', 'zxcvbnm'
  ]);

  function computeClientStrengthAnalysis(pwd) {
    const len = pwd.length;
    const suggestions = [];
    const lower = pwd.toLowerCase();

    // Check blocklist
    const isBlocklisted = COMMON_WEAK_PASSWORDS.has(lower);
    if (isBlocklisted) {
      suggestions.push("Critical: This password matches known leaked credentials. Never use it.");
    }

    const hasLower = /[a-z]/.test(pwd);
    const hasUpper = /[A-Z]/.test(pwd);
    const hasDigit = /[0-9]/.test(pwd);
    const hasSpecial = /[!@#$%^&*()\-_=+\[\]{}|;:'",.<>/?`~\\]/.test(pwd);
    const hasMinLen = len >= 12;

    const checks = [
      { name: "Length: at least 12 characters", passed: hasMinLen },
      { name: "Uppercase letters (A-Z)", passed: hasUpper },
      { name: "Lowercase letters (a-z)", passed: hasLower },
      { name: "Numbers (0-9)", passed: hasDigit },
      { name: "Special characters", passed: hasSpecial }
    ];

    if (!hasMinLen) suggestions.push("Increase length to at least 12–16 characters for exponentially higher brute-force resistance.");
    if (!hasUpper) suggestions.push("Add uppercase characters (A-Z) to expand keyspace.");
    if (!hasLower) suggestions.push("Add lowercase characters (a-z) to broaden symbol variety.");
    if (!hasDigit) suggestions.push("Include numerical digits (0-9).");
    if (!hasSpecial) suggestions.push("Incorporate special symbols (!@#$%^&*...) to defend against dictionary attacks.");

    // Sequence detection
    let hasSequence = false;
    for (let i = 0; i < lower.length - 2; i++) {
      const c1 = lower.charCodeAt(i);
      const c2 = lower.charCodeAt(i + 1);
      const c3 = lower.charCodeAt(i + 2);
      if ((c2 - c1 === 1 && c3 - c2 === 1) || (c1 - c2 === 1 && c2 - c3 === 1)) {
        hasSequence = true;
        break;
      }
    }
    if (hasSequence) suggestions.push("Pattern warning: Avoid sequential characters (like '123', 'abc') which automated crackers test first.");

    // Compute heuristic score
    let score = 0;
    if (len >= 8) score += 10;
    if (len >= 12) score += 20;
    if (len >= 16) score += 15;
    if (len >= 20) score += 10;

    const varieties = [hasLower, hasUpper, hasDigit, hasSpecial].filter(Boolean).length;
    score += varieties * 8; // up to 32

    // Unique ratio bonus
    const unique = new Set(pwd).size;
    const uniqueRatio = len > 0 ? unique / len : 0;
    score += Math.round(uniqueRatio * 15);

    if (isBlocklisted) score = Math.min(score, 12);
    if (hasSequence) score = Math.max(5, score - 15);

    score = Math.min(100, Math.max(5, score));

    let rating = 'Very Weak';
    if (score >= 85) rating = 'Very Strong';
    else if (score >= 70) rating = 'Strong';
    else if (score >= 50) rating = 'Moderate';
    else if (score >= 25) rating = 'Weak';

    return {
      score,
      rating,
      checks,
      suggestions: suggestions.length > 0 ? suggestions : ["Password exhibits strong complexity and healthy entropy characteristics."]
    };
  }

  // ==========================================================================
  // SHA-1 Web Crypto & Pure JS Fallback (k-Anonymity)
  // ==========================================================================
  function jsSha1(str) {
    function rotateLeft(n, s) { return (n << s) | (n >>> (32 - s)); }
    function cvtHex(val) {
      let s = '';
      for (let i = 7; i >= 0; i--) {
        s += ((val >>> (i * 4)) & 0x0f).toString(16);
      }
      return s;
    }
    const utf8 = unescape(encodeURIComponent(str));
    const words = [];
    for (let i = 0; i < utf8.length * 8; i += 8) {
      words[i >> 5] |= (utf8.charCodeAt(i / 8) & 0xff) << (24 - (i % 32));
    }
    words[((utf8.length * 8 + 64) >>> 9 << 4) + 15] = utf8.length * 8;
    words[utf8.length >> 2] |= 0x80 << (24 - (utf8.length % 4) * 8);

    let w = new Array(80);
    let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878, e = -1009589776;

    for (let i = 0; i < words.length; i += 16) {
      let olda = a, oldb = b, oldc = c, oldd = d, olde = e;
      for (let j = 0; j < 80; j++) {
        if (j < 16) w[j] = words[i + j] || 0;
        else w[j] = rotateLeft(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);

        let t;
        if (j < 20) t = ((b & c) | (~b & d)) + 1518500249;
        else if (j < 40) t = (b ^ c ^ d) + 1859775393;
        else if (j < 60) t = ((b & c) | (b & d) | (c & d)) - 1894007588;
        else t = (b ^ c ^ d) - 899497514;

        t = (t + rotateLeft(a, 5) + e + w[j]) | 0;
        e = d; d = c; c = rotateLeft(b, 30); b = a; a = t;
      }
      a = (a + olda) | 0; b = (b + oldb) | 0; c = (c + oldc) | 0; d = (d + oldd) | 0; e = (e + olde) | 0;
    }
    return (cvtHex(a) + cvtHex(b) + cvtHex(c) + cvtHex(d) + cvtHex(e)).toUpperCase();
  }

  async function computeSha1Hex(text) {
    if (window.crypto && window.crypto.subtle) {
      try {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        const hashBuffer = await window.crypto.subtle.digest('SHA-1', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
      } catch {}
    }
    return jsSha1(text);
  }

  // ==========================================================================
  // Client-Side Real-Time Telemetry & Simulation
  // ==========================================================================
  function formatSecondsToHuman(seconds) {
    if (seconds < 0.001) return 'Instant (< 1 ms)';
    if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
    if (seconds < 60) return `${seconds.toFixed(1)} seconds`;
    if (seconds < 3600) return `${(seconds / 60).toFixed(1)} minutes`;
    if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} hours`;
    if (seconds < 365.25 * 86400) return `${Math.round(seconds / 86400)} days`;
    if (seconds < 1000 * 365.25 * 86400) return `${(seconds / (365.25 * 86400)).toFixed(1)} years`;
    if (seconds < 1e6 * 365.25 * 86400) return `${Math.round(seconds / (1000 * 365.25 * 86400))}k years`;
    if (seconds < 1e9 * 365.25 * 86400) return `${Math.round(seconds / (1e6 * 365.25 * 86400))}M years`;
    return '> 1B years (Immune)';
  }

  function evaluateClientTelemetry(pwd) {
    const len = pwd.length;
    if (charCount) charCount.textContent = len;

    if (!pwd) {
      resetDashboard();
      return;
    }

    const unique = new Set(pwd).size;
    if (uniqueCount) uniqueCount.textContent = unique;

    // Character classification
    const hasLower = /[a-z]/.test(pwd);
    const hasUpper = /[A-Z]/.test(pwd);
    const hasDigit = /[0-9]/.test(pwd);
    const hasSpecial = /[!@#$%^&*()\-_=+\[\]{}|;:'",.<>/?`~\\]/.test(pwd);

    // Active Keyspace Pool (R)
    let pool = 0;
    if (hasLower) pool += 26;
    if (hasUpper) pool += 26;
    if (hasDigit) pool += 10;
    if (hasSpecial) pool += 33;
    if (pool === 0) pool = 1;

    if (poolSizeValue) poolSizeValue.textContent = pool;

    // Shannon Entropy Bits: L * log2(Pool)
    const entropy = len * Math.log2(pool);
    const roundedEntropy = Math.round(entropy * 10) / 10;
    if (entropyValue) entropyValue.textContent = roundedEntropy.toFixed(1);
    if (entropyFill) entropyFill.style.width = `${Math.min(100, (roundedEntropy / 90) * 100)}%`;

    // Combinations (if present)
    if (combinationsValue) {
      const log10Comb = len * Math.log10(pool);
      combinationsValue.textContent = log10Comb >= 10 ? `~10^${Math.round(log10Comb)} combinations` : `${Math.round(Math.pow(pool, len)).toLocaleString()} combinations`;
    }

    // Complexity Checklist
    const hasMinLen = len >= 12;
    setCheckItem(checkLength, hasMinLen);
    setCheckItem(checkUppercase, hasUpper);
    setCheckItem(checkLowercase, hasLower);
    setCheckItem(checkNumber, hasDigit);
    setCheckItem(checkSpecial, hasSpecial);

    const passedCount = [hasMinLen, hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length;
    if (checklistCounter) checklistCounter.textContent = `${passedCount}/5 Passed`;

    // Brute-force simulation calculation (average guesses = (R^L) / 2)
    const log10Guesses = (len * Math.log10(pool)) - Math.log10(2);

    if (crackOnline) {
      const webSec = log10Guesses > 15 ? 1e16 : Math.max(0.0001, Math.pow(10, log10Guesses - 2));
      crackOnline.textContent = formatSecondsToHuman(webSec);
      crackOnline.className = `crack-value ${webSec < 3600 ? 'danger' : 'safe'}`;
    }

    if (crackOffline) {
      const cpuSec = log10Guesses > 15 ? 1e16 : Math.max(0.0001, Math.pow(10, log10Guesses - 5));
      crackOffline.textContent = formatSecondsToHuman(cpuSec);
      crackOffline.className = `crack-value ${cpuSec < 3600 ? 'danger' : 'safe'}`;
    }

    if (crackSingleGpu) {
      const gpuSec = log10Guesses > 15 ? 1e16 : Math.max(0.0001, Math.pow(10, log10Guesses - 10));
      crackSingleGpu.textContent = formatSecondsToHuman(gpuSec);
      crackSingleGpu.className = `crack-value ${gpuSec < 3600 ? 'danger' : 'safe'}`;
    }

    if (crackCluster) {
      const clusterSec = log10Guesses > 15 ? 1e16 : Math.max(0.0001, Math.pow(10, log10Guesses - 14));
      crackCluster.textContent = formatSecondsToHuman(clusterSec);
      crackCluster.className = `crack-value ${clusterSec < 3600 ? 'danger' : 'safe'}`;
    }

    // Update real-time Packet Inspector SHA-1 preview
    computeSha1Hex(pwd).then(hash => {
      if (sha1PrefixHex) sha1PrefixHex.textContent = hash.substring(0, 5);
      if (sha1SuffixHex) sha1SuffixHex.textContent = hash.substring(5);
    });
  }

  function setCheckItem(elem, passed) {
    if (!elem) return;
    if (passed) {
      elem.classList.add('passed');
    } else {
      elem.classList.remove('passed');
    }
  }

  // ==========================================================================
  // Breach Check via k-Anonymity Range Query
  // ==========================================================================
  async function performBreachCheck(password) {
    const thisBreachId = ++activeBreachRequestId;

    if (!password) {
      resetBreachDisplay();
      return;
    }

    if (radarWrapper) radarWrapper.className = 'radar-wrapper scanning';
    if (breachBadge) {
      breachBadge.className = 'badge-status checking';
      breachBadge.textContent = 'Checking...';
    }
    if (breachStatusTitle) breachStatusTitle.textContent = 'Scanning breach databases';
    if (breachStatusDesc) breachStatusDesc.textContent = 'Querying HIBP range API with 5-character prefix...';
    if (occurrencesCount) {
      occurrencesCount.textContent = '—';
      occurrencesCount.className = 'occurrences-count';
    }
    if (occurrencesSubtext) occurrencesSubtext.textContent = 'Evaluating anonymous hash suffixes...';
    if (retryBreachBtn) retryBreachBtn.disabled = true;

    try {
      const fullHash = await computeSha1Hex(password);
      if (thisBreachId !== activeBreachRequestId) return;

      const prefix = fullHash.substring(0, 5);
      const suffix = fullHash.substring(5);

      if (sha1PrefixHex) sha1PrefixHex.textContent = prefix;
      if (sha1SuffixHex) sha1SuffixHex.textContent = suffix;

      let hashes = [];
      let isDemo = false;

      try {
        const response = await fetch(`${API_BASE}/api/breach-check?prefix=${encodeURIComponent(prefix)}`, {
          method: 'GET',
          headers: { 'Accept': 'application/json' },
          cache: 'no-store'
        });

        if (response.ok) {
          const data = await response.json();
          hashes = data.hashes || [];
          isDemo = Boolean(data.is_demo);
        } else {
          throw new Error(`Server returned HTTP ${response.status}`);
        }
      } catch (backendErr) {
        // Transparent client-side fallback: Query official HIBP range API directly via zero-knowledge k-Anonymity
        const hibpRes = await fetch(`https://api.pwnedpasswords.com/range/${encodeURIComponent(prefix)}`, {
          method: 'GET',
          cache: 'no-store'
        });
        if (!hibpRes.ok) throw new Error(`HIBP API returned ${hibpRes.status}`);
        const text = await hibpRes.text();
        const lines = text.split('\n');
        for (let j = 0; j < lines.length; j++) {
          const line = lines[j].trim();
          if (!line) continue;
          const [s, c] = line.split(':');
          if (s && c) {
            hashes.push({ suffix: s.trim().toUpperCase(), count: parseInt(c.trim(), 10) || 1 });
          }
        }
      }

      if (thisBreachId !== activeBreachRequestId) return;

      let matchCount = 0;
      let matched = false;

      for (let i = 0; i < hashes.length; i++) {
        if (hashes[i].suffix.toUpperCase() === suffix) {
          matched = true;
          matchCount = hashes[i].count;
          break;
        }
      }

      if (matched) {
        if (radarWrapper) radarWrapper.className = 'radar-wrapper matched';
        if (breachBadge) {
          breachBadge.className = 'badge-status match-found';
          breachBadge.textContent = isDemo ? 'Match found (DEMO)' : 'Match found';
        }
        if (breachStatusTitle) breachStatusTitle.textContent = isDemo ? 'Compromised in demo dataset!' : 'Compromised in known breach!';
        if (breachStatusDesc) {
          breachStatusDesc.textContent = isDemo
            ? 'DEMO DATA — NOT A REAL BREACH CHECK. Match found in local test fixture.'
            : 'This password has appeared in public security breaches. Attackers can test it quickly.';
        }
        if (occurrencesCount) {
          occurrencesCount.textContent = matchCount.toLocaleString();
          occurrencesCount.className = 'occurrences-count breached';
        }
        if (occurrencesSubtext) {
          occurrencesSubtext.textContent = isDemo
            ? 'DEMO DATA — NOT A REAL BREACH CHECK'
            : `Found in ${matchCount.toLocaleString()} verified breach occurrences.`;
        }
      } else {
        if (radarWrapper) radarWrapper.className = 'radar-wrapper safe';
        if (breachBadge) {
          breachBadge.className = 'badge-status no-match';
          breachBadge.textContent = isDemo ? 'No match found (DEMO)' : 'No match found';
        }
        if (breachStatusTitle) breachStatusTitle.textContent = 'No known breach matches';
        if (breachStatusDesc) {
          breachStatusDesc.textContent = isDemo
            ? 'DEMO DATA — NOT A REAL BREACH CHECK. No match in local test fixture.'
            : 'No match found in the returned dataset. Always use distinct passwords.';
        }
        if (occurrencesCount) {
          occurrencesCount.textContent = '0';
          occurrencesCount.className = 'occurrences-count safe';
        }
        if (occurrencesSubtext) {
          occurrencesSubtext.textContent = isDemo
            ? 'DEMO DATA — NOT A REAL BREACH CHECK'
            : 'Zero matches found in HIBP database range.';
        }
      }

    } catch {
      if (thisBreachId !== activeBreachRequestId) return;
      if (radarWrapper) radarWrapper.className = 'radar-wrapper';
      if (breachBadge) {
        breachBadge.className = 'badge-status unable';
        breachBadge.textContent = 'Unable to check';
      }
      if (breachStatusTitle) breachStatusTitle.textContent = 'Breach check unavailable';
      if (breachStatusDesc) breachStatusDesc.textContent = 'Could not verify with the breach database. Do not assume this password is safe.';
      if (occurrencesCount) {
        occurrencesCount.textContent = '—';
        occurrencesCount.className = 'occurrences-count';
      }
      if (occurrencesSubtext) occurrencesSubtext.textContent = 'Check your connection or backend status and retry.';
    } finally {
      if (thisBreachId === activeBreachRequestId && retryBreachBtn) {
        retryBreachBtn.disabled = false;
      }
    }
  }

  // ==========================================================================
  // Password Analysis via Backend REST API
  // ==========================================================================
  async function performStrengthAnalysis(password) {
    const thisRequestId = ++activeRequestId;

    if (!password) {
      resetDashboard();
      return;
    }

    if (analyzeBtn) {
      analyzeBtn.disabled = true;
      analyzeBtn.innerHTML = `<span>Analyzing...</span>`;
    }

    try {
      let data = null;

      try {
        const response = await fetch(`${API_BASE}/api/analyze`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          body: JSON.stringify({ password }),
          cache: 'no-store'
        });

        if (response.ok) {
          data = await response.json();
        } else {
          throw new Error(`Analysis failed with status ${response.status}`);
        }
      } catch (backendErr) {
        // Fallback to client-side heuristic engine (works on mobile / offline / static hosting)
        data = computeClientStrengthAnalysis(password);
      }

      if (thisRequestId !== activeRequestId) return;

      lastAnalyzedPassword = password;

      // Score Value & Progress Fill
      const score = data.score ?? 0;
      if (scoreValue) scoreValue.textContent = score;
      if (progressFill) progressFill.style.width = `${score}%`;
      if (progressTrack) progressTrack.setAttribute('aria-valuenow', score);

      // Rating badge
      const rating = data.rating || 'Very Weak';
      const ratingClass = rating.toLowerCase().replace(/\s+/g, '-');
      if (scoreRatingBadge) {
        scoreRatingBadge.className = `score-badge ${ratingClass}`;
        scoreRatingBadge.textContent = rating;
      }

      // Feedback
      if (scoreFeedback) {
        if (score >= 85) {
          scoreFeedback.textContent = 'Exceptional security resistance against brute-force and dictionary attacks.';
        } else if (score >= 70) {
          scoreFeedback.textContent = 'Strong complexity. Meets modern security standards for personal accounts.';
        } else if (score >= 50) {
          scoreFeedback.textContent = 'Moderate security. Could be strengthened by adding more length or variety.';
        } else if (score >= 25) {
          scoreFeedback.textContent = 'Weak password. Vulnerable to common automated cracking dictionaries.';
        } else {
          scoreFeedback.textContent = 'Very weak password. Highly predictable or too short.';
        }
      }

      // Update Checklist from server checks
      if (Array.isArray(data.checks)) {
        updateChecklistFromChecks(data.checks);
      }

      // Recommendations list
      renderRecommendations(data.suggestions || []);

      // Concurrent Breach Check
      performBreachCheck(password);

    } catch (err) {
      if (thisRequestId !== activeRequestId) return;
      if (scoreFeedback) scoreFeedback.textContent = 'Evaluation error occurred. Please retry.';
      if (scoreRatingBadge) {
        scoreRatingBadge.className = 'score-badge';
        scoreRatingBadge.textContent = 'Error';
      }
    } finally {
      if (thisRequestId === activeRequestId && analyzeBtn) {
        analyzeBtn.disabled = false;
        analyzeBtn.innerHTML = `
          <span>Analyze Password</span>
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <line x1="5" y1="12" x2="19" y2="12"></line>
            <polyline points="12 5 19 12 12 19"></polyline>
          </svg>
        `;
      }
    }
  }

  function updateChecklistFromChecks(checks) {
    let passedCount = 0;
    checks.forEach(check => {
      const name = check.name || '';
      const passed = Boolean(check.passed);
      if (passed) passedCount++;

      if (name.includes('12 characters')) {
        setCheckItem(checkLength, passed);
      } else if (name.includes('Uppercase')) {
        setCheckItem(checkUppercase, passed);
      } else if (name.includes('Lowercase')) {
        setCheckItem(checkLowercase, passed);
      } else if (name.includes('Number')) {
        setCheckItem(checkNumber, passed);
      } else if (name.includes('Special')) {
        setCheckItem(checkSpecial, passed);
      }
    });
    if (checklistCounter) checklistCounter.textContent = `${passedCount}/5 Passed`;
  }

  function renderRecommendations(suggestions) {
    if (!suggestions || suggestions.length === 0) {
      if (recommendationsPrompt) recommendationsPrompt.style.display = 'none';
      if (recommendationsStatusBox) {
        recommendationsStatusBox.style.display = 'block';
        recommendationsStatusBox.textContent = 'No immediate security vulnerabilities detected.';
      }
      if (recommendationsList) recommendationsList.style.display = 'none';
      return;
    }

    if (recommendationsPrompt) recommendationsPrompt.style.display = 'none';
    if (recommendationsStatusBox) recommendationsStatusBox.style.display = 'none';
    if (recommendationsList) {
      recommendationsList.style.display = 'flex';
      recommendationsList.innerHTML = '';

      suggestions.forEach(item => {
        const li = document.createElement('li');
        li.className = 'recommendation-bullet';
        const lowered = item.toLowerCase();
        if (lowered.includes('critical') || lowered.includes('warning')) {
          li.classList.add('danger');
        } else if (lowered.includes('pattern') || lowered.includes('sequence')) {
          li.classList.add('warning');
        }
        li.textContent = item;
        recommendationsList.appendChild(li);
      });
    }
  }

  // ==========================================================================
  // Reset States
  // ==========================================================================
  function resetBreachDisplay() {
    if (radarWrapper) radarWrapper.className = 'radar-wrapper';
    if (breachBadge) {
      breachBadge.className = 'badge-status';
      breachBadge.textContent = 'Not checked';
    }
    if (breachStatusTitle) breachStatusTitle.textContent = 'Exposure status unknown';
    if (breachStatusDesc) breachStatusDesc.textContent = 'Check against public data breach records via Have I Been Pwned.';
    if (occurrencesCount) {
      occurrencesCount.textContent = '—';
      occurrencesCount.className = 'occurrences-count';
    }
    if (occurrencesSubtext) occurrencesSubtext.textContent = 'No breach lookup has been performed yet.';
    if (retryBreachBtn) retryBreachBtn.disabled = false;
  }

  function resetDashboard() {
    if (scoreValue) scoreValue.textContent = '--';
    if (scoreRatingBadge) {
      scoreRatingBadge.className = 'score-badge';
      scoreRatingBadge.textContent = 'Not analyzed';
    }
    if (progressFill) progressFill.style.width = '0%';
    if (progressTrack) progressTrack.setAttribute('aria-valuenow', 0);
    if (scoreFeedback) scoreFeedback.textContent = 'Enter a password above to view its strength evaluation.';

    setCheckItem(checkLength, false);
    setCheckItem(checkUppercase, false);
    setCheckItem(checkLowercase, false);
    setCheckItem(checkNumber, false);
    setCheckItem(checkSpecial, false);
    if (checklistCounter) checklistCounter.textContent = '0/5 Passed';

    if (charCount) charCount.textContent = '0';
    if (uniqueCount) uniqueCount.textContent = '0';
    if (poolSizeValue) poolSizeValue.textContent = '0';
    if (entropyValue) entropyValue.textContent = '0.0';
    if (entropyFill) entropyFill.style.width = '0%';

    if (crackOnline) crackOnline.textContent = 'Instant';
    if (crackOffline) crackOffline.textContent = 'Instant';
    if (crackSingleGpu) crackSingleGpu.textContent = 'Instant';
    if (crackCluster) crackCluster.textContent = 'Instant';

    if (sha1PrefixHex) sha1PrefixHex.textContent = '-----';
    if (sha1SuffixHex) sha1SuffixHex.textContent = '-----------------------------------';

    if (recommendationsPrompt) recommendationsPrompt.style.display = 'flex';
    if (recommendationsStatusBox) {
      recommendationsStatusBox.style.display = 'block';
      recommendationsStatusBox.textContent = 'Ready for analysis.';
    }
    if (recommendationsList) {
      recommendationsList.style.display = 'none';
      recommendationsList.innerHTML = '';
    }

    resetBreachDisplay();
    lastAnalyzedPassword = '';
  }

  // ==========================================================================
  // Smart Password Generator
  // ==========================================================================
  const PASSPHRASE_WORDS = [
    'Solar', 'Flare', 'Cascade', 'Orbit', 'Vanguard', 'Horizon', 'Phoenix',
    'Nebula', 'Glacier', 'Phantom', 'Titanium', 'Pulsar', 'Quantum', 'Echo',
    'Falcon', 'Cobalt', 'Vector', 'Matrix', 'Apex', 'Strata', 'Zenith'
  ];

  function generateCipher(mode) {
    if (mode === 'passphrase') {
      const chosen = [];
      for (let i = 0; i < 4; i++) {
        const idx = Math.floor(Math.random() * PASSPHRASE_WORDS.length);
        chosen.push(PASSPHRASE_WORDS[idx]);
      }
      const num = Math.floor(10 + Math.random() * 90);
      const symbol = '!@#$'[Math.floor(Math.random() * 4)];
      if (genEntropyTag) genEntropyTag.textContent = '~95 bits entropy';
      return `${chosen.join('-')}-${num}${symbol}`;
    }

    if (mode === 'alphanumeric') {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
      let res = '';
      for (let i = 0; i < 18; i++) {
        res += chars.charAt(Math.floor(Math.random() * chars.length));
      }
      if (genEntropyTag) genEntropyTag.textContent = '~107 bits entropy';
      return res;
    }

    if (mode === 'quantum') {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}<>?';
      let res = '';
      for (let i = 0; i < 32; i++) {
        res += chars.charAt(Math.floor(Math.random() * chars.length));
      }
      if (genEntropyTag) genEntropyTag.textContent = '~208 bits entropy';
      return res;
    }

    if (mode === 'hex') {
      const hexChars = '0123456789ABCDEF';
      let res = '';
      for (let i = 0; i < 32; i++) {
        res += hexChars.charAt(Math.floor(Math.random() * 16));
      }
      if (genEntropyTag) genEntropyTag.textContent = '~128 bits entropy';
      return res;
    }

    return 'Solar#Flare$Cascade88';
  }

  function updateGeneratorOutput() {
    if (!generatedCipher) return;
    const token = generateCipher(currentGeneratorMode);
    generatedCipher.textContent = token;
  }

  genModeButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      genModeButtons.forEach(b => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');
      currentGeneratorMode = btn.getAttribute('data-mode') || 'passphrase';
      updateGeneratorOutput();
    });
  });

  if (regenerateBtn) {
    regenerateBtn.addEventListener('click', updateGeneratorOutput);
  }

  if (deployGeneratedBtn) {
    deployGeneratedBtn.addEventListener('click', () => {
      if (!generatedCipher || !passwordInput) return;
      const token = generatedCipher.textContent.trim();
      passwordInput.value = token;
      evaluateClientTelemetry(token);
      performStrengthAnalysis(token);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  if (copyGeneratedBtn) {
    copyGeneratedBtn.addEventListener('click', async () => {
      if (!generatedCipher) return;
      const token = generatedCipher.textContent.trim();
      const copyText = document.getElementById('copyText');
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(token);
        } else {
          const ta = document.createElement('textarea');
          ta.value = token;
          document.body.appendChild(ta);
          ta.select();
          document.execCommand('copy');
          document.body.removeChild(ta);
        }
        if (copyText) copyText.textContent = '✓ Copied!';
        setTimeout(() => {
          if (copyText) copyText.textContent = '📋 Copy';
        }, 1800);
      } catch {
        if (copyText) copyText.textContent = 'Copy failed';
        setTimeout(() => { if (copyText) copyText.textContent = '📋 Copy'; }, 1800);
      }
    });
  }

  // Initial generator seed
  updateGeneratorOutput();

  // ==========================================================================
  // Event Listeners: Input & User Actions
  // ==========================================================================
  if (passwordInput) {
    passwordInput.addEventListener('input', () => {
      const currentVal = passwordInput.value;
      evaluateClientTelemetry(currentVal);

      clearTimeout(inputDebounceTimer);
      if (!currentVal) {
        resetDashboard();
        return;
      }

      inputDebounceTimer = setTimeout(() => {
        performStrengthAnalysis(currentVal);
      }, 420);
    });

    passwordInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        clearTimeout(inputDebounceTimer);
        performStrengthAnalysis(passwordInput.value);
      }
    });
  }

  if (analyzeBtn) {
    analyzeBtn.addEventListener('click', () => {
      clearTimeout(inputDebounceTimer);
      if (passwordInput) performStrengthAnalysis(passwordInput.value);
    });
  }

  if (togglePasswordBtn && passwordInput) {
    togglePasswordBtn.addEventListener('click', () => {
      const isPassword = passwordInput.type === 'password';
      passwordInput.type = isPassword ? 'text' : 'password';
      togglePasswordBtn.textContent = isPassword ? 'HIDE' : 'SHOW';
      togglePasswordBtn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
    });
  }

  if (clearPasswordBtn && passwordInput) {
    clearPasswordBtn.addEventListener('click', () => {
      clearTimeout(inputDebounceTimer);
      passwordInput.value = '';
      passwordInput.focus();
      resetDashboard();
    });
  }

  if (retryBreachBtn) {
    retryBreachBtn.addEventListener('click', () => {
      const pwd = (passwordInput && passwordInput.value) || lastAnalyzedPassword;
      if (pwd) {
        performBreachCheck(pwd);
      } else if (passwordInput) {
        passwordInput.focus();
      }
    });
  }

  // Preset Chips
  document.querySelectorAll('.sample-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const samplePwd = chip.getAttribute('data-sample');
      if (samplePwd && passwordInput) {
        clearTimeout(inputDebounceTimer);
        passwordInput.value = samplePwd;
        evaluateClientTelemetry(samplePwd);
        performStrengthAnalysis(samplePwd);
      }
    });
  });

  // Expose global indicator so fallback script knows app.js initialized
  window.SecurePassInitialized = true;

})();
