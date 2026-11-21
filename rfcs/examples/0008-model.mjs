// RFC-0008 model: reproduces the break-even and time-to-tier tables.
// Run: node rfcs/examples/0008-model.mjs
// Deterministic expected-value model, not a Monte Carlo. Ignores hysteresis,
// promotion delays, dormancy and the risk accumulator (see RFC-0008 §8).

const R = { READ: 1, LOW: 3, MEDIUM: 5, HIGH: 10, CRITICAL: 15, LIFE_CRITICAL: 30 };
const RHO = { READ: 0, LOW: 0.15, MEDIUM: 0.35, HIGH: 0.6, CRITICAL: 0.85, LIFE_CRITICAL: 1 };
const THRESHOLD = { READ: 0, LOW: 200, MEDIUM: 400, HIGH: 600, CRITICAL: 800, LIFE_CRITICAL: 951 };
const EVIDENCE_CEILING = { READ: 499, LOW: 649, MEDIUM: 799, HIGH: 950, CRITICAL: 1000, LIFE_CRITICAL: 1000 };
const TIER_MIN = [0, 200, 350, 500, 650, 800, 876, 951];
const C = 1000;
const tier = (s) => TIER_MIN.reduce((t, m, i) => (s >= m ? i : t), 0);
const P = (t) => 3 + t;

const today = {
  gain: (s, ceil, a) => 0.05 * Math.log(1 + Math.max(0, ceil - s)) * Math.cbrt(R[a]),
  loss: (t, a) => -P(t) * R[a] * 0.05 * Math.log(1 + C / 2),
};
const proposed = (kMin, kMax) => {
  const k = (a) => kMin + RHO[a] * (kMax - kMin);
  return {
    k,
    gain: (s, ceil, a) => k(a) * Math.log(1 + Math.max(0, ceil - s)),
    loss: (t, a) => -P(t) * k(a) * Math.log(1 + C / 2),
  };
};

function breakEven() {
  const rows = [
    ['READ', 0, 100], ['LOW', 1, 250], ['MEDIUM', 3, 550],
    ['HIGH', 4, 700], ['CRITICAL', 5, 820], ['LIFE_CRITICAL', 7, 960],
  ];
  const prop = proposed(0.05, 0.25);
  console.log('level          tier  S    | today: ratio  break-even  loss pts | proposed: ratio  break-even  loss pts');
  for (const [a, t, s] of rows) {
    const rt = -today.loss(t, a) / today.gain(s, C, a);
    const rp = -prop.loss(t, a) / prop.gain(s, C, a);
    console.log(
      `${a.padEnd(14)} T${t}   ${String(s).padEnd(4)} | ${rt.toFixed(2).padStart(7)}  ${(100 * rt / (rt + 1)).toFixed(2).padStart(6)}%  ${(-today.loss(t, a)).toFixed(2).padStart(7)} | ${rp.toFixed(2).padStart(6)}  ${(100 * rp / (rp + 1)).toFixed(2).padStart(6)}%  ${(-prop.loss(t, a)).toFixed(2).padStart(6)}`,
    );
  }
}

// Agent L: 2,000 actions/day, 80% READ / 20% LOW once permitted, 99.5% success.
// Agent H: 5 actions/day, always the highest level it is permitted up to HIGH, 99% success.
function agents() {
  let i = 0;
  const L = (s) => ((i++ % 5 === 0 && s >= THRESHOLD.LOW) ? 'LOW' : 'READ');
  const H = (s) => ['HIGH', 'MEDIUM', 'LOW', 'READ'].find((a) => s >= THRESHOLD[a]);
  return [
    ['L', 2000, L, 0.995],
    ['H', 5, H, 0.99],
  ];
}

function run({ model, perDay, mix, p, evidenceCeiling, cap, days = 3650 }) {
  let s = 0;
  const demonstrated = new Set();
  const reached = {};
  for (let d = 1; d <= days; d++) {
    const plan = Array.from({ length: perDay }, () => mix(s));
    const count = {};
    for (const a of plan) count[a] = (count[a] ?? 0) + 1;
    for (const a of plan) {
      demonstrated.add(a);
      const ceil = evidenceCeiling ? Math.min(C, Math.max(...[...demonstrated].map((x) => EVIDENCE_CEILING[x]))) : C;
      const w = cap ? Math.min(1, cap / count[a]) : 1;
      const delta = p * model.gain(s, ceil, a) + (1 - p) * model.loss(tier(s), a);
      s = Math.min(ceil, Math.max(0, s + w * delta));
    }
    for (const [t, m] of [[3, 500], [4, 650], [5, 800]]) if (s >= m && reached[`T${t}`] === undefined) reached[`T${t}`] = d;
  }
  return { daysTo: reached, finalScore: Math.round(s * 10) / 10 };
}

breakEven();
console.log('\nDays to reach T3 / T4 / T5 (blank = never in 10 years); final score');
const configs = [
  ['today', today, false, null],
  ['k 0.01..0.05, rate only', proposed(0.01, 0.05), false, null],
  ['k 0.01..0.05 + ceiling + volume cap 50', proposed(0.01, 0.05), true, 50],
  ['k 0.05..0.25, rate only', proposed(0.05, 0.25), false, null],
  ['k 0.05..0.25 + ceiling + volume cap 50', proposed(0.05, 0.25), true, 50],
];
for (const [name, model, evidenceCeiling, cap] of configs) {
  for (const [agent, perDay, mix, p] of agents()) {
    console.log(name.padEnd(42), agent, JSON.stringify(run({ model, perDay, mix, p, evidenceCeiling, cap })));
  }
}
