const Sentinel = {
  csrf() {
    return document.querySelector('meta[name="csrf-token"]').content;
  },
  async api(url, options = {}) {
    const headers = Object.assign({ "X-CSRFToken": this.csrf() }, options.headers || {});
    if (options.body && !(options.body instanceof FormData)) {
      headers["Content-Type"] = "application/json";
    }
    const res = await fetch(url, Object.assign({}, options, { headers }));
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw data;
    return data;
  },
  fmtDuration(ms) {
    const s = (ms || 0) / 1000;
    return s.toFixed(2) + "s";
  },
  fmtTime(iso) {
    try { return new Date(iso).toLocaleString(); } catch { return iso; }
  },
  debounce(fn, wait) {
    let t;
    return (...args) => {
      clearTimeout(t);
      t = setTimeout(() => fn(...args), wait);
    };
  },
  chartDefaults() {
    Chart.defaults.color = "#8aa0c2";
    Chart.defaults.borderColor = "rgba(80,200,255,0.15)";
    Chart.defaults.font.family = "Rajdhani";
  },
  lineChart(id, labels, values, color) {
    this.chartDefaults();
    return new Chart(document.getElementById(id), {
      type: "line",
      data: { labels, datasets: [{ data: values, borderColor: color, backgroundColor: color + "33", fill: true, tension: 0.35 }] },
      options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
    });
  },
  doughnut(id, labels, values, colors) {
    this.chartDefaults();
    return new Chart(document.getElementById(id), {
      type: "doughnut",
      data: { labels, datasets: [{ data: values, backgroundColor: colors, borderWidth: 0 }] },
      options: { plugins: { legend: { position: "bottom" } } }
    });
  },
  barChart(id, labels, values, color) {
    this.chartDefaults();
    return new Chart(document.getElementById(id), {
      type: "bar",
      data: { labels, datasets: [{ data: values, backgroundColor: color }] },
      options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
    });
  }
};

document.querySelectorAll(".toggle-pass").forEach((btn) => {
  btn.addEventListener("click", () => {
    const input = document.getElementById(btn.dataset.target);
    if (!input) return;
    input.type = input.type === "password" ? "text" : "password";
    btn.textContent = input.type === "password" ? "Show" : "Hide";
  });
});

function scorePassword(value) {
  let score = 0;
  if (value.length >= 8) score += 1;
  if (/[A-Z]/.test(value) && /[a-z]/.test(value)) score += 1;
  if (/\d/.test(value)) score += 1;
  if (/[^A-Za-z0-9]/.test(value)) score += 1;
  return score;
}

document.querySelectorAll("[data-strength-for]").forEach((el) => {
  const input = document.getElementById(el.dataset.strengthFor);
  if (!input) return;
  const bar = el.querySelector("span");
  const label = el.querySelector("em");
  const colors = ["#ff4d6d", "#ffb020", "#3ee0ff", "#3dff9a"];
  const names = ["Weak", "Fair", "Good", "Strong"];
  input.addEventListener("input", () => {
    const score = scorePassword(input.value);
    bar.style.width = (score / 4) * 100 + "%";
    bar.style.background = colors[Math.max(0, score - 1)] || colors[0];
    label.textContent = input.value ? names[Math.max(0, score - 1)] : "Strength";
  });
});
