const form = document.getElementById("scan-form");
const stage = document.getElementById("scan-stage");
const errors = document.getElementById("form-errors");
const exportBtn = document.getElementById("export-csv");
let lastJob = null;
let timer = null;

function renderResults(rows) {
  const body = document.getElementById("results-body");
  if (!rows || !rows.length) {
    body.innerHTML = '<tr><td colspan="3" class="muted">No port results yet.</td></tr>';
    return;
  }
  body.innerHTML = rows.map((r) =>
    `<tr><td>${r.port}</td><td class="${r.state}">${r.state}</td><td>${r.service}</td></tr>`
  ).join("");
}

function updateHud(job) {
  document.getElementById("scan-percent").textContent = job.percent + "%";
  document.getElementById("scan-elapsed").textContent = (job.elapsed || 0).toFixed(2) + "s";
  document.getElementById("scan-port").textContent = job.current_port || "—";
  document.getElementById("progress-bar").style.width = job.percent + "%";
  document.getElementById("scan-status").textContent =
    job.status === "running" ? "Scanning" : job.status === "completed" ? "Complete" : job.status;
  document.getElementById("scan-detail").textContent =
    job.target_ip + " · ports " + job.start_port + "–" + job.end_port +
    " · open " + job.open_count + " / closed " + job.closed_count;
}

async function poll(jobId) {
  const data = await Sentinel.api("/api/scan/status/" + jobId);
  lastJob = data.job;
  updateHud(lastJob);
  if (lastJob.status === "completed") {
    stage.classList.remove("active");
    stage.classList.add("done");
    renderResults(lastJob.results);
    exportBtn.disabled = !lastJob.scan_id;
    exportBtn.onclick = () => { window.location = "/api/history/" + lastJob.scan_id + "/csv"; };
    return;
  }
  if (lastJob.status === "error") {
    stage.classList.remove("active");
    errors.textContent = lastJob.error || "Scan failed.";
    return;
  }
  timer = setTimeout(() => poll(jobId), 400);
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  errors.textContent = "";
  exportBtn.disabled = true;
  stage.classList.add("active");
  stage.classList.remove("done");
  document.getElementById("scan-status").textContent = "Initializing";
  try {
    const data = await Sentinel.api("/api/scan/start", { method: "POST", body: new FormData(form) });
    updateHud(data.job);
    poll(data.job.job_id);
  } catch (err) {
    stage.classList.remove("active");
    const msgs = err.errors ? Object.values(err.errors).join(" ") : (err.error || "Unable to start scan.");
    errors.textContent = msgs;
  }
});
