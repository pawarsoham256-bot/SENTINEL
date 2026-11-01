Sentinel.api("/api/dashboard").then((data) => {
  document.getElementById("stat-scans").textContent = data.stats.total_scans;
  document.getElementById("stat-open").textContent = data.stats.open_ports;
  document.getElementById("stat-closed").textContent = data.stats.closed_ports;
  document.getElementById("stat-hosts").textContent = data.stats.hosts;
  const body = document.getElementById("recent-body");
  if (!data.recent.length) {
    body.innerHTML = '<tr><td colspan="6" class="muted">No scans recorded yet.</td></tr>';
  } else {
    body.innerHTML = data.recent.map((s) => `
      <tr>
        <td>${s.target_ip}</td>
        <td>${s.start_port}–${s.end_port}</td>
        <td class="ok">${s.open_count}</td>
        <td>${s.closed_count}</td>
        <td>${Sentinel.fmtDuration(s.duration_ms)}</td>
        <td>${Sentinel.fmtTime(s.created_at)}</td>
      </tr>`).join("");
  }
  Sentinel.lineChart("activityChart", data.trend.labels, data.trend.scans, "#3ee0ff");
  Sentinel.doughnut("portsChart", ["Open", "Closed"], [data.ports.open, data.ports.closed], ["#3dff9a", "#ff4d6d"]);
}).catch(() => {});
