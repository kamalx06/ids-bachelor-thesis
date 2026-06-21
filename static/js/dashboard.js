function el(id) {
  return document.getElementById(id);
}

function setText(id, value) {
  const n = el(id);
  if (n) n.textContent = String(value ?? "");
}

const IDS_HEALTH_POLL_MS = 5000;

function applyIdsSensorHealth(payload) {
  const wrap = el("idsSensorStatus");
  const dot = el("idsLiveDot");
  const label = el("idsStatusLabel");
  if (!wrap || !label) return;

  const online = Boolean(payload && payload.online);
  wrap.classList.toggle("is-online", online);
  wrap.classList.toggle("is-offline", !online);
  if (dot) {
    dot.setAttribute("title", online ? "IDS engine running" : "IDS engine not running");
  }
  const text = payload?.label || (online ? "LIVE" : "OFFLINE");
  label.textContent = online ? `ONLINE / ${text}` : `OFFLINE`;
}

async function refreshIdsHealth() {
  try {
    const res = await fetch("/ids/health", { credentials: "same-origin" });
    if (!res.ok) {
      applyIdsSensorHealth({ online: false, label: "OFFLINE" });
      return;
    }
    const body = await res.json();
    const data = body && body.data ? body.data : body;
    applyIdsSensorHealth(data);
  } catch (_) {
    applyIdsSensorHealth({ online: false, label: "OFFLINE" });
  }
}

function toEpochSeconds(ts) {
  if (ts == null || ts === "") return NaN;
  if (typeof ts === "number" && Number.isFinite(ts)) {
    if (ts > 1e14) return ts / 1000;
    if (ts > 1e12) return ts / 1000;
    return ts;
  }
  const s = String(ts).trim();
  if (/^-?\d+(\.\d+)?$/.test(s)) {
    return toEpochSeconds(Number(s));
  }
  const parsed = Date.parse(s);
  return Number.isFinite(parsed) ? parsed / 1000 : NaN;
}

function pad2(n) {
  return String(n).padStart(2, "0");
}

function fmtTime(ts) {
  const sec = toEpochSeconds(ts);
  if (!Number.isFinite(sec)) return "";
  const integral = Math.floor(sec + 1e-12);
  let micro = Math.round((sec - integral) * 1e6);
  if (micro >= 1000000) micro = 999999;
  const d = new Date(integral * 1000);
  const base =
    `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())} ` +
    `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}`;
  if (micro === 0) return base;
  const frac = String(micro).padStart(6, "0").replace(/0+$/, "");
  return frac ? `${base}.${frac}` : base;
}

const RISK_DANGEROUS = 0.78;
const RISK_SUSPICIOUS = 0.52;

/** ML-adjusted score for charts (matches ~0.3 signals users expect). */
function displayScore(e) {
  if (typeof e.ai_score === "number" && Number.isFinite(e.ai_score)) return e.ai_score;
  if (typeof e.risk_score === "number" && Number.isFinite(e.risk_score)) return e.risk_score;
  return NaN;
}

/** Fused score for severity classification only. */
function classificationScore(e) {
  if (typeof e.risk_score === "number" && Number.isFinite(e.risk_score)) return e.risk_score;
  return displayScore(e);
}

function effectiveClassification(e) {
  const c = String(e.classification || e.status || "").toLowerCase();
  if (c === "dangerous" || c === "suspicious" || c === "safe") return c;
  const score = classificationScore(e);
  if (Number.isFinite(score)) {
    if (score >= RISK_DANGEROUS) return "dangerous";
    if (score >= RISK_SUSPICIOUS) return "suspicious";
  }
  return "safe";
}

function effectiveTrendScore(e) {
  const score = displayScore(e);
  if (Number.isFinite(score)) return score;
  const cls = effectiveClassification(e);
  if (cls === "dangerous") return 0.9;
  if (cls === "suspicious") return 0.55;
  return 0.08;
}

function parseHttpMeta(e) {
  if (e.http && typeof e.http === "object") return e.http;
  if (typeof e.http_json === "string") {
    try {
      return JSON.parse(e.http_json);
    } catch (_) {
      return null;
    }
  }
  return null;
}

function hostFromEvent(e) {
  const http = parseHttpMeta(e);
  if (http && http.host) {
    return String(http.host).split(":")[0].toLowerCase();
  }
  const raw = e.url;
  if (!raw) return null;
  const u = String(raw).trim();
  try {
    if (/^https?:\/\//i.test(u)) {
      return new URL(u).hostname.toLowerCase();
    }
    if (u.includes(".") && !u.startsWith("/")) {
      return u.split("/")[0].split(":")[0].toLowerCase();
    }
  } catch (_) {
    /* ignore */
  }
  return null;
}

function dnsLikeFromEvent(e) {
  if (e.dns && (e.dns.tunnel === true || e.dns.suspicious === true)) return true;
  const reasons = Array.isArray(e.reasons) ? e.reasons : [];
  return reasons.some((r) => {
    if (typeof r !== "string") return false;
    const s = r.toLowerCase();
    return s.startsWith("dns_") || s.includes("tunnel");
  });
}

function summarizeTiObject(obj) {
  if (!obj || typeof obj !== "object") return "";
  if (obj._parse_error) return "data error (see raw)";
  const parts = [];
  ["verdict", "category", "risk", "source", "asn", "country", "provider", "reason"].forEach((k) => {
    if (obj[k] != null && obj[k] !== "") parts.push(String(obj[k]));
  });
  if (obj.score != null && obj.score !== "") parts.push(`score=${obj.score}`);
  if (obj.value != null && !parts.length) parts.push(String(obj.value));
  return parts.join(" · ");
}

function renderThreatIntelCell(td, r) {
  td.textContent = "";
  const ipTi = r.ti_ip;
  const urlTi = r.ti_url;
  const ipText = summarizeTiObject(ipTi);
  const urlText = summarizeTiObject(urlTi);
  const legacyIp = ipTi && (ipTi.category || ipTi.risk || ipTi.verdict);
  const legacyUrl = urlTi && (urlTi.category || urlTi.risk || urlTi.verdict);
  const reasons = Array.isArray(r.reasons) ? r.reasons : [];
  const repFromReasons = reasons.filter(
    (x) => typeof x === "string" && (x.startsWith("reputation_ip_") || x.startsWith("reputation_url_"))
  );

  const toneFor = (label, text) => {
    const t = (text || "").toLowerCase();
    if (t.includes("malicious") || t.includes("danger")) return "danger";
    if (t.includes("suspicious") || t.includes("warn")) return "warn";
    return "ok";
  };

  if (ipText || legacyIp) {
    const label = legacyIp || (ipText ? `IP:${ipText.slice(0, 48)}` : "IP");
    td.appendChild(tag(String(label).slice(0, 64), toneFor(label, String(ipText || legacyIp))));
  }
  if (urlText || legacyUrl) {
    td.appendChild(document.createTextNode(" "));
    const label = legacyUrl || (urlText ? `URL:${urlText.slice(0, 48)}` : "URL");
    td.appendChild(tag(String(label).slice(0, 64), toneFor(label, String(urlText || legacyUrl))));
  }
  for (const rr of repFromReasons.slice(0, 4)) {
    td.appendChild(document.createTextNode(" "));
    td.appendChild(tag(rr, "warn"));
  }
  if (!td.textContent.trim()) {
    const hasDnsIntel = r.dns && typeof r.dns === "object" && Object.keys(r.dns).length;
    if (hasDnsIntel) td.appendChild(tag("DNS intel", "warn"));
    else td.textContent = "-";
  }
}

function tag(text, tone) {
  const span = document.createElement("span");
  span.className = "tag-pill";
  span.textContent = text;
  if (tone === "danger") {
    span.style.borderColor = "#7f1d1d";
    span.style.background = "#1f0b0b";
    span.style.color = "#fecaca";
  } else if (tone === "warn") {
    span.style.borderColor = "#92400e";
    span.style.background = "#1a1206";
    span.style.color = "#fde68a";
  } else if (tone === "ok") {
    span.style.borderColor = "#065f46";
    span.style.background = "#052e2a";
    span.style.color = "#a7f3d0";
  }
  return span;
}

function showAlert(message, type = "info") {
  const box = el("searchAlert");
  if (!box) return;
  box.textContent = message || "";
  box.className = message ? `alert ${type}` : "";
}

async function apiGet(path, params = {}) {
  const url = new URL(path, window.location.origin);
  Object.entries(params).forEach(([k, v]) => {
    if (v === undefined || v === null || v === "") return;
    url.searchParams.set(k, String(v));
  });
  const res = await fetch(url.toString(), { credentials: "same-origin" });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg =
      data?.error?.message ||
      data?.error ||
      `Request failed: ${res.status}`;
    throw new Error(msg);
  }
  if (typeof data.success === "boolean") {
    if (!data.success) {
      const msg = data?.error?.message || data?.error || "Request failed";
      throw new Error(msg);
    }
    return data.data;
  }
  return data;
}

async function apiGetEnvelope(path, params = {}) {
  const url = new URL(path, window.location.origin);
  Object.entries(params).forEach(([k, v]) => {
    if (v === undefined || v === null || v === "") return;
    url.searchParams.set(k, String(v));
  });
  const res = await fetch(url.toString(), { credentials: "same-origin" });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg =
      data?.error?.message ||
      data?.error ||
      `Request failed: ${res.status}`;
    throw new Error(msg);
  }
  return data;
}

function buildSeveritySeries(logs, minutes = 60, agg = null) {
  const now = Math.floor(Date.now() / 1000);
  const start = now - minutes * 60;
  const minKey = Math.floor(start / 60) * 60;
  const maxKey = Math.floor(now / 60) * 60;

  const buckets = new Map();
  for (let i = 0; i < minutes; i++) {
    const t = start + i * 60;
    const key = Math.floor(t / 60) * 60;
    buckets.set(key, { safe: 0, suspicious: 0, dangerous: 0, total: 0 });
  }

  for (const e of logs) {
    const tsRaw = toEpochSeconds(e.timestamp);
    let key = Number.isFinite(tsRaw) ? Math.floor(tsRaw / 60) * 60 : minKey;
    if (key < minKey) key = minKey;
    if (key > maxKey) key = maxKey;
    if (!buckets.has(key)) {
      buckets.set(key, { safe: 0, suspicious: 0, dangerous: 0, total: 0 });
    }
    const b = buckets.get(key);
    const cls = effectiveClassification(e);
    if (cls === "dangerous") b.dangerous++;
    else if (cls === "suspicious") b.suspicious++;
    else b.safe++;
    b.total++;
  }

  const ordered = [...buckets.entries()].sort((a, b) => a[0] - b[0]);
  let sumTotal = 0;
  for (const [, b] of ordered) {
    sumTotal += b.total;
  }

  if (sumTotal === 0 && agg && typeof agg.total === "number" && agg.total > 0 && minutes > 0) {
    const per = 1 / minutes;
    const add = (field, key) => {
      const n = Math.max(0, Number(agg[field]) || 0);
      return n * per;
    };
    for (const [, b] of ordered) {
      b.safe += add("safe");
      b.suspicious += add("suspicious");
      b.dangerous += add("dangerous");
      b.total += add("safe") + add("suspicious") + add("dangerous");
    }
  }

  const labels = [];
  const safe = [];
  const suspicious = [];
  const dangerous = [];
  const total = [];
  for (const [ts, b] of ordered) {
    labels.push(
      new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", timeZone: "UTC" })
    );
    safe.push(b.safe);
    suspicious.push(b.suspicious);
    dangerous.push(b.dangerous);
    total.push(b.total);
  }

  return { labels, safe, suspicious, dangerous, total };
}

document.addEventListener("DOMContentLoaded", async () => {
  if (!window.Chart) {
    showAlert("Chart library failed to load.", "error");
    return;
  }

  Chart.defaults.color = "#8b9cb3";
  Chart.defaults.borderColor = "rgba(148, 163, 184, 0.12)";
  Chart.defaults.font.family = "'DM Sans', system-ui, sans-serif";

  const severityCtx = el("severityChart")?.getContext("2d");
  const trafficCtx = el("trafficChart")?.getContext("2d");
  const distCtx = el("distributionChart")?.getContext("2d");
  const riskTrendCtx = el("riskTrendChart")?.getContext("2d");
  const topIpCtx = el("topIpChart")?.getContext("2d");
  const topDomainCtx = el("topDomainChart")?.getContext("2d");
  const dnsTunnelCtx = el("dnsTunnelChart")?.getContext("2d");

  let severityChart, trafficChart, distChart, riskTrendChart, topIpChart, topDomainChart, dnsTunnelChart;

  function ensureCharts() {
    if (severityCtx && !severityChart) {
      severityChart = new Chart(severityCtx, {
        type: "bar",
        data: { labels: [], datasets: [] },
        options: {
          responsive: true,
          plugins: { legend: { position: "bottom" } },
          scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true } },
        },
      });
    }
    if (trafficCtx && !trafficChart) {
      trafficChart = new Chart(trafficCtx, {
        type: "line",
        data: { labels: [], datasets: [] },
        options: {
          responsive: true,
          plugins: { legend: { position: "bottom" } },
          scales: { y: { beginAtZero: true } },
        },
      });
    }
    if (distCtx && !distChart) {
      distChart = new Chart(distCtx, {
        type: "doughnut",
        data: { labels: ["Safe", "Suspicious", "Dangerous"], datasets: [{ data: [0, 0, 0] }] },
        options: { responsive: true, plugins: { legend: { position: "bottom" } } },
      });
    }
    if (riskTrendCtx && !riskTrendChart) {
      riskTrendChart = new Chart(riskTrendCtx, {
        type: "line",
        data: { labels: [], datasets: [] },
        options: {
          responsive: true,
          plugins: { legend: { position: "bottom" } },
          scales: { y: { beginAtZero: true, suggestedMax: 1 } },
        },
      });
    }
    if (topIpCtx && !topIpChart) {
      topIpChart = new Chart(topIpCtx, {
        type: "bar",
        data: { labels: [], datasets: [] },
        options: {
          indexAxis: "y",
          responsive: true,
          plugins: { legend: { display: false } },
          scales: { x: { beginAtZero: true } },
        },
      });
    }
    if (topDomainCtx && !topDomainChart) {
      topDomainChart = new Chart(topDomainCtx, {
        type: "bar",
        data: { labels: [], datasets: [] },
        options: {
          indexAxis: "y",
          responsive: true,
          plugins: { legend: { display: false } },
          scales: { x: { beginAtZero: true } },
        },
      });
    }
    if (dnsTunnelCtx && !dnsTunnelChart) {
      dnsTunnelChart = new Chart(dnsTunnelCtx, {
        type: "line",
        data: { labels: [], datasets: [] },
        options: {
          responsive: true,
          plugins: { legend: { position: "bottom" } },
          scales: { y: { beginAtZero: true } },
        },
      });
    }
  }

  async function refreshOverview() {
    const stats = await apiGet("/ids/stats");
    setText("sumTotal", stats.total ?? 0);
    setText("sumSafe", stats.safe ?? 0);
    setText("sumSuspicious", stats.suspicious ?? 0);
    setText("sumDangerous", stats.dangerous ?? 0);
    setText("sumUnique", stats.unique_attackers ?? 0);
    setText("sumDangerousIps", (stats.dangerous_ips || []).length);
    const refreshEl = el("dashLastRefresh");
    if (refreshEl) {
      refreshEl.textContent = new Date().toLocaleTimeString();
    }
  }

  async function refreshCharts() {
    ensureCharts();
    const end = Math.floor(Date.now() / 1000);
    const start = end - 60 * 60;

    const [series, logsEnvelope, agg, stats] = await Promise.all([
      apiGet("/ids/traffic-timeseries", {
        start_time: start,
        end_time: end,
        minutes: 60,
      }).catch(() => null),
      apiGet("/ids/logs", {
        start_time: start,
        end_time: end,
        limit: 2000,
      }).catch(() => []),
      apiGet("/ids/log-aggregate", { start_time: start, end_time: end }).catch(() => null),
      apiGet("/ids/stats").catch(() => null),
    ]);

    const logs = Array.isArray(logsEnvelope) ? logsEnvelope : [];
    const s =
      series && Array.isArray(series.labels) && series.labels.length
        ? {
            labels: series.labels,
            safe: series.safe || [],
            suspicious: series.suspicious || [],
            dangerous: series.dangerous || [],
            total: series.total || [],
            avgRisk: series.avg_risk || [],
          }
        : (() => {
            const built = buildSeveritySeries(logs, 60, agg);
            return { ...built, avgRisk: [] };
          })();

    if (severityChart) {
      severityChart.data.labels = s.labels;
      severityChart.data.datasets = [
        { label: "Safe", data: s.safe, backgroundColor: "#10b981" },
        { label: "Suspicious", data: s.suspicious, backgroundColor: "#f59e0b" },
        { label: "Dangerous", data: s.dangerous, backgroundColor: "#ef4444" },
      ];
      severityChart.update();
    }

    if (trafficChart) {
      trafficChart.data.labels = s.labels;
      trafficChart.data.datasets = [{ label: "Events/min", data: s.total, borderColor: "#3b82f6", tension: 0.2 }];
      trafficChart.update();
    }

    if (distChart) {
      let safeSum = s.safe.reduce((a, b) => a + b, 0);
      let suspSum = s.suspicious.reduce((a, b) => a + b, 0);
      let dangSum = s.dangerous.reduce((a, b) => a + b, 0);
      if (safeSum + suspSum + dangSum === 0 && series?.totals) {
        safeSum = series.totals.safe || 0;
        suspSum = series.totals.suspicious || 0;
        dangSum = series.totals.dangerous || 0;
      }
      if (safeSum + suspSum + dangSum === 0 && agg && agg.total > 0) {
        safeSum = agg.safe || 0;
        suspSum = agg.suspicious || 0;
        dangSum = agg.dangerous || 0;
      }
      if (safeSum + suspSum + dangSum === 0 && stats && stats.total > 0) {
        safeSum = stats.safe || 0;
        suspSum = stats.suspicious || 0;
        dangSum = stats.dangerous || 0;
      }
      distChart.data.datasets[0].data = [safeSum, suspSum, dangSum];
      distChart.update();
    }

    if (riskTrendChart) {
      let riskLabels = s.labels;
      let riskValues = Array.isArray(s.avgRisk) && s.avgRisk.length ? [...s.avgRisk] : [];

      if (!riskValues.length) {
        const now = Math.floor(Date.now() / 1000);
        const startTs = now - 60 * 60;
        const minKey = Math.floor(startTs / 60) * 60;
        const maxKey = Math.floor(now / 60) * 60;
        const buckets = new Map();
        for (let i = 0; i < 60; i++) {
          const t = startTs + i * 60;
          const key = Math.floor(t / 60) * 60;
          buckets.set(key, { sum: 0, count: 0 });
        }
        for (const e of logs) {
          const tsRaw = toEpochSeconds(e.timestamp);
          let ts = Number.isFinite(tsRaw) ? Math.floor(tsRaw / 60) * 60 : minKey;
          if (ts < minKey) ts = minKey;
          if (ts > maxKey) ts = maxKey;
          if (!buckets.has(ts)) buckets.set(ts, { sum: 0, count: 0 });
          const b = buckets.get(ts);
          b.sum += effectiveTrendScore(e);
          b.count += 1;
        }
        const orderedRisk = [...buckets.entries()].sort((a, b) => a[0] - b[0]);
        riskLabels = [];
        riskValues = [];
        for (const [ts, b] of orderedRisk) {
          riskLabels.push(
            new Date(ts * 1000).toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
              timeZone: "UTC",
            })
          );
          riskValues.push(b.count ? b.sum / b.count : 0);
        }
      }

      const any = riskValues.some((v) => v > 0);
      if (!any && agg && agg.total > 0) {
        const inferred = Math.min(
          1,
          0.2 +
            ((agg.dangerous || 0) / agg.total) * 0.75 +
            ((agg.suspicious || 0) / agg.total) * 0.35
        );
        for (let i = 0; i < riskValues.length; i++) riskValues[i] = inferred;
      }
      const yMax = Math.max(1.05, ...riskValues, 0.01);
      if (riskTrendChart.options?.scales?.y) {
        riskTrendChart.options.scales.y.max = yMax;
      }
      riskTrendChart.data.labels = riskLabels;
      riskTrendChart.data.datasets = [
        {
          label: "Avg risk / AI signal",
          data: riskValues,
          borderColor: "#f97316",
          tension: 0.25,
        },
      ];
      riskTrendChart.update();
    }

    if (topIpChart || topDomainChart || dnsTunnelChart) {
      const byIp = new Map();
      const byDomain = new Map();
      const dnsByTime = new Map();

      for (const e of logs) {
        const score = effectiveTrendScore(e);
        const keyIp = e.src_ip || e.dst_ip || null;
        if (keyIp) {
          const prev = byIp.get(keyIp) || 0;
          byIp.set(keyIp, Math.max(prev, score));
        }
        const host = hostFromEvent(e);
        if (host) {
          const prev = byDomain.get(host) || 0;
          byDomain.set(host, Math.max(prev, score));
        }
        if (dnsLikeFromEvent(e)) {
          const tsRaw = toEpochSeconds(e.timestamp);
          const ts = Number.isFinite(tsRaw) ? Math.floor(tsRaw / 60) * 60 : Math.floor(end / 60) * 60;
          dnsByTime.set(ts, (dnsByTime.get(ts) || 0) + 1);
        }
      }

      if (topIpChart) {
        let entries = [...byIp.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
        if (entries.length === 0 && stats && Array.isArray(stats.dangerous_ips) && stats.dangerous_ips.length) {
          entries = stats.dangerous_ips.slice(0, 10).map((ip) => [ip, 1]);
        }
        if (entries.length === 0 && agg && Array.isArray(agg.dangerous_ips) && agg.dangerous_ips.length) {
          entries = agg.dangerous_ips.slice(0, 10).map((ip) => [ip, 1]);
        }
        topIpChart.data.labels = entries.map(([k]) => k);
        topIpChart.data.datasets = [
          {
            data: entries.map(([, v]) => v),
            backgroundColor: "#ef4444",
          },
        ];
        topIpChart.update();
      }

      if (topDomainChart) {
        let entries = [...byDomain.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
        if (entries.length === 0 && stats && Array.isArray(stats.dangerous_urls) && stats.dangerous_urls.length) {
          const m = new Map();
          for (const u of stats.dangerous_urls) {
            const host =
              hostFromEvent({ url: u }) || String(u).split("/")[0].split(":")[0];
            if (host) m.set(host, Math.max(m.get(host) || 0, 1));
          }
          entries = [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
        }
        topDomainChart.data.labels = entries.map(([k]) => k);
        topDomainChart.data.datasets = [
          {
            data: entries.map(([, v]) => v),
            backgroundColor: "#6366f1",
          },
        ];
        topDomainChart.update();
      }

      if (dnsTunnelChart) {
        const labels = [];
        const values = [];
        let sorted = [...dnsByTime.entries()].sort((a, b) => a[0] - b[0]);
        if (sorted.length === 0 && logs.some((e) => dnsLikeFromEvent(e))) {
          const total = logs.filter((e) => dnsLikeFromEvent(e)).length;
          const oneTs = Math.floor(end / 60) * 60;
          sorted = [[oneTs, total]];
        }
        for (const [ts, count] of sorted) {
          labels.push(
            new Date(ts * 1000).toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
              timeZone: "UTC",
            })
          );
          values.push(count);
        }
        if (values.length === 0) {
          labels.push(
            new Date(Math.floor(end / 60) * 60 * 1000).toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
              timeZone: "UTC",
            })
          );
          values.push(0);
        }
        dnsTunnelChart.data.labels = labels;
        dnsTunnelChart.data.datasets = [
          {
            label: "Suspect DNS events",
            data: values,
            borderColor: "#22c55e",
            tension: 0.25,
          },
        ];
        dnsTunnelChart.update();
      }
    }
  }

  let lastLogs = [];
  let lastLogsMeta = null;
  let lastSearchParams = null;
  let logsCursorStack = [null];
  let logsCursorIndex = 0;

  function renderLogsPager() {
    const host = el("logsPager");
    if (!host) return;
    const meta = lastLogsMeta || {};
    host.innerHTML = "";

    const totalText = document.createElement("span");
    totalText.textContent = meta.total
      ? `Showing page ${logsCursorIndex + 1} (${meta.limit || meta.page_size || lastLogs.length} per page)`
      : `Page ${logsCursorIndex + 1}`;
    totalText.style.marginRight = "12px";

    const prevBtn = document.createElement("button");
    prevBtn.type = "button";
    prevBtn.className = "secondary";
    prevBtn.textContent = "Prev";
    prevBtn.style.width = "auto";
    prevBtn.style.marginRight = "8px";
    prevBtn.disabled = logsCursorIndex === 0;

    prevBtn.addEventListener("click", (e) => {
      e.preventDefault();
      if (logsCursorIndex === 0) return;
      logsCursorIndex = Math.max(0, logsCursorIndex - 1);
      void runSearch(false);
    });

    const nextBtn = document.createElement("button");
    nextBtn.type = "button";
    nextBtn.className = "secondary";
    nextBtn.textContent = "Next";
    nextBtn.style.width = "auto";
    nextBtn.disabled = !meta.next_before_time;

    nextBtn.addEventListener("click", (e) => {
      e.preventDefault();
      if (!meta.next_before_time) return;
      // advance cursor
      logsCursorStack = logsCursorStack.slice(0, logsCursorIndex + 1);
      logsCursorStack.push(meta.next_before_time);
      logsCursorIndex += 1;
      void runSearch(false);
    });

    host.appendChild(totalText);
    host.appendChild(prevBtn);
    host.appendChild(nextBtn);
  }

  let sortKey = "timestamp";
  let sortDir = "desc";

  function sortRows(rows) {
    const copy = [...rows];
    copy.sort((a, b) => {
      let av = a[sortKey];
      let bv = b[sortKey];
      if (sortKey === "timestamp") {
        av = Number(toEpochSeconds(av) || 0);
        bv = Number(toEpochSeconds(bv) || 0);
      } else if (typeof av === "string") {
        av = av.toLowerCase();
        bv = String(bv || "").toLowerCase();
      }
      if (av < bv) return sortDir === "asc" ? -1 : 1;
      if (av > bv) return sortDir === "asc" ? 1 : -1;
      return 0;
    });
    return copy;
  }

  function renderLogs(rows) {
    const tbody = el("logsTbody");
    if (!tbody) return;
    tbody.innerHTML = "";
    lastLogs = rows || [];

    if (!rows || rows.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 10;
      td.className = "empty";
      td.textContent = "No matching events.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    const sorted = sortRows(rows);
    sorted.forEach((r, idx) => {
      const tr = document.createElement("tr");
      tr.dataset.index = String(rows.indexOf(r));
      tr.style.cursor = "pointer";

      const cells = [
        fmtTime(r.timestamp),
        r.src_ip || "-",
        r.src_port != null ? String(r.src_port) : "-",
        r.dst_ip || "-",
        r.dst_port != null ? String(r.dst_port) : "-",
        r.protocol || "-",
      ];

      cells.forEach((text) => {
        const td = document.createElement("td");
        td.textContent = text;
        tr.appendChild(td);
      });

      const tdCls = document.createElement("td");
      const cls = effectiveClassification(r);
      if (cls === "dangerous") tdCls.appendChild(tag("dangerous", "danger"));
      else if (cls === "suspicious") tdCls.appendChild(tag("suspicious", "warn"));
      else tdCls.appendChild(tag("safe", "ok"));
      tr.appendChild(tdCls);

      const tdAi = document.createElement("td");
      const score = r.ai_score != null ? Number(r.ai_score).toFixed(3) : "-";
      const risk = r.risk_score != null ? Number(r.risk_score).toFixed(3) : "";
      tdAi.textContent = risk ? `${score} (risk ${risk})` : score;
      tr.appendChild(tdAi);

      const tdTi = document.createElement("td");
      renderThreatIntelCell(tdTi, r);
      tr.appendChild(tdTi);

      const tdReasons = document.createElement("td");
      const reasons = Array.isArray(r.reasons) ? r.reasons.slice(0, 6) : [];
      if (reasons.length === 0) tdReasons.textContent = "-";
      else {
        for (const reason of reasons) {
          tdReasons.appendChild(tag(reason));
          tdReasons.appendChild(document.createTextNode(" "));
        }
      }
      tr.appendChild(tdReasons);
      tbody.appendChild(tr);
    });
  }

  document.querySelectorAll(".dash-table thead th[data-sort]").forEach((th) => {
    th.style.cursor = "pointer";
    th.addEventListener("click", () => {
      const key = th.getAttribute("data-sort");
      if (sortKey === key) {
        sortDir = sortDir === "asc" ? "desc" : "asc";
      } else {
        sortKey = key;
        sortDir = "desc";
      }
      renderLogs(lastLogs);
    });
  });

  const FILTER_FIELD_IDS = [
    "qIp", "qSrcIp", "qDstIp", "qPort", "qSrcPort", "qDstPort", "qProtocol",
    "qUrl", "qReason", "qClassification", "qAiLabel", "qMinScore", "qMaxScore",
    "qMinAnomaly", "qMinConfidence", "qThreatIntel", "qStart", "qEnd",
  ];

  const TIME_RANGE_SECONDS = {
    "15m": 15 * 60,
    "1h": 60 * 60,
    "6h": 6 * 60 * 60,
    "24h": 24 * 60 * 60,
    "7d": 7 * 24 * 60 * 60,
  };

  function datetimeLocalToEpoch(val) {
    if (!val) return "";
    const ms = new Date(val).getTime();
    return Number.isFinite(ms) ? ms / 1000 : "";
  }

  function epochToDatetimeLocal(epochSec) {
    if (!epochSec) return "";
    const d = new Date(Number(epochSec) * 1000);
    if (!Number.isFinite(d.getTime())) return "";
    const off = d.getTimezoneOffset();
    const local = new Date(d.getTime() - off * 60 * 1000);
    return local.toISOString().slice(0, 19);
  }

  function collectSearchParams() {
    return {
      ip: el("qIp")?.value?.trim() || "",
      src_ip: el("qSrcIp")?.value?.trim() || "",
      dst_ip: el("qDstIp")?.value?.trim() || "",
      port: el("qPort")?.value || "",
      src_port: el("qSrcPort")?.value || "",
      dst_port: el("qDstPort")?.value || "",
      protocol: el("qProtocol")?.value || "",
      url: el("qUrl")?.value?.trim() || "",
      reason: el("qReason")?.value?.trim() || "",
      classification: el("qClassification")?.value || "",
      ai_label: el("qAiLabel")?.value || "",
      min_ai_score: el("qMinScore")?.value || "",
      max_ai_score: el("qMaxScore")?.value || "",
      min_anomaly_score: el("qMinAnomaly")?.value || "",
      min_confidence: el("qMinConfidence")?.value || "",
      has_threat_intel: el("qThreatIntel")?.value || "",
      start_time: datetimeLocalToEpoch(el("qStart")?.value),
      end_time: datetimeLocalToEpoch(el("qEnd")?.value),
      limit: el("qLimit")?.value || 200,
    };
  }

  function updateActiveFilterBadge(params) {
    const badge = el("activeFilterCount");
    if (!badge) return;
    const active = Object.entries(params || {}).filter(
      ([k, v]) => k !== "limit" && v !== "" && v != null,
    ).length;
    badge.textContent = active === 1 ? "1 active" : `${active} active`;
    badge.classList.toggle("is-hidden", active === 0);
  }

  function applyTimePreset(rangeKey) {
    const startEl = el("qStart");
    const endEl = el("qEnd");
    if (!startEl || !endEl) return;

    document.querySelectorAll(".dash-preset-btn.is-active").forEach((btn) => {
      btn.classList.remove("is-active");
    });

    if (rangeKey === "clear") {
      startEl.value = "";
      endEl.value = "";
      return;
    }

    const seconds = TIME_RANGE_SECONDS[rangeKey];
    if (!seconds) return;

    const now = Date.now() / 1000;
    startEl.value = epochToDatetimeLocal(now - seconds);
    endEl.value = epochToDatetimeLocal(now);

    const btn = document.querySelector(`.dash-preset-btn[data-range="${rangeKey}"]`);
    btn?.classList.add("is-active");
  }

  document.querySelectorAll(".dash-preset-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      applyTimePreset(btn.getAttribute("data-range"));
      updateActiveFilterBadge(collectSearchParams());
    });
  });

  async function runSearch(resetCursor = true) {
    try {
      showAlert("", "info");

      const params = collectSearchParams();
      updateActiveFilterBadge(params);

      if (resetCursor) {
        logsCursorStack = [null];
        logsCursorIndex = 0;
      }

      const before_time = logsCursorStack[logsCursorIndex];
      const envelope = await apiGetEnvelope("/ids/search", {
        ...params,
        before_time,
      });

      const rows = Array.isArray(envelope.data)
        ? envelope.data
        : envelope.data || [];

      lastLogsMeta = envelope.meta || {};
      lastSearchParams = params;

      const freeText = el("qFreeText");
      if (freeText) freeText.value = "";

      renderLogs(rows);
      showAlert(`Loaded ${rows.length} event(s).`, "success");
      renderLogsPager();
    } catch (e) {
      renderLogs([]);
      showAlert(e.message || "Search failed.", "error");
      lastLogsMeta = null;
      renderLogsPager();
    }
  }

  el("runSearch")?.addEventListener("click", (e) => {
    e.preventDefault();
    runSearch();
  });

  el("resetSearch")?.addEventListener("click", () => {
    FILTER_FIELD_IDS.forEach((id) => {
      const n = el(id);
      if (!n) return;
      if (n.tagName === "SELECT") n.value = "";
      else n.value = "";
    });
    document.querySelectorAll(".dash-preset-btn.is-active").forEach((btn) => {
      btn.classList.remove("is-active");
    });
    const freeText = el("qFreeText");
    if (freeText) freeText.value = "";
    updateActiveFilterBadge({});
    showAlert("", "info");
    renderLogs([]);
    lastLogsMeta = null;
    logsCursorStack = [null];
    logsCursorIndex = 0;
    renderLogsPager();
  });

  FILTER_FIELD_IDS.forEach((id) => {
    const node = el(id);
    if (!node) return;
    node.addEventListener("keydown", (e) => {
      if (e.key !== "Enter") return;
      e.preventDefault();
      runSearch();
    });
    node.addEventListener("change", () => {
      updateActiveFilterBadge(collectSearchParams());
    });
  });

  el("qFreeText")?.addEventListener("input", () => {
    const q = el("qFreeText").value.trim().toLowerCase();
    if (!q) {
      renderLogs(lastLogs);
      showAlert(lastLogs.length ? `Showing ${lastLogs.length} event(s).` : "", "success");
      return;
    }
    const filtered = lastLogs.filter((r) => {
      const buf = JSON.stringify(r || {}).toLowerCase();
      return buf.includes(q);
    });
    renderLogs(filtered);
    showAlert(`Filtered to ${filtered.length} event(s).`, "success");
  });

  // Drilldown modal
  const modal = el("logDetailModal");
  const modalPre = el("logDetailPre");
  const modalTitle = el("logDetailTitle");
  const closeBtn = el("closeLogDetail");
  if (modal && modalPre && modalTitle && closeBtn) {
    closeBtn.addEventListener("click", () => {
      modal.classList.remove("open");
    });
    modal.addEventListener("click", (e) => {
      if (e.target === modal) modal.classList.remove("open");
    });
    el("logsTbody")?.addEventListener("click", (e) => {
      const tr = e.target.closest("tr");
      if (!tr) return;
      const idx = Number(tr.dataset.index || "-1");
      if (idx < 0 || !lastLogs[idx]) return;
      const ev = lastLogs[idx];
      modalTitle.textContent = `Event ${ev.id ?? ""}`.trim();
      modalPre.textContent = JSON.stringify(ev, null, 2);
      modal.classList.add("open");
    });
  }

  try {
    await refreshIdsHealth();
    await refreshOverview();
    await refreshCharts();
  } catch (e) {
    showAlert(e.message || "Failed to load dashboard data.", "error");
  }

  setInterval(() => {
    refreshIdsHealth().catch(() => {});
  }, IDS_HEALTH_POLL_MS);

  function connectLiveStream() {
    if (typeof EventSource === "undefined") return;
    const source = new EventSource("/ids/stream");
    source.addEventListener("stats", (ev) => {
      try {
        const stats = JSON.parse(ev.data);
        setText("sumTotal", stats.total ?? 0);
        setText("sumSafe", stats.safe ?? 0);
        setText("sumSuspicious", stats.suspicious ?? 0);
        setText("sumDangerous", stats.dangerous ?? 0);
        setText("sumUnique", stats.unique_attackers ?? 0);
        setText("sumDangerousIps", (stats.dangerous_ips || []).length);
        const refreshEl = el("dashLastRefresh");
        if (refreshEl) refreshEl.textContent = new Date().toLocaleTimeString();
      } catch (_) {
        /* ignore malformed SSE */
      }
    });
    source.onerror = () => {
      source.close();
      setTimeout(connectLiveStream, 5000);
    };
  }

  connectLiveStream();

  setInterval(() => {
    refreshOverview().catch(() => {});
    refreshCharts().catch(() => {});
  }, 10000);
});

