/**
 * main.js — Phishing URL Detection System
 * Client-side enhancements: form validation, loading states,
 * animated risk bars, and table search.
 */

"use strict";

/* ------------------------------------------------------------------ */
/* URL Form — validation + loading spinner                            */
/* ------------------------------------------------------------------ */

(function initAnalyzeForm() {
  const form = document.getElementById("analyzeForm");
  if (!form) return;

  const input   = document.getElementById("urlInput");
  const btn     = document.getElementById("analyzeBtn");
  const btnText = document.getElementById("analyzeBtnText");
  const spinner = document.getElementById("analyzeSpinner");

  form.addEventListener("submit", function (e) {
    const val = (input.value || "").trim();

    if (!val) {
      e.preventDefault();
      showInputError(input, "Please enter a URL.");
      return;
    }

    // Basic URL-shape check (scheme optional)
    const urlPattern = /^(https?:\/\/)?[\w\-]+(\.[\w\-]+)+.*$/i;
    if (!urlPattern.test(val)) {
      e.preventDefault();
      showInputError(input, "That doesn't look like a valid URL.");
      return;
    }

    // Show loading state
    btn.disabled = true;
    btnText.textContent = "Analyzing…";
    if (spinner) spinner.style.display = "inline-block";
  });

  // Clear error styling on input
  if (input) {
    input.addEventListener("input", function () {
      clearInputError(input);
    });
  }

  function showInputError(el, msg) {
    el.classList.add("is-invalid");
    let feedback = el.parentElement.querySelector(".invalid-feedback");
    if (!feedback) {
      feedback = document.createElement("div");
      feedback.className = "invalid-feedback";
      el.parentElement.appendChild(feedback);
    }
    feedback.textContent = msg;
  }

  function clearInputError(el) {
    el.classList.remove("is-invalid");
    const feedback = el.parentElement.querySelector(".invalid-feedback");
    if (feedback) feedback.textContent = "";
  }
})();


/* ------------------------------------------------------------------ */
/* Risk bar — animate width on page load                              */
/* ------------------------------------------------------------------ */

(function animateRiskBars() {
  const bars = document.querySelectorAll(".risk-bar-fill[data-width]");
  bars.forEach(function (bar) {
    // Start at 0, then animate to target after a short delay
    const target = bar.getAttribute("data-width");
    bar.style.width = "0%";
    requestAnimationFrame(function () {
      setTimeout(function () {
        bar.style.width = target + "%";
      }, 80);
    });
  });
})();


/* ------------------------------------------------------------------ */
/* History table — live search / filter                               */
/* ------------------------------------------------------------------ */

(function initTableSearch() {
  const searchInput = document.getElementById("historySearch");
  if (!searchInput) return;

  const tableBody  = document.getElementById("historyTableBody");
  if (!tableBody) return;

  searchInput.addEventListener("input", function () {
    const query = this.value.toLowerCase();
    const rows  = tableBody.querySelectorAll("tr");

    rows.forEach(function (row) {
      const text = row.textContent.toLowerCase();
      row.style.display = text.includes(query) ? "" : "none";
    });
  });
})();


/* ------------------------------------------------------------------ */
/* Status-filter buttons on the history page                          */
/* ------------------------------------------------------------------ */

(function initStatusFilter() {
  const filterBtns = document.querySelectorAll("[data-filter]");
  if (!filterBtns.length) return;

  const tableBody = document.getElementById("historyTableBody");
  if (!tableBody) return;

  filterBtns.forEach(function (btn) {
    btn.addEventListener("click", function () {
      // Toggle active state
      filterBtns.forEach(function (b) { b.classList.remove("active"); });
      btn.classList.add("active");

      const filter = btn.getAttribute("data-filter").toLowerCase();
      const rows   = tableBody.querySelectorAll("tr");

      rows.forEach(function (row) {
        if (filter === "all") {
          row.style.display = "";
          return;
        }
        const statusCell = row.querySelector("[data-status]");
        if (!statusCell) { row.style.display = "none"; return; }
        row.style.display =
          statusCell.getAttribute("data-status").toLowerCase() === filter ? "" : "none";
      });
    });
  });
})();


/* ------------------------------------------------------------------ */
/* Tooltip initialisation (Bootstrap 5)                               */
/* ------------------------------------------------------------------ */

(function initTooltips() {
  if (typeof bootstrap === "undefined") return;
  const els = document.querySelectorAll('[data-bs-toggle="tooltip"]');
  els.forEach(function (el) {
    new bootstrap.Tooltip(el, { trigger: "hover" });
  });
})();


/* ------------------------------------------------------------------ */
/* Confirm dialog for destructive actions                             */
/* ------------------------------------------------------------------ */

(function initConfirmForms() {
  const forms = document.querySelectorAll("[data-confirm]");
  forms.forEach(function (form) {
    form.addEventListener("submit", function (e) {
      const msg = form.getAttribute("data-confirm") || "Are you sure?";
      if (!window.confirm(msg)) {
        e.preventDefault();
      }
    });
  });
})();


/* ------------------------------------------------------------------ */
/* Auto-dismiss flash messages after 5 s                              */
/* ------------------------------------------------------------------ */

(function autoDismissAlerts() {
  const alerts = document.querySelectorAll(".alert[data-auto-dismiss]");
  alerts.forEach(function (alert) {
    setTimeout(function () {
      const bsAlert = bootstrap && bootstrap.Alert && bootstrap.Alert.getOrCreateInstance(alert);
      if (bsAlert) bsAlert.close();
      else alert.style.display = "none";
    }, 5000);
  });
})();
