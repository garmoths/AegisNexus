import { classifyField, classifyForm } from "./field_classifier.js";

function getFormAction(form) {
  const action = (form.getAttribute("action") || "").trim();
  if (!action || action === "#") return null;
  return action;
}

function isActionDifferentDomain(form) {
  const action = getFormAction(form);
  if (!action) return false;

  try {
    const actionUrl = new URL(action, location.href);
    return actionUrl.hostname !== location.hostname;
  } catch {
    return action.startsWith("http");
  }
}

function isActionHttp(form) {
  const action = getFormAction(form);
  if (!action) return false;
  try {
    const actionUrl = new URL(action, location.href);
    return actionUrl.protocol === "http:";
  } catch {
    return action.startsWith("http://");
  }
}

function isInsideIframe(form) {
  try {
    return window.self !== window.top;
  } catch {
    return true;
  }
}

function countHiddenInputs(form) {
  return form.querySelectorAll('input[type="hidden"]').length;
}

function hasAutocompleteOff(form) {
  return form.autocomplete === "off" || form.autocomplete === "new-password";
}

function analyzeForm(form) {
  if (!form) return { score: 0, flags: [], risk_level: "SAFE" };

  const classification = classifyForm(form);
  let score = 0;
  const flags = [];

  if (classification.has_password) {
    score += 30;
    flags.push("form-has-password");
  }

  if (classification.has_credit_card) {
    score += 40;
    flags.push("form-has-credit-card");
  }

  if (classification.has_otp) {
    score += 20;
    flags.push("form-has-otp");
  }

  if (classification.has_national_id) {
    score += 35;
    flags.push("form-has-national-id");
  }

  if (isActionDifferentDomain(form)) {
    score += 40;
    flags.push("form-action-different-domain");
  }

  if (isActionHttp(form)) {
    score += 25;
    flags.push("form-action-http");
  }

  const hiddenCount = countHiddenInputs(form);
  if (hiddenCount > 3) {
    score += 15;
    flags.push("form-hidden-inputs");
  }

  if (hasAutocompleteOff(form)) {
    score += 10;
    flags.push("form-autocomplete-off");
  }

  const action = getFormAction(form);
  if (!action) {
    score += 10;
    flags.push("form-action-empty");
  }

  if (isInsideIframe(form)) {
    score += 30;
    flags.push("form-in-iframe");
  }

  score = Math.min(score, 100);

  let riskLevel = "SAFE";
  if (score <= 20) riskLevel = "SAFE";
  else if (score <= 40) riskLevel = "LOW";
  else if (score <= 60) riskLevel = "MEDIUM";
  else if (score <= 80) riskLevel = "HIGH";
  else riskLevel = "CRITICAL";

  return { score, flags: [...new Set(flags)], risk_level: riskLevel };
}

function scanPage() {
  const forms = document.querySelectorAll("form");
  let highestScore = 0;
  const suspiciousForms = [];
  const allFlags = [];

  forms.forEach((form, index) => {
    const result = analyzeForm(form);
    const details = getFormDetails(form);
    if (result.score > 0 && details) {
      suspiciousForms.push({
        form_index: index,
        score: result.score,
        flags: result.flags,
        risk_level: result.risk_level,
        action_url: details.action_url,
        field_types: details.field_types,
        field_names: details.field_names,
      });
    }
    if (result.score > highestScore) {
      highestScore = result.score;
    }
    allFlags.push(...result.flags);
  });

  let riskLevel = "SAFE";
  if (highestScore <= 20) riskLevel = "SAFE";
  else if (highestScore <= 40) riskLevel = "LOW";
  else if (highestScore <= 60) riskLevel = "MEDIUM";
  else if (highestScore <= 80) riskLevel = "HIGH";
  else riskLevel = "CRITICAL";

  return {
    form_count: forms.length,
    highest_risk_score: highestScore,
    risk_level: riskLevel,
    flags: [...new Set(allFlags)],
    suspicious_forms: suspiciousForms,
  };
}

function getFormDetails(form) {
  if (!form) return null;

  const inputs = form.querySelectorAll("input, select, textarea");
  const fields = [];
  const classification = classifyForm(form);

  for (const input of inputs) {
    const classified = classifyField(input);
    fields.push({
      type: classified.type,
      name: input.name || "",
      id: input.id || "",
      input_type: input.type || "",
    });
  }

  const actionUrl = (() => {
    const action = form.getAttribute("action");
    if (!action || action.trim() === "" || action.trim() === "#") return "";
    try {
      return new URL(action, location.href).toString();
    } catch {
      return action.trim();
    }
  })();

  return {
    action_url: actionUrl,
    field_types: classification.field_types,
    field_names: fields.map((f) => f.name || f.id || "").filter(Boolean),
    fields,
  };
}

export { analyzeForm, scanPage, getFormDetails };
