const CREDIT_CARD_KEYWORDS = [
  "card",
  "cardnumber",
  "ccnum",
  "pan",
  "creditcard",
  "debitcard",
];

const CVV_KEYWORDS = ["cvv", "cvc", "cv2", "securitycode", "cardverification", "cid"];
const EXPIRY_KEYWORDS = ["expiry", "expdate", "expiration", "expmonth", "expyear", "ccexp"];
const OTP_KEYWORDS = ["otp", "2fa", "token", "verificationcode", "verifycode", "authcode", "mfa", "smscode"];
const NATIONAL_ID_KEYWORDS = ["tc", "tckimlik", "tckn", "ssn", "passport", "national", "nationalid", "kimlik"];
const PASSWORD_KEYWORDS = ["password", "passwd", "pwd", "secret", "pin"];
const EMAIL_KEYWORDS = ["email", "emailaddress", "mail"];
const USERNAME_KEYWORDS = ["username", "user", "login", "userid", "account"];

function normalizeText(value) {
  return String(value || "")
    .toLowerCase()
    .trim()
    .replace(/[\s_-]+/g, "");
}

function getAttrValues(input) {
  return [input.type, input.name, input.id, input.placeholder, input.autocomplete]
    .map((v) => normalizeText(v))
    .filter(Boolean);
}

function matchesKeywords(attrValues, keywords) {
  return attrValues.some((value) => keywords.some((keyword) => value.includes(keyword)));
}

function classifyField(input) {
  if (!input) return { type: "unknown", confidence: 0 };

  const attrs = getAttrValues(input);
  const normalizedType = normalizeText(input.type);

  if (normalizedType === "password" || matchesKeywords(attrs, PASSWORD_KEYWORDS)) {
    return { type: "password", confidence: 95 };
  }
  if (matchesKeywords(attrs, CVV_KEYWORDS)) return { type: "cvv", confidence: 90 };
  if (matchesKeywords(attrs, CREDIT_CARD_KEYWORDS)) return { type: "credit_card", confidence: 88 };
  if (matchesKeywords(attrs, EXPIRY_KEYWORDS)) return { type: "expiry", confidence: 86 };
  if (matchesKeywords(attrs, OTP_KEYWORDS)) return { type: "otp_2fa", confidence: 85 };
  if (matchesKeywords(attrs, NATIONAL_ID_KEYWORDS)) return { type: "national_id", confidence: 82 };
  if (normalizedType === "email" || matchesKeywords(attrs, EMAIL_KEYWORDS)) return { type: "email", confidence: 90 };
  if (matchesKeywords(attrs, USERNAME_KEYWORDS)) return { type: "username", confidence: 75 };

  return { type: "unknown", confidence: 0 };
}

function classifyForm(form) {
  const emptyResult = {
    has_password: false,
    has_credit_card: false,
    has_otp: false,
    has_national_id: false,
    field_types: [],
  };
  if (!form) return emptyResult;

  const inputs = form.querySelectorAll("input, select, textarea");
  const fieldTypes = [];

  for (const input of inputs) {
    const { type } = classifyField(input);
    if (type === "unknown") continue;
    fieldTypes.push(type);
  }

  const uniqueTypes = [...new Set(fieldTypes)];
  return {
    has_password: uniqueTypes.includes("password"),
    has_credit_card: uniqueTypes.includes("credit_card") || uniqueTypes.includes("cvv") || uniqueTypes.includes("expiry"),
    has_otp: uniqueTypes.includes("otp_2fa"),
    has_national_id: uniqueTypes.includes("national_id"),
    field_types: uniqueTypes,
  };
}

export { classifyField, classifyForm };
