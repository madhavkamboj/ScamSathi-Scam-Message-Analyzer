export type RiskLevel = 'Low' | 'Medium' | 'High';

export type Warning = {
  id: string;
  category: string;
  title: string;
  explanation: string;
  severity: number;
};

export type AnalysisRecord = {
  id: string;
  message: string;
  riskScore: number;
  riskLevel: RiskLevel;
  warnings: Warning[];
  recommendations: string[];
  analyzedAt: string;
};

// Transparent scoring: a category contributes once even when several phrases match.
// Maximum raw score is capped at 100. Levels: Low 0–29, Medium 30–59, High 60–100.
const RULES = [
  {
    id: 'urgency',
    category: 'Urgency',
    title: 'Time pressure',
    weight: 14,
    patterns: [/\b(immediately|urgent|within\s+\d+\s*(minutes?|hours?)|act now|last chance|today only|expires? today|expires? in\s+\d+\s*(minutes?|hours?|days?))\b/i],
    explanation: 'The message pushes for a quick response, which can make it harder to verify the request calmly.',
  },
  {
    id: 'threat',
    category: 'Threat',
    title: 'Threat or account pressure',
    weight: 24,
    patterns: [/\b(account|card|sim|upi|service|connection).{0,45}\b(block(?:ed)?|suspend(?:ed)?|deactivat(?:ed|ion)|freeze|terminat(?:ed|ion))\b/i, /\b(block(?:ed)?|suspend(?:ed)?|deactivat(?:ed|ion)|freeze).{0,45}\b(account|card|sim|upi|service|connection)\b/i, /\b(legal action|police case|warrant|arrest)\b/i],
    explanation: 'A threat of account suspension or serious consequences is used to prompt action. Verify through a known official channel.',
  },
  {
    id: 'credentials',
    category: 'Credentials',
    title: 'Sensitive information request',
    weight: 34,
    patterns: [
      /\b(?:otp|one[- ]time password|pin|password|cvv|passcode)\b.{0,45}\b(?:share|send|provide|enter|reply|tell|submit|confirm|verify|disclose|give|forward|text)\b/i,
      /\b(?:share|send|provide|enter|reply|tell|submit|confirm|verify|disclose|give|forward|text)\b.{0,45}\b(?:(?:your|the|an?)\s+)?(?:otp|one[- ]time password|pin|password|cvv|passcode)\b/i,
    ],
    explanation: 'The message mentions a credential such as an OTP, PIN, password or CVV. Never share these, even with someone claiming to be support.',
  },
  {
    id: 'payment',
    category: 'Payment',
    title: 'Payment or refund pressure',
    weight: 24,
    patterns: [
      /\b(?:pay(?:ment)?|transfer|send money|upi|fee|charge|deposit|collect request)\b.{0,55}\b(?:now|immediately|urgent|within|must|expires?|today|to (?:receive|release|claim|unlock|avoid|prevent))\b/i,
      /\b(?:refund|reward|prize|delivery|account|service)\b.{0,55}\b(?:fee|charge|payment|pay|upi|collect request|deposit)\b/i,
      /\b(?:approve|accept)\b.{0,20}\b(?:upi|collect|payment|request)\b/i,
    ],
    explanation: 'A payment, fee, transfer or refund action is mentioned. A refund should not require you to reveal a PIN or approve an unexpected collect request.',
  },
  {
    id: 'shortener',
    category: 'Link',
    title: 'Shortened web address',
    weight: 24,
    patterns: [/\b(?:https?:\/\/)?(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly|rb\.gy|is\.gd|ow\.ly|shorturl\.at|tiny\.cc)\b/i],
    explanation: 'A URL shortener hides the destination. Do not open it; visit the organisation using its known app or typed address instead.',
  },
  {
    id: 'iphost',
    category: 'Link',
    title: 'IP-address web host',
    weight: 28,
    patterns: [/(?:https?:\/\/)?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/|$)/i],
    explanation: 'A web address appears to use a raw IP address rather than a recognisable domain, which is unusual for a customer-facing service.',
  },
];

const knownBrands = ['sbi', 'hdfc', 'icici', 'axis', 'paytm', 'phonepe', 'googlepay', 'amazon', 'flipkart', 'aadhaar', 'uidai', 'irdai', 'incometax'];
const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'cutt.ly', 'rb.gy', 'is.gd', 'ow.ly', 'shorturl.at', 'tiny.cc'];
const officialDomains = [
  'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'axisbank.com', 'paytm.com',
  'phonepe.com', 'google.com', 'amazon.in', 'amazon.com', 'flipkart.com',
  'uidai.gov.in', 'aadhaar.gov.in', 'irdai.gov.in', 'incometax.gov.in',
];

function extractUrls(message: string): string[] {
  return message.match(/(?:https?:\/\/|www\.)[^\s<>"')\]]+|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s<>"')\]]*)?/gi) ?? [];
}

function hasSuspiciousDomain(message: string): boolean {
  return extractUrls(message).some((raw) => {
    const candidate = raw.replace(/[.,!?;:]+$/, '').toLowerCase();
    const domain = candidate.replace(/^https?:\/\//, '').replace(/^www\./, '').split(/[/?#]/)[0].split(':')[0];
    if (!domain || shorteners.some((short) => domain === short || domain.endsWith(`.${short}`))) return false;
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(domain)) return false;
    if (officialDomains.some((official) => domain === official || domain.endsWith(`.${official}`))) return false;
    const parts = domain.split('.');
    if (parts.length > 2 && parts.slice(0, -2).some((part) => knownBrands.some((brand) => part.includes(brand)))) return true;
    return knownBrands.some((brand) => {
      const near = parts.some((part) => part.includes(brand) && part !== brand);
      const officialLooking = parts.some((part) => part === brand);
      return near || (officialLooking && !/(?:\.gov\.in|\.nic\.in)$/.test(domain) && !['amazon.in', 'paytm.com', 'phonepe.com', 'google.com', 'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'axisbank.com'].includes(domain));
    });
  });
}

function hasDeceptiveUrl(message: string): boolean {
  return extractUrls(message).some((raw) => {
    const candidate = raw.toLowerCase();
    return /@/.test(candidate) || /xn--/.test(candidate) || /(?:login|verify|secure|update|kyc|refund|bank|account)[-_][a-z0-9-]{2,}\./i.test(candidate) || /https?:\/\/[^/]*\.(?:com|net|in)\.[a-z]{2,}/i.test(candidate);
  });
}

export function analyzeMessage(message: string): AnalysisRecord {
  const warnings: Warning[] = RULES.filter((rule) => rule.patterns.some((pattern) => pattern.test(message))).map((rule) => ({
    id: rule.id,
    category: rule.category,
    title: rule.title,
    explanation: rule.explanation,
    severity: rule.weight,
  }));

  if (hasSuspiciousDomain(message)) {
    warnings.push({
      id: 'domain-lookalike',
      category: 'Link',
      title: 'Unusual or lookalike domain',
      explanation: 'A web address resembles a known brand or uses a non-standard domain. The analyser cannot confirm ownership; verify the address independently.',
      severity: 28,
    });
  }
  if (hasDeceptiveUrl(message)) {
    warnings.push({
      id: 'deceptive-url',
      category: 'Link',
      title: 'Deceptive URL pattern',
      explanation: 'The URL contains a pattern sometimes used to disguise its destination, such as an embedded user marker or misleading subdomain.',
      severity: 30,
    });
  }

  const riskScore = Math.min(100, warnings.reduce((sum, warning) => sum + warning.severity, 0));
  const riskLevel: RiskLevel = riskScore >= 60 ? 'High' : riskScore >= 30 ? 'Medium' : 'Low';
  const recommendations = new Set<string>();
  if (warnings.some((warning) => warning.category === 'Link')) recommendations.add('Do not open the link. If needed, open the organisation’s official app or type its known address yourself.');
  if (warnings.some((warning) => warning.category === 'Credentials')) recommendations.add('Never share an OTP, PIN, password or CVV. A legitimate support agent will not need them.');
  if (warnings.some((warning) => warning.category === 'Payment')) recommendations.add('Do not approve a collect request or pay an unexpected fee to receive a refund.');
  if (warnings.some((warning) => warning.category === 'Threat' || warning.category === 'Urgency')) recommendations.add('Pause and contact the organisation using a number or channel you already trust.');
  if (!warnings.length) recommendations.add('No listed warning pattern was detected. This is not proof that the message is safe; verify unexpected requests independently.');
  recommendations.add('If you already shared money or credentials, contact your bank immediately and use India’s cybercrime helpline 1930.');

  return {
    id: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
    message,
    riskScore,
    riskLevel,
    warnings,
    recommendations: [...recommendations],
    analyzedAt: new Date().toISOString(),
  };
}
