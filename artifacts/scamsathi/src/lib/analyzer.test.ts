import assert from 'node:assert/strict';
import test from 'node:test';
import { analyzeMessage } from './analyzer.ts';

function hasCredentialWarning(message: string) {
  return analyzeMessage(message).warnings.some((warning) => warning.id === 'credentials');
}

function getPrizeFeeWarning(message: string) {
  return analyzeMessage(message).warnings.find((warning) => warning.id === 'prize-fee-scam');
}

test('does not penalize a security reminder that warns against sharing credentials', () => {
  const result = analyzeMessage(
    'Security reminder: Never share your OTP or PIN with anyone. Your bank will never ask you to disclose these details.',
  );

  assert.equal(result.riskScore, 0);
  assert.equal(result.riskLevel, 'Low');
  assert.equal(hasCredentialWarning(result.message), false);
});

test('recognizes common negative credential-safety phrases', () => {
  const warnings = [
    'Never share your OTP.',
    'Do not disclose your PIN.',
    'We will never ask for your password.',
    'Security tip: Never reveal your CVV to anyone.',
  ];

  for (const message of warnings) {
    assert.equal(hasCredentialWarning(message), false, message);
  }
});

test('flags a direct OTP request', () => {
  assert.equal(hasCredentialWarning('Please share the OTP with our support team.'), true);
});

test('still flags a credential request that contradicts reassuring language', () => {
  assert.equal(
    hasCredentialWarning('We will never ask for your password, but please send your password to verify.'),
    true,
  );
});

test('flags an account threat without changing its existing score', () => {
  const result = analyzeMessage('Your bank account will be blocked today unless you verify.');

  assert.ok(result.warnings.some((warning) => warning.id === 'threat'));
  assert.equal(result.riskScore, 24);
});

test('flags payment pressure without changing its existing score', () => {
  const result = analyzeMessage('Your refund is ready. Pay ₹29 via UPI now to release it.');

  assert.ok(result.warnings.some((warning) => warning.id === 'payment'));
  assert.equal(result.riskScore, 24);
});

test('keeps an ordinary appointment reminder at no risk', () => {
  const result = analyzeMessage('Your appointment is confirmed for Thursday at 4:30 pm.');

  assert.equal(result.warnings.length, 0);
  assert.equal(result.riskScore, 0);
  assert.equal(result.riskLevel, 'Low');
});

test('flags an unexpected prize claim requiring an upfront fee', () => {
  const message = 'Congratulations! You have won ₹50,000 in our lucky draw. Pay ₹500 processing fee immediately to claim your prize. Offer expires today!';
  const result = analyzeMessage(message);
  const warning = getPrizeFeeWarning(message);

  assert.ok(warning);
  assert.equal(warning.category, 'Prize');
  assert.equal(warning.title, 'Prize claim with upfront fee');
  assert.equal(warning.severity, 40);
  assert.match(warning.explanation, /unexpected prize claim.*advance payment.*strong scam warning sign/i);
  assert.ok(result.warnings.some((item) => item.id === 'urgency'));
  assert.ok(result.warnings.some((item) => item.id === 'payment'));
  assert.equal(result.riskLevel, 'High');
  assert.equal(result.riskScore, 78);
  assert.ok(result.recommendations.some((recommendation) => /do not pay an upfront fee/i.test(recommendation)));
});

test('does not flag a prize mention without an upfront payment request', () => {
  const message = 'Congratulations! You have won a prize in our lucky draw. Our team will contact you with details.';
  const result = analyzeMessage(message);

  assert.equal(getPrizeFeeWarning(message), undefined);
  assert.equal(result.riskLevel, 'Low');
});

test('does not flag safety advice against paying a prize fee', () => {
  const message = 'Never pay a processing fee to claim a prize.';

  assert.equal(getPrizeFeeWarning(message), undefined);
});

test('still flags an actual prize payment request after warning language', () => {
  const message = 'Never pay a processing fee to claim a prize, but pay ₹500 registration fee to receive your reward.';

  assert.ok(getPrizeFeeWarning(message));
});
