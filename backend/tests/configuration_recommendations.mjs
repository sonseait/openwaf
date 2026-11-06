import assert from 'node:assert/strict';
import {test} from 'node:test';
import {isConfigurationRecommendation} from '../../frontend/src/configuration-recommendations.ts';

test('optional hardening advice is separate from configuration warnings', () => {
  assert.equal(isConfigurationRecommendation('multipart_body_skipped'), true);
  assert.equal(isConfigurationRecommendation('missing_quota'), true);
  for (const code of ['full_body_cap', 'password_prefix_override', 'short_stream_deadline', 'backend_dedup', 'unknown_future_warning']) {
    assert.equal(isConfigurationRecommendation(code), false);
  }
});
