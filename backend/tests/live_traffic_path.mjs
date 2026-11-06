import assert from 'node:assert/strict';
import {test} from 'node:test';
import {matchesLivePathPrefix} from '../../frontend/src/live-traffic-filter.ts';

test('live path prefix is literal, case sensitive and excludes query strings', () => {
  assert(matchesLivePathPrefix('/api/orders', '/api'));
  assert(matchesLivePathPrefix('/apix', '/api'));
  assert(!matchesLivePathPrefix('/API/orders', '/api'));
  assert(!matchesLivePathPrefix('/other/api', '/api'));
  assert(matchesLivePathPrefix('/orders?next=/api', '/orders'));
  assert(!matchesLivePathPrefix('/orders?next=/api', '/orders?'));
  assert(matchesLivePathPrefix('/literal_%/one', '/literal_%'));
  assert(matchesLivePathPrefix('Unavailable', ''));
  assert(!matchesLivePathPrefix('Unavailable', '/'));
});
