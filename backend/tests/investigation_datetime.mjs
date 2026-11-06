import assert from 'node:assert/strict';
import {test} from 'node:test';
import {toPickerDateTime, fromPickerDateTime} from '../../frontend/src/investigation-datetime.ts';

test('investigation picker converts local date/time to Unix milliseconds', () => {
  const local = new Date(2026, 10, 2, 14, 35, 42);
  assert.equal(toPickerDateTime(String(local.getTime())), '2026-11-02 14:35:42');
  assert.equal(fromPickerDateTime('2026-11-02 14:35:42'), String(local.getTime()));
  assert.equal(toPickerDateTime(''), null);
  assert.equal(fromPickerDateTime(null), '');
  assert.equal(toPickerDateTime('invalid'), null);
});
