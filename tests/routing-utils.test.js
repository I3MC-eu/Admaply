const test = require('node:test');
const assert = require('node:assert/strict');

const {
  haversineDistanceMeters,
  isWayHikeable,
  buildGraphFromOverpass,
  shortestPath,
  fetchOpenRouteServiceSegment
} = require('../routing-utils');

test('isWayHikeable includes path with sac_scale=mountain_hiking', () => {
  assert.equal(isWayHikeable({ highway: 'path', sac_scale: 'mountain_hiking', foot: 'yes' }), true);
});

test('isWayHikeable excludes via_ferrata and private access', () => {
  assert.equal(isWayHikeable({ highway: 'via_ferrata', sac_scale: 'mountain_hiking' }), false);
  assert.equal(isWayHikeable({ highway: 'path', sac_scale: 'mountain_hiking', access: 'private' }), false);
});

test('isWayHikeable excludes sac_scale above mountain_hiking', () => {
  assert.equal(isWayHikeable({ highway: 'path', sac_scale: 'demanding_mountain_hiking' }), false);
  assert.equal(isWayHikeable({ highway: 'path', sac_scale: 'alpine_hiking' }), false);
});

test('buildGraphFromOverpass + shortestPath returns route distance on eligible ways', () => {
  const data = {
    elements: [
      { type: 'node', id: 1, lat: 48.0, lon: 14.0 },
      { type: 'node', id: 2, lat: 48.0, lon: 14.01 },
      { type: 'node', id: 3, lat: 48.0, lon: 14.02 },
      { type: 'node', id: 4, lat: 48.0, lon: 14.03 },
      { type: 'way', id: 10, nodes: [1, 2, 3], tags: { highway: 'path', sac_scale: 'mountain_hiking' } },
      { type: 'way', id: 11, nodes: [3, 4], tags: { highway: 'path', access: 'private' } }
    ]
  };

  const { graph } = buildGraphFromOverpass(data);
  const result = shortestPath(graph, 1, 3);
  assert.ok(result);
  assert.ok(result.distanceMeters > 1000);
  assert.equal(shortestPath(graph, 1, 4), null);
});

test('haversineDistanceMeters returns realistic geodesic distance', () => {
  const d = haversineDistanceMeters({ lat: 48.0, lng: 14.0 }, { lat: 48.0, lng: 14.01 });
  assert.ok(d > 700 && d < 800);
});


test('fetchOpenRouteServiceSegment reads hiking segment from backend endpoint', async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => ({
    ok: true,
    json: async () => ({
      route: {
        distanceMeters: 1234,
        coordinates: [{ lat: 48.1, lng: 14.1 }, { lat: 48.2, lng: 14.2 }],
        instructions: [{ text: 'Head north', distance: 250 }]
      }
    })
  });

  try {
    const result = await fetchOpenRouteServiceSegment({ lat: 48.1, lng: 14.1 }, { lat: 48.2, lng: 14.2 });
    assert.ok(result);
    assert.equal(result.distanceMeters, 1234);
    assert.equal(result.coordinates.length, 2);
    assert.equal(result.instructions.length, 1);
  } finally {
    global.fetch = originalFetch;
  }
});
