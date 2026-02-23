(function(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.RoutingUtils = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  const BLOCKED_ACCESS_VALUES = new Set(['no', 'private', 'customers', 'military']);
  const ALLOWED_HIGHWAYS = new Set(['path', 'footway', 'track', 'steps', 'bridleway']);
  const SAC_ALLOWED = new Set(['hiking', 'mountain_hiking']);

  function haversineDistanceMeters(a, b) {
    const toRad = (deg) => (deg * Math.PI) / 180;
    const R = 6371000;
    const dLat = toRad(b.lat - a.lat);
    const dLng = toRad(b.lng - a.lng);
    const lat1 = toRad(a.lat);
    const lat2 = toRad(b.lat);

    const x = Math.sin(dLat / 2) ** 2 + Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLng / 2) ** 2;
    return 2 * R * Math.asin(Math.sqrt(x));
  }

  function hasBlockedAccess(tags) {
    const candidates = [tags.access, tags.foot, tags.bicycle, tags.motor_vehicle];
    return candidates.some((value) => BLOCKED_ACCESS_VALUES.has(String(value || '').toLowerCase()));
  }

  function isWayHikeable(tags) {
    const highway = String(tags.highway || '').toLowerCase();
    if (!ALLOWED_HIGHWAYS.has(highway)) return false;
    if (String(tags.highway || '').toLowerCase() === 'via_ferrata') return false;
    if (hasBlockedAccess(tags)) return false;

    const trailVisibility = String(tags.trail_visibility || '').toLowerCase();
    if (trailVisibility === 'no') return false;

    const sacScale = String(tags.sac_scale || '').toLowerCase();
    if (!sacScale) return true;
    return SAC_ALLOWED.has(sacScale);
  }

  function buildGraphFromOverpass(overpass) {
    const nodes = new Map();
    const graph = new Map();

    for (const el of overpass.elements || []) {
      if (el.type === 'node') nodes.set(el.id, { lat: el.lat, lng: el.lon });
    }

    for (const el of overpass.elements || []) {
      if (el.type !== 'way' || !el.nodes || el.nodes.length < 2) continue;
      const tags = el.tags || {};
      if (!isWayHikeable(tags)) continue;

      for (let i = 0; i < el.nodes.length - 1; i++) {
        const aId = el.nodes[i];
        const bId = el.nodes[i + 1];
        const a = nodes.get(aId);
        const b = nodes.get(bId);
        if (!a || !b) continue;
        const distance = haversineDistanceMeters(a, b);

        if (!graph.has(aId)) graph.set(aId, []);
        if (!graph.has(bId)) graph.set(bId, []);
        graph.get(aId).push({ id: bId, distance });
        graph.get(bId).push({ id: aId, distance });
      }
    }

    return { nodes, graph };
  }

  function nearestNodeId(nodes, point) {
    let nearest = null;
    let best = Infinity;
    for (const [id, coord] of nodes.entries()) {
      const d = haversineDistanceMeters(point, coord);
      if (d < best) {
        best = d;
        nearest = id;
      }
    }
    return nearest;
  }

  function shortestPath(graph, startId, endId) {
    if (!graph.has(startId) || !graph.has(endId)) return null;
    const dist = new Map([[startId, 0]]);
    const prev = new Map();
    const queue = [{ id: startId, distance: 0 }];
    const visited = new Set();

    while (queue.length) {
      queue.sort((a, b) => a.distance - b.distance);
      const current = queue.shift();
      if (!current || visited.has(current.id)) continue;
      visited.add(current.id);
      if (current.id === endId) break;

      for (const edge of graph.get(current.id) || []) {
        if (visited.has(edge.id)) continue;
        const currentDistance = dist.has(current.id) ? dist.get(current.id) : Infinity;
        const next = currentDistance + edge.distance;
        const knownEdgeDistance = dist.has(edge.id) ? dist.get(edge.id) : Infinity;
        if (next < knownEdgeDistance) {
          dist.set(edge.id, next);
          prev.set(edge.id, current.id);
          queue.push({ id: edge.id, distance: next });
        }
      }
    }

    if (!dist.has(endId)) return null;
    const path = [endId];
    let cursor = endId;
    while (cursor !== startId) {
      cursor = prev.get(cursor);
      if (cursor === undefined) return null;
      path.push(cursor);
    }
    path.reverse();
    return { nodePath: path, distanceMeters: dist.get(endId) };
  }

  function computeBbox(start, end, marginKm) {
    const marginDeg = Math.max(0.01, marginKm / 111);
    return {
      south: Math.min(start.lat, end.lat) - marginDeg,
      west: Math.min(start.lng, end.lng) - marginDeg,
      north: Math.max(start.lat, end.lat) + marginDeg,
      east: Math.max(start.lng, end.lng) + marginDeg
    };
  }


  async function fetchOpenRouteServiceSegment(start, end) {
    const params = new URLSearchParams({
      start: `${start.lat},${start.lng}`,
      end: `${end.lat},${end.lng}`
    });
    const res = await fetch(`/api/routing/hiking?${params.toString()}`);
    if (!res.ok) return null;
    const data = await res.json().catch(() => null);
    if (!data || !data.route || !Array.isArray(data.route.coordinates) || data.route.coordinates.length < 2) return null;
    return {
      coordinates: data.route.coordinates,
      distanceMeters: Number(data.route.distanceMeters) || 0,
      instructions: Array.isArray(data.route.instructions) ? data.route.instructions : []
    };
  }

  async function fetchTrailRouteSegment(start, end) {
    const straightKm = haversineDistanceMeters(start, end) / 1000;
    const marginKm = Math.max(2.5, straightKm * 0.7);
    const bbox = computeBbox(start, end, marginKm);

    const query = `[out:json][timeout:25];\n(\n  way["highway"](${bbox.south},${bbox.west},${bbox.north},${bbox.east});\n  >;\n);\nout body;`;
    const url = `https://overpass-api.de/api/interpreter?data=${encodeURIComponent(query)}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Trail graph lookup failed');
    const data = await res.json();

    const { nodes, graph } = buildGraphFromOverpass(data);
    const startNode = nearestNodeId(nodes, start);
    const endNode = nearestNodeId(nodes, end);
    if (!startNode || !endNode) return null;

    const result = shortestPath(graph, startNode, endNode);
    if (!result) return null;

    const coordinates = result.nodePath.map((id) => nodes.get(id)).filter(Boolean);
    return {
      coordinates,
      distanceMeters: result.distanceMeters
    };
  }

  return {
    haversineDistanceMeters,
    isWayHikeable,
    buildGraphFromOverpass,
    shortestPath,
    fetchOpenRouteServiceSegment,
    fetchTrailRouteSegment
  };
});
