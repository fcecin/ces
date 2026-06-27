# peerclusterer

A `/s/` extension that nudges the host's peer table into closed cliques
("clusters") of a target size. It is stigmergic: there is no consensus, no votes,
and no shared notion of "what the group is". Each node periodically tells its
peers its own peer list (the pheromone) over the `/ces/peer/1` mesh, folds in the
lists it hears to build a 2-hop view, and each slow tick makes ONE greedy
triadic-closure move toward closing a clique around itself. Convergence is
emergent and measurable, the lineage being ant/boid swarm optimization.

It rides the discovery + peerfunder layers: discovery keeps the peer table
populated (the raw graph to find dense sets in), peerfunder makes the chosen
peerings economically live, and peerclusterer spends the table's headroom closing
cliques within that graph.

## What it points at, and what it reclaims

The clusterer only POINTS: it adds peers toward a clique. It does not make peers
actually sync -- the C++ peer maintenance does that over time (probe, link,
keepalive). So it never over-points: once it has pointed at `group_size - 1`
cluster-relevant peers (confirmed members plus pending adds), it stops and waits
for the links to come up. Adding more while waiting would just pile on excess
peers, since linking lags pointing.

It is otherwise add-only, with ONE scoped exception: a peer the clusterer ITSELF
added that, after a long settle window (`dud_timeout_ms`, default 24h), never
became a real cluster member is a dud, and the clusterer reclaims it
(`ces.remove_peer`). This is safe and destroys no value: a peering that never
became live + economically committed never built a meaningful reserve. The
clusterer never touches a peer it did not add (operator, config, discovery, or
sticky peers are off-limits), and a reclaimed dud is never re-recruited.

A peer is a real cluster member ("fulfilled") only when it BOTH reciprocates over
the mesh AND has reciprocated at least `peer_credit_target` lifetime inbound PoW
-- the "this peer is committed to the peering" signal (lifetime PoW, not balance,
which drains via transfers and gossip). A reciprocating peer with sub-target PoW
after the settle window is "not excited about the peering" and is reclaimed.

The server peer table is a fixed 100-persisted / 200-in-mem (compiled-in
constants, not configurable). `max_peers` defaults to 80, a 20-slot buffer under
the persisted 100, so the clusterer always leaves headroom for discovery's peers,
operator peers, and inbound churn. In practice it stops well before the cap (it
idles once its clique of `group_size` closes), so the cap is only a backstop.

## Speakers only

A peer counts toward a cluster only if it actually runs peerclusterer. The mesh
routes a service-tagged message to the one local instance that registered that
service, so you only ever hear back from peers that speak peerclusterer; a peer
that is merely connected but has the extension disabled is never counted nor
recruited. A candidate is recruited only when a peer you have heard vouches it is
a speaker too.

## Config (`/s/peerclusterer.conf`)

```
group_size = 20              # clique size the clusterer closes around the host
max_peers = 80               # 20-slot buffer under the fixed server 100 limit
tick_ms = 5000               # gossip one pheromone + make one move per tick
gossip_cap = 64              # peers advertised per gossip frame
peer_credit_target = 500000000  # 5 full credits lifetime inbound PoW to count
                                # a peer as a real member; 0 = link-liveness only
dud_timeout_ms = 86400000    # 24h settle before reclaiming one of its own duds
```

`group_size` is a target: keep trying to cluster up to N; once a closed clique of
N members holds, go idle. Multiple clusters of varying size form across the
network as an emergent consequence of every node nudging toward its own clique.

`peer_credit_target` should not exceed the server's `peer_target` (the reserve
the peer miner maintains on each peer): a peer can only reciprocate as much PoW
as the network mines. Both default to 5 credits.

## Relay commands (`cesh dial <pid>`)

- `status` - peers, core size, total adds, total culls, ticks, last action
- `view`   - the 2-hop view: each known node and its peer count (`*` marks self)
