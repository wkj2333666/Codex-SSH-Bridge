# Poisoned Session Recovery Design

## Goal

Keep a cancelled or timed-out request from poisoning later calls on the same
SSH alias.

## Confirmed failure boundary

`HostSession::abort_request` waits briefly for the remote request's final
`EXIT`. When that acknowledgement does not arrive, the result correctly marks
`remote_process_may_continue`, but 0.5.2 leaves the same session in the
per-host cache. Later calls can therefore reuse a transport whose writer,
reader, helper, or remote request cleanup is no longer making progress.

## Design

An unconfirmed cancellation or timeout retires that `HostSession` from future
admission. Retirement is an atomic local state change with no hot-path network
round trip. Requests that already hold the old session keep their existing
request-scoped semantics; a later session lookup skips the retired instance
and establishes a fresh SSH/helper channel.

Confirmed request cancellation keeps the healthy session reusable. Transport
failure continues to close the session as before. The bridge does not replay
the cancelled or timed-out request.

This is generation replacement, not a daemon, heartbeat, watchdog, retry
queue, or global host reset.

## Verification

Automated coverage must prove that an unconfirmed cancellation causes the next
same-host request to start a second SSH session, while ordinary confirmed
completion still reuses the first session. Release verification then exercises
parallel search cancellation, same-host recovery, cross-host isolation, and
bounded timeout recovery against real SSH aliases.
