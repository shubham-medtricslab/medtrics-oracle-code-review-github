#!/usr/bin/env python3
"""
Connector adapter seam.

Deliberately defined in Phase 0 rather than Phase 5. v0.5.0's
`review-orchestrator` calls connectors inline at five of its seventeen steps
(blast-radius graph, Mem dedup warm tier, ticket contextualisation, lane move,
Slack DM). Introducing the seam after the write path is live would mean editing
production control flow to add it; introducing it now means Phase 4 only drops
implementations behind a stable interface.

The default for every adapter is `unconfigured`, which is a normal outcome and
never an error. A repo with no Optimus, no Slack and no Mem gets a complete
review with three `unconfigured` entries in its run record. v0.5.0 already
modelled this idea (`written_via: "none"`, `mem_degraded`); this makes it
uniform and testable.

Adapters never participate in the verdict. A ticket tracker being down must not
change whether a security finding is reported.

Stdlib only.
"""
from typing import Literal, Optional, Protocol, runtime_checkable

Outcome = Literal["unconfigured", "skipped", "ok", "failed"]


class AdapterResult:
    """Outcome of one adapter call. Never raises into the pipeline."""

    __slots__ = ("outcome", "detail", "ref")

    def __init__(self, outcome: Outcome, detail: str = "", ref: Optional[str] = None):
        self.outcome: Outcome = outcome
        self.detail = detail
        self.ref = ref

    def __repr__(self):
        return f"AdapterResult({self.outcome!r}, {self.detail!r})"

    @property
    def ok(self) -> bool:
        return self.outcome == "ok"


UNCONFIGURED = AdapterResult("unconfigured", "no configuration provided")


@runtime_checkable
class Adapter(Protocol):
    """Every connector implements this.

    `is_configured()` is checked before any call. An adapter that is not
    configured is never invoked, so implementations may assume configuration
    exists once they are called.
    """

    name: str

    def is_configured(self) -> bool: ...


class TicketTracker(Protocol):
    """Optimus today; any issue tracker tomorrow."""

    name: str

    def is_configured(self) -> bool: ...
    def resolve_ticket(self, *, branch: str, pr_title: str) -> AdapterResult: ...
    def append_context(self, *, ticket_id: str, markdown: str) -> AdapterResult: ...
    def move_lane(self, *, ticket_id: str, lane: str) -> AdapterResult: ...


class ChatNotifier(Protocol):
    """Slack today."""

    name: str

    def is_configured(self) -> bool: ...
    def notify_author(self, *, author: str, markdown: str) -> AdapterResult: ...
    def broadcast(self, *, channel: str, markdown: str) -> AdapterResult: ...


class MemoryStore(Protocol):
    """Mem warm tier layered over the local dedup store.

    When absent, dedup degrades to the local store only - which is correct, not
    broken. It must never cause a finding to be dropped.
    """

    name: str

    def is_configured(self) -> bool: ...
    def recall(self, *, key: str) -> AdapterResult: ...
    def remember(self, *, key: str, value: str) -> AdapterResult: ...


class GraphProvider(Protocol):
    """Repo-graph backed blast radius. Degrades to diff-only."""

    name: str

    def is_configured(self) -> bool: ...
    def dependents_of(self, *, symbol: str, depth: int) -> AdapterResult: ...


# --------------------------------------------------------------------------- #
# No-op defaults
# --------------------------------------------------------------------------- #
class _NullAdapter:
    """Answers `unconfigured` to everything. The default for every slot."""

    def __init__(self, name: str):
        self.name = name

    def is_configured(self) -> bool:
        return False

    def __getattr__(self, _item):
        def _call(*_args, **_kwargs):
            return UNCONFIGURED
        return _call


class Registry:
    """Holds one adapter per slot and records every outcome for the run record.

    `call` is the only entry point. It guarantees:
      - an unconfigured adapter is never invoked
      - an adapter exception becomes `failed`, never a pipeline crash
      - every attempt is recorded, so the run record reports all slots
    """

    SLOTS = ("ticket_tracker", "chat_notifier", "memory_store", "graph_provider")

    def __init__(self, **adapters):
        unknown = set(adapters) - set(self.SLOTS)
        if unknown:
            raise ValueError(f"unknown connector slots: {sorted(unknown)}")
        self._adapters = {
            slot: adapters.get(slot) or _NullAdapter(slot) for slot in self.SLOTS
        }
        self._outcomes = {slot: "unconfigured" for slot in self.SLOTS}

    def get(self, slot: str):
        return self._adapters[slot]

    def call(self, slot: str, method: str, **kwargs) -> AdapterResult:
        adapter = self._adapters[slot]
        if not adapter.is_configured():
            self._outcomes[slot] = "unconfigured"
            return UNCONFIGURED
        fn = getattr(adapter, method, None)
        if fn is None:
            self._outcomes[slot] = "skipped"
            return AdapterResult("skipped", f"{adapter.name} has no {method!r}")
        try:
            result = fn(**kwargs)
        except Exception as e:  # noqa: BLE001 - a connector must never break a review
            self._outcomes[slot] = "failed"
            return AdapterResult("failed", f"{type(e).__name__}: {e}")
        if not isinstance(result, AdapterResult):
            self._outcomes[slot] = "failed"
            return AdapterResult("failed", f"{adapter.name}.{method} returned non-AdapterResult")
        self._outcomes[slot] = result.outcome
        return result

    def outcomes(self) -> dict:
        """For run_record['connectors']. Every slot is always reported."""
        return dict(self._outcomes)
