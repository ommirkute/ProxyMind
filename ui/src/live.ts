import { useEffect, useRef, useState } from "react";
import type { Counters } from "./api";

/**
 * The UI's one server-event connection (ADR-0018). `connectLive` opens a single EventSource for every topic the
 * UI reacts to and fans events out to subscribers; pages never open their own. Events say that something
 * changed (ids only), so a page refetches what it shows through the normal API.
 */

/** Topics the server publishes (the `counters` event is handled by `connectLive`'s caller). */
export type LiveTopic =
  | "exchanges"
  | "findings"
  | "approvals"
  | "audit"
  | "intercept"
  | "collaborator"
  | "websockets"
  | "scans"
  | "proofs"
  | "fuzzer"
  | "ai_scan";

const TOPICS: LiveTopic[] = [
  "exchanges",
  "findings",
  "approvals",
  "audit",
  "intercept",
  "collaborator",
  "websockets",
  "scans",
  "proofs",
  "fuzzer",
  "ai_scan",
];

/** What a subscriber gets: a typed event with its parsed JSON, or `resync` (refetch everything you show). */
export type LiveEvent = { topic: LiveTopic; data: Record<string, unknown> } | { topic: "resync"; data: { missed?: number } };

interface Subscriber {
  topics: ReadonlySet<LiveTopic>;
  fn: (e: LiveEvent) => void;
}

const subscribers = new Set<Subscriber>();

/** Delivers to subscribers of the topic; `resync` goes to everyone. A throwing handler does not stop the others. */
function dispatch(e: LiveEvent) {
  for (const s of [...subscribers]) {
    if (e.topic !== "resync" && !s.topics.has(e.topic)) continue;
    try {
      s.fn(e);
    } catch (err) {
      console.error("live event handler failed:", err);
    }
  }
}

/**
 * Opens the connection (call once, after sign-in) and returns a function that closes it. `onCounters` gets the nav
 * counters, `onState` whether the stream is up. EventSource reconnects by itself; every open after the first
 * counts as a resync, since events published while it was down are not replayed.
 */
export function connectLive(onCounters: (c: Counters) => void, onState: (up: boolean) => void): () => void {
  const es = new EventSource(`/api/v1/events?topics=counters,${TOPICS.join(",")}`);
  let opened = false;
  es.addEventListener("counters", (e) => onCounters(JSON.parse((e as MessageEvent).data)));
  for (const topic of TOPICS) {
    es.addEventListener(topic, (e) => {
      try {
        dispatch({ topic, data: JSON.parse((e as MessageEvent).data) });
      } catch {
        dispatch({ topic: "resync", data: {} }); // an event we cannot read: refetch instead of guessing
      }
    });
  }
  es.addEventListener("resync", (e) => {
    let data: { missed?: number } = {};
    try {
      data = JSON.parse((e as MessageEvent).data);
    } catch {
      // the resync itself is what matters
    }
    dispatch({ topic: "resync", data });
  });
  es.onopen = () => {
    onState(true);
    if (opened) dispatch({ topic: "resync", data: {} });
    opened = true;
  };
  es.onerror = () => onState(false);
  return () => es.close();
}

/** Calls `handler` for events of these topics (and for every `resync`). The latest handler is always used. */
export function useLiveEvent(topics: LiveTopic[], handler: (e: LiveEvent) => void) {
  const latest = useRef(handler);
  latest.current = handler;
  const key = topics.join(",");
  useEffect(() => {
    const s: Subscriber = { topics: new Set(key.split(",") as LiveTopic[]), fn: (e) => latest.current(e) };
    subscribers.add(s);
    return () => {
      subscribers.delete(s);
    };
  }, [key]);
}

/**
 * A number that goes up whenever one of these topics has an event (or on resync), for `useLoad` dependency
 * lists: `useLoad(load, [tick])` refetches on each change.
 */
export function useLiveTick(topics: LiveTopic[]): number {
  const [tick, setTick] = useState(0);
  useLiveEvent(topics, () => setTick((t) => t + 1));
  return tick;
}
