import type { StudioEvent } from "../types";

function eventStreamUrl(path: string): string {
  const token = localStorage.getItem("agentbrakeFusionToken") || "agentbrake-fusion-local";
  const separator = path.includes("?") ? "&" : "?";
  return `${path}${separator}token=${encodeURIComponent(token)}`;
}

export function subscribeToRun(runId: string, onEvent: (event: StudioEvent) => void): EventSource {
  const source = new EventSource(eventStreamUrl(`/api/events/stream?run_id=${encodeURIComponent(runId)}`));
  source.addEventListener("studio_event", (message) => {
    onEvent(JSON.parse((message as MessageEvent).data) as StudioEvent);
  });
  return source;
}

export function subscribeToAllEvents(onEvent: (event: StudioEvent) => void): EventSource {
  const source = new EventSource(eventStreamUrl("/api/events/stream"));
  source.addEventListener("studio_event", (message) => {
    onEvent(JSON.parse((message as MessageEvent).data) as StudioEvent);
  });
  return source;
}
