import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { studioApi } from "../api/client";
import { subscribeToAllEvents } from "../api/events";
import type {
  ActionDetail,
  ApprovalEvent,
  BenchReport,
  CoverageReport,
  GraphEdge,
  GraphNode,
  JudgmentTraceViewModel,
  RunSummary,
  ScenarioSpec,
  StudioEvent,
} from "../types";

export function useRunStore() {
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string>("");
  const [events, setEvents] = useState<StudioEvent[]>([]);
  const [graph, setGraph] = useState<{ nodes: GraphNode[]; edges: GraphEdge[] }>({ nodes: [], edges: [] });
  const [actionDetail, setActionDetail] = useState<ActionDetail | null>(null);
  const [actionJudgment, setActionJudgment] = useState<JudgmentTraceViewModel | null>(null);
  const [selectedActionId, setSelectedActionId] = useState<string>("");
  const [scenarios, setScenarios] = useState<ScenarioSpec[]>([]);
  const [approvals, setApprovals] = useState<ApprovalEvent[]>([]);
  const [bench, setBench] = useState<BenchReport>({ metrics: {}, samples: [] });
  const [coverage, setCoverage] = useState<CoverageReport>({ ok: false, mode: "unknown", missing: [], matrix: [] });
  const [health, setHealth] = useState<{ version: string; demo_mode: boolean } | null>(null);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<number | null>(null);
  const [liveStatus, setLiveStatus] = useState<"syncing" | "live" | "error">("syncing");
  const sourceRef = useRef<EventSource | null>(null);
  const runsRef = useRef<RunSummary[]>([]);
  const selectedRunIdRef = useRef<string>("");
  const refreshTimerRef = useRef<number | null>(null);
  const graphTimerRef = useRef<number | null>(null);

  const refreshRuns = useCallback(async (options: { autoSelectLatest?: boolean } = {}) => {
    setLiveStatus("syncing");
    try {
      const next = (await studioApi.runs()).runs;
      const knownRunIds = new Set(runsRef.current.map((run) => run.run_id));
      const latestRunId = next[0]?.run_id || "";
      const hasNewLatestRun = Boolean(latestRunId && !knownRunIds.has(latestRunId));
      runsRef.current = next;
      setRuns(next);
      if (latestRunId && (!selectedRunIdRef.current || (options.autoSelectLatest && hasNewLatestRun))) {
        selectedRunIdRef.current = latestRunId;
        setSelectedRunId(latestRunId);
      }
      setLastUpdatedAt(Date.now());
      setLiveStatus("live");
      return next;
    } catch (error) {
      setLiveStatus("error");
      throw error;
    }
  }, []);

  const refreshSecondary = useCallback(async () => {
    const [healthResult, scenarioResult, approvalResult, benchResult, coverageResult] = await Promise.all([
      studioApi.health(),
      studioApi.scenarios(),
      studioApi.approvals(),
      studioApi.bench(),
      studioApi.coverage(),
    ]);
    setHealth({ version: healthResult.version, demo_mode: healthResult.demo_mode });
    setScenarios(scenarioResult.scenarios);
    setApprovals(approvalResult.events);
    setBench(benchResult);
    setCoverage(coverageResult);
    setLastUpdatedAt(Date.now());
  }, []);

  const selectRun = useCallback(async (runId: string) => {
    setSelectedRunId(runId);
    selectedRunIdRef.current = runId;
    const [eventResult, graphResult] = await Promise.all([studioApi.events(runId), studioApi.graph(runId)]);
    setEvents(eventResult.events);
    setGraph(graphResult);
    setLastUpdatedAt(Date.now());
  }, []);

  const inspectAction = useCallback(async (actionId: string) => {
    setSelectedActionId(actionId);
    const [detail, judgment] = await Promise.all([studioApi.action(actionId), studioApi.judgment(actionId)]);
    setActionDetail(detail);
    setActionJudgment(judgment);
  }, []);

  const runScenario = useCallback(async (scenarioId: string) => {
    const result = await studioApi.runScenario(scenarioId);
    await refreshRuns();
    await refreshSecondary();
    await selectRun(result.result.trace_id);
  }, [refreshRuns, refreshSecondary, selectRun]);

  const grantApproval = useCallback(async (approvalId: string, actionHash: string) => {
    await studioApi.grant(approvalId, actionHash);
    const approvalResult = await studioApi.approvals();
    setApprovals(approvalResult.events);
  }, []);

  const denyApproval = useCallback(async (approvalId: string) => {
    await studioApi.deny(approvalId);
    const approvalResult = await studioApi.approvals();
    setApprovals(approvalResult.events);
  }, []);

  const exportEvidence = useCallback(async () => {
    if (!selectedRunId) return "";
    const result = await studioApi.exportEvidence(selectedRunId);
    return result.output;
  }, [selectedRunId]);

  const clearRecords = useCallback(async (backup: boolean) => {
    const result = await studioApi.clearRecords(backup);
    setRuns([]);
    runsRef.current = [];
    setSelectedRunId("");
    selectedRunIdRef.current = "";
    setEvents([]);
    setGraph({ nodes: [], edges: [] });
    setActionDetail(null);
    setActionJudgment(null);
    setSelectedActionId("");
    const approvalResult = await studioApi.approvals();
    setApprovals(approvalResult.events);
    return result;
  }, []);

  useEffect(() => {
    refreshRuns();
    refreshSecondary();
    sourceRef.current = subscribeToAllEvents((event) => {
      setLastUpdatedAt(Date.now());
      setLiveStatus("live");
      const knownRun = runsRef.current.some((run) => run.run_id === event.run_id);
      const shouldFocusIncomingRun = Boolean(event.run_id && (!selectedRunIdRef.current || !knownRun || event.type === "gateway_pre_call"));
      if (shouldFocusIncomingRun) {
        selectedRunIdRef.current = event.run_id;
        setSelectedRunId(event.run_id);
        setEvents([event]);
        setGraph({ nodes: [], edges: [] });
      } else if (event.run_id === selectedRunIdRef.current) {
        setEvents((existing) => existing.some((item) => item.event_id === event.event_id) ? existing : [...existing, event]);
      }
      if (refreshTimerRef.current) window.clearTimeout(refreshTimerRef.current);
      refreshTimerRef.current = window.setTimeout(() => {
        refreshRuns({ autoSelectLatest: true }).catch(() => undefined);
      }, 150);
      if (event.run_id === selectedRunIdRef.current || shouldFocusIncomingRun) {
        if (graphTimerRef.current) window.clearTimeout(graphTimerRef.current);
        graphTimerRef.current = window.setTimeout(() => {
          const currentRunId = selectedRunIdRef.current;
          if (!currentRunId) return;
          Promise.all([studioApi.events(currentRunId), studioApi.graph(currentRunId)]).then(([eventResult, graphResult]) => {
            setEvents(eventResult.events);
            setGraph(graphResult);
            setLastUpdatedAt(Date.now());
            setLiveStatus("live");
          }).catch(() => setLiveStatus("error"));
        }, 350);
      }
    });
    const runsTimer = window.setInterval(() => {
      refreshRuns({ autoSelectLatest: true }).then((nextRuns) => {
        const currentRunId = selectedRunIdRef.current;
        if (!currentRunId || !nextRuns.some((run) => run.run_id === currentRunId)) return;
        Promise.all([studioApi.events(currentRunId), studioApi.graph(currentRunId)]).then(([eventResult, graphResult]) => {
          setEvents(eventResult.events);
          setGraph(graphResult);
          setLastUpdatedAt(Date.now());
          setLiveStatus("live");
        }).catch(() => setLiveStatus("error"));
      }).catch(() => undefined);
    }, 2500);
    const secondaryTimer = window.setInterval(() => {
      refreshSecondary().catch(() => setLiveStatus("error"));
    }, 15000);
    return () => {
      window.clearInterval(runsTimer);
      window.clearInterval(secondaryTimer);
      if (refreshTimerRef.current) window.clearTimeout(refreshTimerRef.current);
      if (graphTimerRef.current) window.clearTimeout(graphTimerRef.current);
      sourceRef.current?.close();
    };
  }, [refreshRuns, refreshSecondary]);

  useEffect(() => {
    if (selectedRunId) selectRun(selectedRunId);
  }, [selectedRunId, selectRun]);

  const selectedRun = useMemo(() => runs.find((run) => run.run_id === selectedRunId) || null, [runs, selectedRunId]);

  return {
    runs,
    selectedRun,
    selectedRunId,
    events,
    graph,
    actionDetail,
    actionJudgment,
    selectedActionId,
    scenarios,
    approvals,
    bench,
    coverage,
    health,
    lastUpdatedAt,
    liveStatus,
    refreshRuns,
    refreshSecondary,
    selectRun,
    inspectAction,
    runScenario,
    grantApproval,
    denyApproval,
    exportEvidence,
    clearRecords,
  };
}
