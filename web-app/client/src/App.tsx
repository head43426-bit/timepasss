import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { SafeAreaTopScrim } from "@hatch/space-sdk/client";
import { api, type ApiResponse } from "./api";

type Detail = ApiResponse<typeof api, "getIncident">;
type Step = Detail["steps"][number];

const CHAPTERS = [
  { n: "01", id: "ch-missions", label: "Missions" },
  { n: "02", id: "ch-feed", label: "Feed the machine" },
  { n: "03", id: "ch-line", label: "The line" },
  { n: "04", id: "ch-rules", label: "Rules file" },
  { n: "05", id: "ch-engine", label: "Engine" },
  { n: "06", id: "ch-report", label: "Report" },
];

const WEIGHTS: Record<string, number> = { Critical: 40, High: 25, Medium: 10, Low: 3 };

function riskOf(steps: Pick<Step, "stage" | "severity">[]): number {
  const total = steps.reduce((s, d) => s + (WEIGHTS[d.severity] ?? 10), 0);
  const stages = new Set(steps.map((d) => d.stage));
  let score = 0.3 * total + 3 * stages.size;
  if (steps.some((d) => d.stage === "Exfiltration")) score += 15;
  if (steps.some((d) => d.stage === "Privilege Escalation" || d.stage === "Credential Access")) score += 10;
  return Math.round(Math.min(100, score) * 10) / 10;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      return true;
    } catch {
      return false;
    }
  }
}

function downloadText(filename: string, text: string): void {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

const LIVE_FEED_BATCHES: string[][] = [
  [
    '{"time":"2026-10-31T09:02:00","host":"LAP-118","user":"meera.nair","ip":"10.0.4.18","source":"workstation","action":"port scan detected","detail":"port scan against internal hosts","severity":"High"}',
    '{"time":"2026-10-31T09:11:00","host":"LAP-118","user":"meera.nair","ip":"10.0.4.18","source":"workstation","action":"email opened","detail":"phishing email opened on LAP-118","severity":"High"}',
  ],
  [
    '{"time":"2026-10-31T09:26:00","host":"FS-03","user":"meera.nair","ip":"10.0.4.18","source":"workstation","action":"smb lateral movement","detail":"lateral movement to FS-03","severity":"High"}',
    '{"time":"2026-10-31T09:31:00","host":"FS-03","user":"meera.nair","ip":"10.0.4.18","source":"workstation","action":"credential dump detected","detail":"lsass memory accessed, credential dump","severity":"Critical"}',
  ],
  [
    '{"time":"2026-10-31T09:44:00","host":"FS-03","user":"meera.nair","ip":"10.0.4.18","source":"workstation","action":"data upload","detail":"upload to an outside IP from FS-03","severity":"Critical"}',
  ],
];

// ---------------------------------------------------------------------------
// Flat vector illustration: log browser, phone, terminal, rack, database.
// Drawn in code; no reference artwork is reused.
// ---------------------------------------------------------------------------

function FactoryIllustration({ lines, detections, incidents }: { lines: number; detections: number; incidents: number }) {
  return (
    <svg viewBox="0 0 560 340" className="h-auto w-full" role="img" aria-label="Flat illustration of a log browser, a phone, a terminal, a server rack and a database cylinder">
      {/* browser window */}
      <rect x="28" y="30" width="240" height="170" rx="6" fill="#FBF8EF" />
      <rect x="28" y="30" width="240" height="26" rx="6" fill="#E8241A" />
      <rect x="28" y="48" width="240" height="8" fill="#E8241A" />
      <circle cx="46" cy="43" r="5" fill="#FBF8EF" />
      <circle cx="62" cy="43" r="5" fill="#FBF8EF" />
      <circle cx="78" cy="43" r="5" fill="#FBF8EF" />
      <rect x="44" y="72" width="150" height="14" fill="#111114" />
      <rect x="44" y="96" width="196" height="8" fill="#D8D0BA" />
      <rect x="44" y="112" width="160" height="8" fill="#D8D0BA" />
      <rect x="44" y="128" width="180" height="8" fill="#D8D0BA" />
      <rect x="44" y="152" width="86" height="26" rx="13" fill="#E8241A" />
      <rect x="206" y="72" width="48" height="48" fill="#E9E2CF" />
      <path d="M206 108 L226 84 L238 98 L246 88 L254 108 Z" fill="#111114" />
      <circle cx="242" cy="80" r="7" fill="#E8241A" />
      {/* phone straddling the middle */}
      <rect x="238" y="150" width="86" height="168" rx="14" fill="#111114" />
      <rect x="247" y="164" width="68" height="140" rx="6" fill="#FBF8EF" />
      <rect x="247" y="164" width="68" height="20" fill="#E8241A" />
      <rect x="255" y="198" width="52" height="26" rx="3" fill="#E9E2CF" />
      <rect x="255" y="232" width="52" height="26" rx="3" fill="#E9E2CF" />
      <rect x="255" y="268" width="34" height="8" fill="#D8D0BA" />
      {/* terminal */}
      <rect x="330" y="42" width="204" height="132" rx="6" fill="#232529" />
      <rect x="330" y="42" width="204" height="22" rx="6" fill="#2A2C31" />
      <rect x="330" y="56" width="204" height="8" fill="#2A2C31" />
      <circle cx="346" cy="53" r="4" fill="#A3A0A8" />
      <circle cx="360" cy="53" r="4" fill="#A3A0A8" />
      <circle cx="374" cy="53" r="4" fill="#A3A0A8" />
      <text x="346" y="88" fill="#F2A007" fontSize="13" fontFamily="ui-monospace, monospace">$ detect --rules sigma</text>
      <text x="346" y="110" fill="#FBF8EF" fontSize="13" fontFamily="ui-monospace, monospace">{`${lines.toLocaleString()} lines read`}</text>
      <text x="346" y="132" fill="#F2A007" fontSize="13" fontFamily="ui-monospace, monospace">{`${detections} flagged · ${incidents} linked`}</text>
      <text x="346" y="156" fill="#FBF8EF" fontSize="13" fontFamily="ui-monospace, monospace">$ link --window 48h</text>
      <rect x="346" y="162" width="10" height="16" fill="#F2A007" />
      {/* server rack */}
      <rect x="330" y="196" width="96" height="122" fill="#232529" />
      <rect x="338" y="206" width="80" height="20" fill="#2A2C31" />
      <rect x="338" y="232" width="80" height="20" fill="#2A2C31" />
      <rect x="338" y="258" width="80" height="20" fill="#2A2C31" />
      <rect x="338" y="284" width="80" height="20" fill="#2A2C31" />
      <circle cx="348" cy="216" r="4" fill="#F2A007" />
      <circle cx="360" cy="216" r="4" fill="#E8241A" />
      <circle cx="348" cy="242" r="4" fill="#F2A007" />
      <circle cx="360" cy="242" r="4" fill="#F2A007" />
      <circle cx="348" cy="268" r="4" fill="#E8241A" />
      <circle cx="348" cy="294" r="4" fill="#F2A007" />
      {/* database cylinder */}
      <ellipse cx="482" cy="216" rx="46" ry="14" fill="#2A2C31" />
      <path d="M436 216 L436 300 A46 14 0 0 0 528 300 L528 216" fill="#232529" />
      <path d="M436 244 A46 14 0 0 0 528 244" fill="none" stroke="#3A3D44" strokeWidth="3" />
      <path d="M436 272 A46 14 0 0 0 528 272" fill="none" stroke="#3A3D44" strokeWidth="3" />
      <ellipse cx="482" cy="216" rx="46" ry="14" fill="#2A2C31" />
      <text x="482" y="272" fill="#F2A007" fontSize="15" textAnchor="middle" fontFamily="ui-monospace, monospace">DB</text>
      {/* connector lines */}
      <path d="M426 174 C 426 190, 378 186, 378 196" fill="none" stroke="#F2A007" strokeWidth="2" />
      <path d="M482 188 C 482 192, 482 190, 482 202" fill="none" stroke="#F2A007" strokeWidth="2" />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Host / user graph (SVG, deterministic layout)
// ---------------------------------------------------------------------------

function GraphView({ detail, focus, onFocus }: { detail: Detail; focus: string | null; onFocus: (n: string | null) => void }) {
  const hosts = detail.incident.hosts;
  const users = detail.incident.users;
  const W = 640;
  const H = 250;
  const hostPos = useMemo(() => {
    const m = new Map<string, { x: number; y: number }>();
    hosts.forEach((h, i) => m.set(h, { x: hosts.length === 1 ? W / 2 : 50 + (i * (W - 100)) / Math.max(1, hosts.length - 1), y: 196 }));
    return m;
  }, [hosts]);
  const userPos = useMemo(() => {
    const m = new Map<string, { x: number; y: number }>();
    users.forEach((u, i) => m.set(u, { x: users.length === 1 ? W / 2 : 50 + (i * (W - 100)) / Math.max(1, users.length - 1), y: 54 }));
    return m;
  }, [users]);
  const connectedTo = (node: string): boolean => {
    if (!focus) return true;
    return detail.edges.some((e) => (e.from === focus && e.to === node) || (e.to === focus && e.from === node)) || focus === node;
  };
  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" role="img" aria-label="Host and user graph for this incident">
        {detail.edges.map((e, i) => {
          const a = userPos.get(e.from) ?? hostPos.get(e.from);
          const b = userPos.get(e.to) ?? hostPos.get(e.to);
          if (!a || !b) return null;
          const dim = !connectedTo(e.from) || !connectedTo(e.to);
          return (
            <g key={i} opacity={dim ? 0.25 : 1}>
              <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={e.kind === "path" ? "#E8241A" : "#F2A007"} strokeWidth={e.kind === "path" ? 3 : 2} strokeDasharray={e.kind === "path" ? "7 5" : undefined} />
              <text x={(a.x + b.x) / 2 + 4} y={(a.y + b.y) / 2 - 4} fill="#A3A0A8" fontSize="11" fontFamily="ui-monospace, monospace">{e.techniqueId}</text>
            </g>
          );
        })}
        {users.map((u) => {
          const p = userPos.get(u);
          if (!p) return null;
          const active = focus === u;
          return (
            <g key={`u-${u}`}>
              <rect x={p.x - 52} y={p.y - 18} width="104" height="36" rx="3" fill={active ? "#E8241A" : "#2A2C31"} stroke="#F2A007" strokeWidth="1.5" />
              <text x={p.x} y={p.y + 4} fill="#FBF8EF" fontSize="12" textAnchor="middle" fontFamily="ui-monospace, monospace">{u}</text>
              <text x={p.x} y={p.y - 26} fill="#A3A0A8" fontSize="10" textAnchor="middle" fontFamily="ui-monospace, monospace">USER</text>
            </g>
          );
        })}
        {hosts.map((h) => {
          const p = hostPos.get(h);
          if (!p) return null;
          const active = focus === h;
          return (
            <g key={`h-${h}`}>
              <rect x={p.x - 52} y={p.y - 18} width="104" height="36" rx="3" fill={active ? "#E8241A" : "#FBF8EF"} stroke="#111114" strokeWidth="1.5" />
              <text x={p.x} y={p.y + 4} fill={active ? "#FBF8EF" : "#111114"} fontSize="12" textAnchor="middle" fontFamily="ui-monospace, monospace">{h}</text>
              <text x={p.x} y={p.y - 26} fill="#A3A0A8" fontSize="10" textAnchor="middle" fontFamily="ui-monospace, monospace">HOST</text>
            </g>
          );
        })}
      </svg>
      <div className="mt-2 flex flex-wrap gap-2" aria-label="Highlight a node in the graph">
        {[...users.map((u) => ({ label: u, kind: "user" })), ...hosts.map((h) => ({ label: h, kind: "host" }))].map((n) => (
          <button
            key={n.label}
            type="button"
            onClick={() => onFocus(focus === n.label ? null : n.label)}
            aria-pressed={focus === n.label}
            className={`font-mono-label border px-2 py-1 text-[11px] ${focus === n.label ? "border-[#E8241A] bg-[#E8241A] text-[#FBF8EF]" : "border-[#3A3D44] bg-transparent text-[#FBF8EF] hover:border-[#F2A007]"}`}
          >
            {n.kind} · {n.label}
          </button>
        ))}
      </div>
      <p className="font-mono-label mt-1 text-[11px] text-[#A3A0A8]">
        {focus ? `Showing connections for ${focus} - tap it again to clear.` : "Tap a host or user to highlight its connections. Amber lines are events; dashed red lines are the path between hosts."}
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Conveyor belt: one package per step, in timeline order.
// ---------------------------------------------------------------------------

function BeltView({
  steps, selected, onSelect, playing, onTogglePlay,
}: {
  steps: Step[];
  selected: number;
  onSelect: (i: number) => void;
  playing: boolean;
  onTogglePlay: () => void;
}) {
  const trackRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = trackRef.current?.querySelector<HTMLElement>(`#pkg-${selected}`);
    el?.scrollIntoView({ behavior: "smooth", inline: "center", block: "nearest" });
  }, [selected]);
  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <p className="font-mono-label text-[11px] text-[#A3A0A8]">Packaging line - each step rides the belt as its own package</p>
        <button
          type="button"
          onClick={onTogglePlay}
          aria-pressed={playing}
          className="font-mono-label border border-[#F2A007] bg-[#E8241A] px-3 py-1.5 text-[11px] text-[#FBF8EF] hover:bg-[#B3120C]"
        >
          {playing ? "■ Stop the belt" : "▶ Run the belt"}
        </button>
      </div>
      <div className="overflow-hidden border-2 border-[#111114] bg-[#1D1E22] p-2">
        <div ref={trackRef} className="belt-scroll flex gap-3 overflow-x-auto pb-1" aria-label="Incident steps as packages on a conveyor belt">
          {steps.map((step, i) => {
            const isSel = i === selected;
            const isExfil = step.stage === "Exfiltration";
            return (
              <button
                key={step.id}
                id={`pkg-${i}`}
                type="button"
                onClick={() => onSelect(i)}
                aria-label={`Step ${i + 1}: ${step.techniqueName}, ${step.stage}, on ${step.host}`}
                aria-current={isSel}
                className={`package-in relative w-[168px] shrink-0 text-left ${isSel ? "outline-4 outline-[#E8241A]" : "outline-1 outline-[#D8D0BA]"}`}
                style={{ animationDelay: `${Math.min(i * 90, 600)}ms` }}
              >
                <span className={`block h-3 w-full ${isExfil ? "hazard-red" : "hazard"}`} aria-hidden="true" />
                <span className="relative block bg-[#FBF8EF] px-3 pt-2 pb-3 text-[#111114]">
                  <span className="font-mono-label block text-[10px] text-[#6F6A5C]">PKG {String(i + 1).padStart(2, "0")} · {step.stage}</span>
                  <span className="font-display mt-1 block text-[17px] leading-tight">{step.techniqueId}</span>
                  <span className="mt-1 block text-[13px] leading-snug font-semibold">{step.techniqueName}</span>
                  <span className="font-mono-label mt-2 block text-[10px]">{step.host} · {step.user}</span>
                  <span className="font-mono-label mt-1 block text-[10px] text-[#6F6A5C]">{step.time.replace("T", " ")}</span>
                  {i === 0 && (
                    <span className="stamp-in absolute top-8 right-2 rotate-[-10deg] border-2 border-[#E8241A] px-1 py-0.5 font-mono-label text-[9px] text-[#E8241A]">First step</span>
                  )}
                  {isExfil && (
                    <span className="stamp-in absolute top-8 right-2 rotate-[-10deg] border-2 border-[#B3120C] bg-[#FBF8EF] px-1 py-0.5 font-mono-label text-[9px] text-[#B3120C]">Exfil</span>
                  )}
                </span>
                <span className="block bg-[#111114] px-3 py-1.5 font-mono-label text-[10px] text-[#F2A007]">
                  {isSel ? "● On the line" : "○ Tap for detail"}
                </span>
              </button>
            );
          })}
        </div>
        <div className={`hazard belt-moving mt-2 h-4 w-full`} aria-hidden="true" />
        <div className="mt-1 flex justify-between font-mono-label text-[10px] text-[#A3A0A8]" aria-hidden="true">
          <span>◉ ◉ ◉</span>
          <span>Conveyor · {steps.length} packages</span>
          <span>◉ ◉ ◉</span>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

export function App() {
  const queryClient = useQueryClient();
  const [datasetId, setDatasetId] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<number | null>(null);
  const [stepIndex, setStepIndex] = useState(0);
  const [blockedStep, setBlockedStep] = useState<number | null>(null);
  const [graphFocus, setGraphFocus] = useState<string | null>(null);
  const [beltPlaying, setBeltPlaying] = useState(false);
  const [reportLang, setReportLang] = useState<"en" | "hi">("en");
  const [copied, setCopied] = useState(false);
  const [rulesText, setRulesText] = useState<string | null>(null);
  const [rulesMessage, setRulesMessage] = useState("");
  const [armedDelete, setArmedDelete] = useState<string | null>(null);
  const [uploadState, setUploadState] = useState<{ fileName: string; done: number; total: number; detections: number; phase: string } | null>(null);
  const [uploadError, setUploadError] = useState("");
  const [liveText, setLiveText] = useState("");
  const [liveStatus, setLiveStatus] = useState("");
  const [streamState, setStreamState] = useState<{ batch: number; batches: number; total: number; detections: number; running: boolean; done: boolean } | null>(null);
  const [feedRunning, setFeedRunning] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);

  const datasetsQuery = useQuery({ queryKey: ["datasets"], queryFn: () => api.listDatasets({}) });
  const datasets = datasetsQuery.data?.datasets ?? [];
  const activeDatasetId = datasetId ?? datasets[0]?.id ?? "synthetic";
  const activeDataset = datasets.find((d) => d.id === activeDatasetId);

  const incidentsQuery = useQuery({
    queryKey: ["incidents", activeDatasetId],
    queryFn: () => api.listIncidents({ datasetId: activeDatasetId }),
  });
  const incidents = incidentsQuery.data?.incidents ?? [];
  const activeIncident = incidents.find((i) => i.id === selectedIncidentId) ?? incidents[0];
  const activeIncidentId = activeIncident?.id;

  const detailQuery = useQuery({
    queryKey: ["incident", activeIncidentId],
    queryFn: () => api.getIncident({ incidentId: activeIncidentId ?? 0 }),
    enabled: activeIncidentId !== undefined,
  });
  const detail = detailQuery.data;

  const rulesQuery = useQuery({ queryKey: ["rules"], queryFn: () => api.getRules({}) });
  const factsQuery = useQuery({ queryKey: ["engine-facts"], queryFn: () => api.getEngineFacts({}) });

  useEffect(() => {
    if (rulesQuery.data && rulesText === null) setRulesText(rulesQuery.data.yaml);
  }, [rulesQuery.data, rulesText]);

  useEffect(() => {
    setSelectedIncidentId(null);
    setStepIndex(0);
    setBlockedStep(null);
    setGraphFocus(null);
  }, [activeDatasetId]);

  useEffect(() => {
    setStepIndex(0);
    setBlockedStep(null);
    setGraphFocus(null);
  }, [activeIncidentId]);

  useEffect(() => {
    if (!beltPlaying || !detail) return;
    const timer = setInterval(() => {
      setStepIndex((prev) => {
        if (prev >= detail.steps.length - 1) {
          setBeltPlaying(false);
          return prev;
        }
        return prev + 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [beltPlaying, detail]);

  const invalidateAll = () => {
    void queryClient.invalidateQueries({ queryKey: ["datasets"] });
    void queryClient.invalidateQueries({ queryKey: ["incidents"] });
    void queryClient.invalidateQueries({ queryKey: ["incident"] });
    void queryClient.invalidateQueries({ queryKey: ["rules"] });
  };

  const seedMutation = useMutation({
    mutationFn: () => api.seedSynthetic({}),
    onSuccess: () => { invalidateAll(); },
  });

  const saveRulesMutation = useMutation({
    mutationFn: (yaml: string) => api.saveRules({ yaml }),
    onSuccess: (res) => {
      if (res.ok) {
        setRulesMessage(`Rules saved. Detection re-ran over ${res.reprocessed.length} dataset(s) whose lines were available.`);
        invalidateAll();
      } else {
        setRulesMessage(`Not saved - ${res.error}`);
      }
    },
    onError: (e) => setRulesMessage(`Not saved - ${String(e)}`),
  });

  const resetRulesMutation = useMutation({
    mutationFn: () => api.resetRules({}),
    onSuccess: (res) => {
      setRulesText(res.yaml);
      setRulesMessage(`Default rules restored. Detection re-ran over ${res.reprocessed.length} dataset(s).`);
      invalidateAll();
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteDataset({ datasetId: id }),
    onSuccess: (_res, id) => {
      setArmedDelete(null);
      if (datasetId === id) setDatasetId(null);
      invalidateAll();
    },
  });

  const liveMutation = useMutation({
    mutationFn: (text: string) => api.appendLiveLines({ text, demoFeed: false }),
    onSuccess: (res) => {
      setLiveStatus(`Live feed: ${res.totalLines} lines in, ${res.detections} detections, ${res.incidents} incident(s).`);
      setDatasetId("live");
      invalidateAll();
    },
    onError: (e) => setLiveStatus(`Live append failed - ${String(e)}`),
  });

  async function handleFile(file: File): Promise<void> {
    setUploadError("");
    const lower = file.name.toLowerCase();
    if (!lower.endsWith(".log") && !lower.endsWith(".txt")) {
      setUploadError(`"${file.name}" is not a .log or .txt file. Only .log and .txt log files are accepted.`);
      return;
    }
    if (file.size > 100 * 1024 * 1024) {
      setUploadError("That file is over the 100 MB upload cap for this page. The Python engine handles the 15/30/50 GB tiers.");
      return;
    }
    setUploadState({ fileName: file.name, done: 0, total: file.size, detections: 0, phase: "Starting…" });
    try {
      const started = await api.startUpload({ fileName: file.name });
      const CHUNK = 64 * 1024;
      const decoder = new TextDecoder();
      let offset = 0;
      let last: { totalLines: number; detections: number; incidents: number } | null = null;
      while (offset < file.size) {
        const slice = file.slice(offset, offset + CHUNK);
        const buf = await slice.arrayBuffer();
        const isLast = offset + CHUNK >= file.size;
        const text = decoder.decode(buf, { stream: !isLast });
        const res = await api.ingestChunk({ datasetId: started.datasetId, text, isLast });
        if (!res.ok) {
          setUploadError(res.error);
          setUploadState(null);
          return;
        }
        last = res;
        offset += CHUNK;
        setUploadState({ fileName: file.name, done: Math.min(offset, file.size), total: file.size, detections: res.detections, phase: isLast ? "Linking…" : "Streaming chunks…" });
      }
      if (file.size === 0) {
        await api.ingestChunk({ datasetId: started.datasetId, text: "", isLast: true });
      }
      setUploadState({
        fileName: file.name, done: file.size, total: file.size,
        detections: last?.detections ?? 0,
        phase: `Done - ${last?.totalLines ?? 0} lines, ${last?.incidents ?? 0} incident(s).`,
      });
      setDatasetId(started.datasetId);
      invalidateAll();
    } catch (e) {
      setUploadError(`Upload failed - ${String(e)}`);
      setUploadState(null);
    }
  }

  async function runStreamDemo(): Promise<void> {
    try {
      const started = await api.startStreamDemo({});
      setStreamState({ batch: 0, batches: started.batches, total: started.totalLines, detections: 0, running: true, done: false });
      let lastDetections = 0;
      for (let b = 0; b < started.batches; b += 1) {
        const res = await api.streamDemoBatch({ datasetId: started.datasetId, batch: b });
        lastDetections = res.detections;
        setStreamState({ batch: b + 1, batches: started.batches, total: res.totalLines, detections: res.detections, running: !res.finished, done: res.finished });
        await sleep(120);
      }
      void lastDetections;
      setDatasetId("stream-demo");
      invalidateAll();
    } catch (e) {
      setStreamState({ batch: 0, batches: 0, total: 0, detections: 0, running: false, done: false });
      setLiveStatus(`Stream demo failed - ${String(e)}`);
    }
  }

  async function runLiveFeedDemo(): Promise<void> {
    setFeedRunning(true);
    try {
      for (const batchLines of LIVE_FEED_BATCHES) {
        await api.appendLiveLines({ text: batchLines.join("\n"), demoFeed: true });
        setDatasetId("live");
        invalidateAll();
        await sleep(900);
      }
      setLiveStatus("Demo feed finished: a concealed chain arrived line by line and was linked into one incident.");
    } catch (e) {
      setLiveStatus(`Demo feed failed - ${String(e)}`);
    } finally {
      setFeedRunning(false);
    }
  }

  const selectedStep: Step | undefined = detail?.steps[Math.min(stepIndex, Math.max(0, (detail?.steps.length ?? 1) - 1))];
  const simulatedRisk = blockedStep !== null && detail ? riskOf(detail.steps.slice(0, blockedStep)) : null;

  const heroLines = activeDataset?.totalLines ?? 0;
  const heroDetections = activeDataset?.detectionCount ?? 0;

  return (
    <div className="min-h-screen bg-[#F3EFE3] text-[#111114]">
      <SafeAreaTopScrim backgroundColor="var(--cream)" />

      {/* Chapter rail - desktop */}
      <nav aria-label="Chapters" className="fixed right-3 top-1/2 z-30 hidden -translate-y-1/2 flex-col items-end gap-3 lg:flex">
        {CHAPTERS.map((c) => (
          <a key={c.id} href={`#${c.id}`} className="font-mono-label group flex items-center gap-2 text-[11px] text-[#6F6A5C] hover:text-[#E8241A]">
            <span className="opacity-0 transition-opacity group-hover:opacity-100 group-focus:opacity-100">{c.label}</span>
            <span className="font-bold">{c.n}</span>
            <span className="inline-block h-px w-6 bg-[#6F6A5C] group-hover:bg-[#E8241A]" aria-hidden="true" />
          </a>
        ))}
      </nav>

      {/* HERO - split halves, dashed red seam */}
      <header className="relative">
        <div className="grid md:grid-cols-2">
          <div className="px-4 pt-8 pb-6 sm:px-8 md:pt-12">
            <p className="font-mono-label text-[11px] text-[#E8241A]">Kill Chain · Attack Path Reconstruction · Synthetic data</p>
            <h1 className="font-display mt-4 text-[clamp(2.6rem,9vw,5.2rem)] leading-[0.95]">
              Find the<br />
              <span className="text-[#E8241A]">hidden</span><br />
              chain.
            </h1>
            <p className="mt-4 max-w-md text-[16px] leading-relaxed">
              Millions of log lines hide one attack. This page finds the suspicious events,
              labels each with a MITRE technique and a kill-chain stage, links them across
              hosts, users, IPs and time - and shows where the attacker began, what they
              did, and what they could reach next.
            </p>
            <div className="mt-6 flex flex-wrap gap-2">
              <a href="#ch-missions" className="font-mono-label bg-[#E8241A] px-4 py-2.5 text-[12px] text-[#FBF8EF] hover:bg-[#B3120C]">▶ Open the missions</a>
              <a href="#ch-feed" className="font-mono-label border-2 border-[#111114] px-4 py-2.5 text-[12px] hover:bg-[#111114] hover:text-[#FBF8EF]">Upload a .log file</a>
            </div>
            <dl className="mt-8 grid max-w-md grid-cols-3 gap-px border-2 border-[#111114] bg-[#111114]">
              {[
                ["Lines in view", heroLines.toLocaleString()],
                ["Detections", heroDetections.toLocaleString()],
                ["Incidents", String(incidents.length)],
              ].map(([label, value]) => (
                <div key={label} className="bg-[#FBF8EF] px-3 py-3">
                  <dt className="font-mono-label text-[10px] text-[#6F6A5C]">{label}</dt>
                  <dd className="font-display mt-1 text-[22px]">{value}</dd>
                </div>
              ))}
            </dl>
          </div>
          <div className="relative bg-[#111114] px-4 pt-8 pb-6 sm:px-8 md:pt-12">
            <p className="font-mono-label text-[11px] text-[#F2A007]">02 · The machine room - what the logs become</p>
            <FactoryIllustration lines={heroLines} detections={heroDetections} incidents={incidents.length} />
            <p className="mt-2 font-mono-label text-[11px] leading-relaxed text-[#A3A0A8]">
              Left: what people see. Right: the pipeline underneath - stream, detect, link, explain.
              Nothing here is a mockup: every count above comes from the dataset in view.
            </p>
          </div>
        </div>
        <div className="seam-vertical absolute top-0 bottom-0 left-1/2 hidden w-[3px] -translate-x-1/2 md:block" aria-hidden="true" />
        <div className="seam-horizontal h-[3px] w-full md:hidden" aria-hidden="true" />
      </header>

      {/* Synthetic-data banner */}
      <div className="hazard h-3 w-full" aria-hidden="true" />
      <p className="border-b-2 border-[#111114] bg-[#111114] px-4 py-2 text-center font-mono-label text-[11px] leading-relaxed text-[#FBF8EF] sm:px-8">
        All built-in data is <span className="text-[#F2A007]">synthetic and labelled as such</span> - planted attacks, invented hosts and users.
        Uploaded files are processed for you only. Use synthetic or authorised demo logs - never real production logs or credentials.
      </p>

      {/* Chapter chips - phone */}
      <nav aria-label="Chapters" className="sticky top-0 z-20 flex gap-2 overflow-x-auto border-b-2 border-[#111114] bg-[#F3EFE3] px-3 py-2 lg:hidden">
        {CHAPTERS.map((c) => (
          <a key={c.id} href={`#${c.id}`} className="font-mono-label shrink-0 border border-[#111114] bg-[#FBF8EF] px-2.5 py-1.5 text-[11px] hover:bg-[#E8241A] hover:text-[#FBF8EF]">
            {c.n} {c.label}
          </a>
        ))}
      </nav>

      <main className="mx-auto max-w-6xl px-4 pb-16 sm:px-8">
        {/* 01 - MISSIONS */}
        <section id="ch-missions" className="chapter-link pt-10">
          <p className="font-mono-label text-[11px] text-[#E8241A]">01 · Missions - worst first</p>
          <h2 className="font-display mt-2 text-[clamp(1.9rem,6vw,3.2rem)] leading-none">
            Pick a mission.<br />Worst on top.
          </h2>
          <p className="mt-3 max-w-2xl text-[15px] leading-relaxed">
            Each mission is one linked incident. The risk score decides the order - the same
            scoring the Python engine uses - and every mission shows how many raw alerts
            were merged into it.
          </p>

          {/* Dataset switcher */}
          <div className="mt-6 flex flex-wrap items-center gap-2" aria-label="Choose a dataset">
            {datasets.map((d) => (
              <div key={d.id} className="flex items-stretch">
                <button
                  type="button"
                  onClick={() => setDatasetId(d.id)}
                  aria-pressed={activeDatasetId === d.id}
                  className={`font-mono-label border-2 border-[#111114] px-3 py-2 text-left text-[11px] ${activeDatasetId === d.id ? "bg-[#111114] text-[#FBF8EF]" : "bg-[#FBF8EF] hover:bg-[#E9E2CF]"}`}
                >
                  {d.name}
                  <span className="block text-[10px] opacity-80">
                    {d.totalLines.toLocaleString()} lines · {d.detectionCount} detections
                    {d.status !== "ready" ? ` · ${d.status}` : ""}
                    {d.staleRules ? " · rules changed" : ""}
                  </span>
                </button>
                {d.kind !== "synthetic" && (
                  <button
                    type="button"
                    onClick={() => {
                      if (armedDelete === d.id) deleteMutation.mutate(d.id);
                      else setArmedDelete(d.id);
                    }}
                    aria-label={armedDelete === d.id ? `Confirm delete of ${d.name}` : `Delete ${d.name}`}
                    className="font-mono-label border-2 border-l-0 border-[#111114] bg-[#FBF8EF] px-2 text-[11px] text-[#E8241A] hover:bg-[#E8241A] hover:text-[#FBF8EF]"
                  >
                    {armedDelete === d.id ? "Sure?" : "✕"}
                  </button>
                )}
              </div>
            ))}
            {datasets.length === 0 && (
              <button
                type="button"
                onClick={() => seedMutation.mutate()}
                disabled={seedMutation.isPending}
                className="font-mono-label bg-[#E8241A] px-4 py-2.5 text-[12px] text-[#FBF8EF] disabled:opacity-60"
              >
                {seedMutation.isPending ? "Loading…" : "Load the synthetic set"}
              </button>
            )}
          </div>
          {datasetsQuery.isError && (
            <p className="mt-3 border-2 border-[#E8241A] bg-[#FBF8EF] px-3 py-2 text-[14px]">Could not load datasets. Reload the page and try again.</p>
          )}
          {activeDataset?.staleRules && (
            <p className="mt-3 border-2 border-[#F2A007] bg-[#FBF8EF] px-3 py-2 text-[14px]">
              The rules changed since this dataset was processed and its original lines are no
              longer available. Re-upload the file to re-detect it under the new rules.
            </p>
          )}

          {/* Incident index */}
          {incidentsQuery.isPending ? (
            <p className="mt-6 font-mono-label text-[12px]">Loading missions…</p>
          ) : incidents.length === 0 ? (
            <div className="mt-6 border-2 border-dashed border-[#111114] bg-[#FBF8EF] px-4 py-6">
              <p className="font-display text-[20px]">No incidents in this dataset.</p>
              <p className="mt-2 max-w-xl text-[15px] leading-relaxed">
                Either every line was benign, or no rule matched. Try the stream demo in
                chapter 02 - a concealed attack is planted inside 5,009 lines - or upload a
                log that contains one of the rule phrases listed in chapter 04.
              </p>
              <button
                type="button"
                onClick={() => document.getElementById("ch-feed")?.scrollIntoView({ behavior: "smooth" })}
                className="font-mono-label mt-4 bg-[#111114] px-4 py-2 text-[12px] text-[#FBF8EF]"
              >
                Go to chapter 02
              </button>
            </div>
          ) : (
            <ol className="mt-6 border-t-2 border-[#111114]">
              {incidents.map((inc, idx) => {
                const selected = activeIncidentId === inc.id;
                return (
                  <li key={inc.id} className="border-b-2 border-[#111114]">
                    <button
                      type="button"
                      onClick={() => setSelectedIncidentId(inc.id)}
                      aria-current={selected}
                      className={`grid w-full grid-cols-[auto_1fr_auto] items-center gap-3 px-3 py-4 text-left sm:grid-cols-[auto_1fr_auto_auto] sm:gap-5 ${selected ? "bg-[#111114] text-[#FBF8EF]" : "bg-[#FBF8EF] hover:bg-[#E9E2CF]"}`}
                    >
                      <span className="font-display text-[30px] leading-none text-[#E8241A]">{String(idx + 1).padStart(2, "0")}</span>
                      <span className="min-w-0">
                        <span className="font-display block truncate text-[19px] leading-tight sm:text-[22px]">{inc.missionLabel || "Incident"}</span>
                        <span className={`mt-1 block truncate text-[13px] ${selected ? "text-[#D8D0BA]" : "text-[#6F6A5C]"}`}>
                          {inc.title} · {inc.hosts.join(" → ")} · {inc.users.join(", ")}
                        </span>
                        <span className={`font-mono-label mt-1 block text-[10px] ${selected ? "text-[#A3A0A8]" : "text-[#6F6A5C]"}`}>
                          {inc.detectionCount} steps · {inc.mergedAlerts} raw alerts merged · {inc.startTime.replace("T", " ")} → {inc.endTime.replace("T", " ")}
                        </span>
                      </span>
                      <span className="text-right">
                        <span className="font-display block text-[26px] leading-none">{inc.riskScore}<span className="text-[14px]">/100</span></span>
                        <span className="font-mono-label mt-1 block text-[10px] text-[#F2A007]">Risk</span>
                      </span>
                      <span className="hidden w-28 sm:block" aria-hidden="true">
                        <span className="block h-2.5 w-full bg-[#D8D0BA]">
                          <span className="block h-2.5 bg-[#E8241A]" style={{ width: `${inc.riskScore}%` }} />
                        </span>
                      </span>
                    </button>
                  </li>
                );
              })}
            </ol>
          )}
        </section>

        {/* 02 - FEED THE MACHINE */}
        <section id="ch-feed" className="chapter-link pt-14">
          <p className="font-mono-label text-[11px] text-[#E8241A]">02 · Feed the machine</p>
          <h2 className="font-display mt-2 text-[clamp(1.9rem,6vw,3.2rem)] leading-none">
            Upload. Paste.<br />Stream.
          </h2>
          <p className="mt-3 max-w-2xl text-[15px] leading-relaxed">
            Files are read in 64&nbsp;KB slices and processed in stream order. Benign lines are
            counted and dropped - only detections are stored. Accepted formats: JSON-lines,
            pipe-separated, and CSV, with the same flexible field names as the Python parser.
          </p>

          <div className="mt-6 grid gap-4 lg:grid-cols-2">
            {/* Upload */}
            <div className="border-2 border-[#111114] bg-[#FBF8EF]">
              <div className="border-b-2 border-[#111114] bg-[#111114] px-4 py-2">
                <h3 className="font-mono-label text-[12px] text-[#FBF8EF]">A · Upload a .log / .txt file</h3>
              </div>
              <div className="p-4">
                <div
                  role="button"
                  tabIndex={0}
                  aria-label="Choose a .log or .txt file to upload"
                  onClick={() => fileInputRef.current?.click()}
                  onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") fileInputRef.current?.click(); }}
                  onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                  onDragLeave={() => setDragOver(false)}
                  onDrop={(e) => {
                    e.preventDefault();
                    setDragOver(false);
                    const f = e.dataTransfer.files?.[0];
                    if (f) void handleFile(f);
                  }}
                  className={`cursor-pointer border-2 border-dashed px-4 py-8 text-center ${dragOver ? "border-[#E8241A] bg-[#E9E2CF]" : "border-[#111114]"}`}
                >
                  <p className="font-display text-[20px]">Drop a log file here</p>
                  <p className="mt-1 text-[14px] text-[#6F6A5C]">or tap to choose - .log and .txt only, up to 100 MB</p>
                  <p className="font-mono-label mt-3 text-[11px] text-[#E8241A]">Processed for you only · nothing is shared</p>
                </div>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".log,.txt"
                  aria-label="Log file to upload"
                  className="sr-only"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) void handleFile(f);
                    e.target.value = "";
                  }}
                />
                {uploadState && (
                  <div className="mt-4" aria-live="polite">
                    <p className="font-mono-label text-[11px]">{uploadState.fileName} - {uploadState.phase}</p>
                    <div className="mt-2 h-3 w-full border border-[#111114] bg-[#E9E2CF]">
                      <div className="hazard h-full" style={{ width: `${uploadState.total > 0 ? Math.round((uploadState.done / uploadState.total) * 100) : 0}%` }} />
                    </div>
                    <p className="font-mono-label mt-1 text-[11px] text-[#6F6A5C]">
                      {uploadState.done.toLocaleString()} / {uploadState.total.toLocaleString()} bytes · {uploadState.detections} detections so far
                    </p>
                  </div>
                )}
                {uploadError && (
                  <p role="alert" className="mt-3 border-2 border-[#E8241A] px-3 py-2 text-[14px]">{uploadError}</p>
                )}
                <p className="mt-4 border-l-4 border-[#F2A007] bg-[#E9E2CF] px-3 py-2 text-[13px] leading-relaxed">
                  <strong>Warning:</strong> use only synthetic or authorised demo logs. Never
                  upload real production logs, credentials, or personal data.
                </p>
              </div>
            </div>

            {/* Live + stream */}
            <div className="flex flex-col gap-4">
              <div className="border-2 border-[#111114] bg-[#1D1E22] text-[#FBF8EF]">
                <div className="border-b border-[#3A3D44] px-4 py-2">
                  <h3 className="font-mono-label text-[12px] text-[#F2A007]">B · Live mode <span className="blink-dot ml-1 inline-block h-2 w-2 rounded-full bg-[#E8241A]" aria-hidden="true" /></h3>
                </div>
                <div className="p-4">
                  <label htmlFor="live-lines" className="font-mono-label text-[11px] text-[#A3A0A8]">Paste log lines - new lines re-link the path within seconds</label>
                  <textarea
                    id="live-lines"
                    value={liveText}
                    onChange={(e) => setLiveText(e.target.value)}
                    rows={4}
                    placeholder={'{"time":"2026-10-31T09:02:00","host":"LAP-118","user":"meera.nair","action":"port scan detected","detail":"port scan against internal hosts","severity":"High"}'}
                    className="mt-2 w-full border border-[#3A3D44] bg-[#111114] p-3 font-mono text-[13px] text-[#FBF8EF] placeholder:text-[#6F6A5C]"
                  />
                  <div className="mt-3 flex flex-wrap gap-2">
                    <button
                      type="button"
                      disabled={liveText.trim() === "" || liveMutation.isPending}
                      onClick={() => { liveMutation.mutate(liveText); setLiveText(""); }}
                      className="font-mono-label bg-[#E8241A] px-3 py-2 text-[11px] text-[#FBF8EF] disabled:opacity-50"
                    >
                      {liveMutation.isPending ? "Appending…" : "Append lines live"}
                    </button>
                    <button
                      type="button"
                      disabled={feedRunning}
                      onClick={() => void runLiveFeedDemo()}
                      className="font-mono-label border border-[#F2A007] px-3 py-2 text-[11px] text-[#F2A007] disabled:opacity-50"
                    >
                      {feedRunning ? "Feeding…" : "▶ Demo feed (synthetic)"}
                    </button>
                  </div>
                  {liveStatus && <p className="mt-3 font-mono-label text-[11px] leading-relaxed text-[#A3A0A8]" aria-live="polite">{liveStatus}</p>}
                </div>
              </div>

              <div className="border-2 border-[#111114] bg-[#FBF8EF]">
                <div className="border-b-2 border-[#111114] px-4 py-2">
                  <h3 className="font-mono-label text-[12px]">C · Large-volume stream demo</h3>
                </div>
                <div className="p-4">
                  <p className="text-[14px] leading-relaxed">
                    5,009 lines stream in 500-line batches. Most are benign; 24 planted
                    steps from 5 concealed attacks are hidden inside. Only detections are kept - the raw stream is never
                    held in full.
                  </p>
                  <button
                    type="button"
                    disabled={streamState?.running}
                    onClick={() => void runStreamDemo()}
                    className="font-mono-label mt-3 bg-[#111114] px-4 py-2.5 text-[12px] text-[#FBF8EF] disabled:opacity-50"
                  >
                    {streamState?.running ? `Streaming batch ${streamState.batch}/${streamState.batches}…` : "▶ Run the 5,009-line stream"}
                  </button>
                  {streamState && (
                    <div className="mt-3" aria-live="polite">
                      <div className="h-3 w-full border border-[#111114] bg-[#E9E2CF]">
                        <div className="hazard h-full" style={{ width: `${streamState.batches > 0 ? Math.round((streamState.batch / streamState.batches) * 100) : 0}%` }} />
                      </div>
                      <p className="font-mono-label mt-1 text-[11px] text-[#6F6A5C]">
                        {streamState.total.toLocaleString()} lines seen · {streamState.detections} flagged
                        {streamState.done ? " · stream finished - open the Stream demo dataset in chapter 01" : ""}
                      </p>
                    </div>
                  )}
                  <p className="mt-3 font-mono-label text-[11px] leading-relaxed text-[#6F6A5C]">
                    The 15/30/50 GB tiers run in the Python engine, not in this page. This demo
                    proves the same chunked design at a size you can watch.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </section>
        {/* 03 - THE LINE (incident detail) */}
        <section id="ch-line" className="chapter-link pt-14">
          <p className="font-mono-label text-[11px] text-[#E8241A]">03 · The line - timeline, graph, look-ahead</p>
          {detailQuery.isPending ? (
            <p className="mt-4 font-mono-label text-[12px]">Loading the incident…</p>
          ) : !detail ? (
            <p className="mt-4 border-2 border-dashed border-[#111114] bg-[#FBF8EF] px-4 py-5 text-[15px]">
              No incident is selected. Pick a mission in chapter 01, or feed the machine in chapter 02.
            </p>
          ) : (
            <>
              <h2 className="font-display mt-2 text-[clamp(1.9rem,6vw,3.2rem)] leading-none">
                {detail.incident.missionLabel || "Incident"}
              </h2>
              <p className="mt-2 text-[15px] leading-relaxed">
                {detail.incident.title} · Risk <strong>{detail.incident.riskScore}/100</strong> ·{" "}
                {detail.incident.detectionCount} steps · {detail.incident.mergedAlerts} raw alerts merged ·{" "}
                {detail.incident.startTime.replace("T", " ")} → {detail.incident.endTime.replace("T", " ")}
              </p>

              <div className="mt-6 bg-[#111114] px-4 py-4 text-[#FBF8EF] sm:px-6">
                <BeltView
                  steps={detail.steps}
                  selected={stepIndex}
                  onSelect={setStepIndex}
                  playing={beltPlaying}
                  onTogglePlay={() => setBeltPlaying((p) => !p)}
                />

                {/* Step detail */}
                {selectedStep && (
                  <div className="mt-4 grid gap-4 border-t border-[#3A3D44] pt-4 md:grid-cols-[1fr_auto]">
                    <div>
                      <p className="font-mono-label text-[11px] text-[#F2A007]">
                        Step {stepIndex + 1} of {detail.steps.length} · {selectedStep.stage} · {selectedStep.tactic}
                      </p>
                      <p className="font-display mt-1 text-[24px] leading-tight">
                        {selectedStep.techniqueId} - {selectedStep.techniqueName}
                      </p>
                      <p className="mt-2 text-[15px] leading-relaxed">{selectedStep.reason}</p>
                      <p className="mt-2 font-mono text-[13px] leading-relaxed text-[#D8D0BA]">
                        {selectedStep.time.replace("T", " ")} · {selectedStep.host} · {selectedStep.user}
                        {selectedStep.ip ? ` · ${selectedStep.ip}` : ""} · {selectedStep.source}
                      </p>
                      <p className="mt-1 font-mono text-[13px] text-[#A3A0A8]">
                        “{selectedStep.action}” - {selectedStep.detail}
                      </p>
                    </div>
                    <dl className="flex gap-6 md:flex-col md:gap-2 md:text-right">
                      <div>
                        <dt className="font-mono-label text-[10px] text-[#A3A0A8]">Confidence</dt>
                        <dd className="font-display text-[22px]">{selectedStep.confidence}%</dd>
                      </div>
                      <div>
                        <dt className="font-mono-label text-[10px] text-[#A3A0A8]">Severity</dt>
                        <dd className="font-display text-[22px]">{selectedStep.severity}</dd>
                      </div>
                      <div>
                        <dt className="font-mono-label text-[10px] text-[#A3A0A8]">Raw alerts in step</dt>
                        <dd className="font-display text-[22px]">{selectedStep.mergedAlerts}</dd>
                      </div>
                      <div>
                        <dt className="font-mono-label text-[10px] text-[#A3A0A8]">Rule</dt>
                        <dd className="font-mono-label text-[12px] text-[#F2A007]">{selectedStep.ruleId}</dd>
                      </div>
                    </dl>
                  </div>
                )}

                {/* Scrubber */}
                <div className="mt-4">
                  <label htmlFor="step-scrubber" className="font-mono-label text-[11px] text-[#A3A0A8]">
                    Scrub the timeline - drag to move along the chain
                  </label>
                  <input
                    id="step-scrubber"
                    type="range"
                    min={0}
                    max={Math.max(0, detail.steps.length - 1)}
                    value={stepIndex}
                    onChange={(e) => { setStepIndex(Number(e.target.value)); setBeltPlaying(false); }}
                    className="mt-2 w-full accent-[#E8241A]"
                  />
                  <div className="flex justify-between font-mono-label text-[10px] text-[#A3A0A8]">
                    <span>First step</span>
                    <span>Step {stepIndex + 1} / {detail.steps.length}</span>
                    <span>Last step</span>
                  </div>
                </div>

                {/* Timeline list */}
                <ol className="mt-4 border-t border-[#3A3D44]">
                  {detail.steps.map((step, i) => {
                    const focused = graphFocus !== null && (step.host === graphFocus || step.user === graphFocus);
                    const dimmed = graphFocus !== null && !focused;
                    return (
                      <li key={step.id}>
                        <button
                          type="button"
                          onClick={() => setStepIndex(i)}
                          aria-current={i === stepIndex}
                          className={`grid w-full grid-cols-[auto_1fr_auto] items-center gap-3 border-b border-[#3A3D44] px-2 py-3 text-left ${i === stepIndex ? "bg-[#E8241A] text-[#FBF8EF]" : "hover:bg-[#232529]"} ${dimmed ? "opacity-40" : ""}`}
                        >
                          <span className="font-display text-[18px]">{String(i + 1).padStart(2, "0")}</span>
                          <span className="min-w-0">
                            <span className="block truncate text-[14px] font-semibold">{step.techniqueName} <span className="font-mono-label text-[11px] opacity-80">{step.techniqueId}</span></span>
                            <span className="font-mono-label mt-0.5 block text-[10px] opacity-80">{step.stage} · {step.host} · {step.user} · {step.time.replace("T", " ")}</span>
                          </span>
                          <span className="font-mono-label text-[11px]">{step.mergedAlerts} alert{step.mergedAlerts === 1 ? "" : "s"}</span>
                        </button>
                      </li>
                    );
                  })}
                </ol>
              </div>

              <div className="mt-4 grid gap-4 lg:grid-cols-2">
                {/* Graph */}
                <div className="border-2 border-[#111114] bg-[#1D1E22] px-4 py-4 text-[#FBF8EF]">
                  <h3 className="font-mono-label text-[12px] text-[#F2A007]">Host / user graph</h3>
                  <p className="mt-1 text-[13px] text-[#A3A0A8]">The same path as nodes and edges - the NetworkX shape of this incident.</p>
                  <GraphView detail={detail} focus={graphFocus} onFocus={setGraphFocus} />
                </div>

                {/* Next reach + what-if */}
                <div className="flex flex-col gap-4">
                  <div className="border-2 border-[#111114] bg-[#FBF8EF] px-4 py-4">
                    <h3 className="font-mono-label text-[12px] text-[#E8241A]">What the attacker could reach next</h3>
                    {detail.nextReach.length === 0 ? (
                      <p className="mt-2 text-[14px] leading-relaxed">
                        No next system could be identified from the supplied topology, so no next
                        target is guessed. Hosts and accounts outside the topology produce no entry.
                      </p>
                    ) : (
                      <ul className="mt-3 space-y-3">
                        {detail.nextReach.map((n) => (
                          <li key={n.host} className="border-l-4 border-[#E8241A] bg-[#E9E2CF] px-3 py-2">
                            <p className="font-display text-[17px]">{n.host} <span className="font-mono-label text-[11px] text-[#6F6A5C]">{n.confidence}% confidence</span></p>
                            <p className="mt-0.5 text-[13px] leading-relaxed">{n.reason}</p>
                            <p className="mt-1 font-mono-label text-[10px] text-[#6F6A5C]">Block: {n.block}</p>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>

                  <div className="border-2 border-[#111114] bg-[#FBF8EF] px-4 py-4">
                    <h3 className="font-mono-label text-[12px]">What-if - block a step</h3>
                    <p className="mt-1 text-[13px] leading-relaxed text-[#6F6A5C]">
                      A simulation only. Blocking is not performed by this tool. Pick the step
                      where containment happens; everything after it is treated as stopped.
                    </p>
                    <label htmlFor="block-step" className="font-mono-label mt-3 block text-[11px]">Block after step</label>
                    <select
                      id="block-step"
                      value={blockedStep === null ? "" : String(blockedStep)}
                      onChange={(e) => setBlockedStep(e.target.value === "" ? null : Number(e.target.value))}
                      className="mt-1 w-full border-2 border-[#111114] bg-[#FBF8EF] px-2 py-2 text-[14px]"
                    >
                      <option value="">No block - full chain</option>
                      {detail.steps.map((s, i) => (
                        <option key={s.id} value={String(i + 1)}>
                          After step {i + 1} - {s.techniqueId} on {s.host}
                        </option>
                      ))}
                    </select>
                    {simulatedRisk !== null && blockedStep !== null && (
                      <p className="mt-3 border-2 border-[#F2A007] px-3 py-2 text-[14px] leading-relaxed" aria-live="polite">
                        Simulated risk falls <strong>{detail.incident.riskScore} → {simulatedRisk}</strong>, and{" "}
                        {detail.steps.length - blockedStep} later step(s) never happen. The
                        next-reach targets above would stay out of reach if containment holds at
                        step {blockedStep}.
                      </p>
                    )}
                  </div>
                </div>
              </div>
            </>
          )}
        </section>

        {/* 04 - RULES FILE */}
        <section id="ch-rules" className="chapter-link pt-14">
          <p className="font-mono-label text-[11px] text-[#E8241A]">04 · Rules file - config, not code</p>
          <h2 className="font-display mt-2 text-[clamp(1.9rem,6vw,3.2rem)] leading-none">
            Add a rule.<br />Edit the file.
          </h2>
          <p className="mt-3 max-w-2xl text-[15px] leading-relaxed">
            Detection rules live in this config text, in the same Sigma-style shape as the
            Python engine's YAML files. Saving re-runs detection over every dataset whose
            original lines are still available. A bad file is rejected and the working
            rules stay in place.
          </p>
          {rulesQuery.isPending ? (
            <p className="mt-4 font-mono-label text-[12px]">Loading rules…</p>
          ) : (
            <div className="mt-6 grid gap-4 lg:grid-cols-[1fr_320px]">
              <div className="border-2 border-[#111114] bg-[#FBF8EF]">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b-2 border-[#111114] bg-[#111114] px-4 py-2">
                  <h3 className="font-mono-label text-[12px] text-[#FBF8EF]">rules.yml - editable</h3>
                  <span className="font-mono-label text-[10px] text-[#F2A007]">{rulesQuery.data?.rules.length ?? 0} rules loaded</span>
                </div>
                <label htmlFor="rules-editor" className="sr-only">Detection rules in YAML format</label>
                <textarea
                  id="rules-editor"
                  value={rulesText ?? ""}
                  onChange={(e) => { setRulesText(e.target.value); setRulesMessage(""); }}
                  rows={22}
                  spellCheck={false}
                  className="w-full resize-y bg-[#111114] p-4 font-mono text-[12.5px] leading-relaxed text-[#FBF8EF] outline-none"
                />
                <div className="flex flex-wrap gap-2 border-t-2 border-[#111114] px-4 py-3">
                  <button
                    type="button"
                    disabled={saveRulesMutation.isPending || rulesText === null}
                    onClick={() => { if (rulesText !== null) saveRulesMutation.mutate(rulesText); }}
                    className="font-mono-label bg-[#E8241A] px-4 py-2 text-[12px] text-[#FBF8EF] disabled:opacity-50"
                  >
                    {saveRulesMutation.isPending ? "Saving & re-running…" : "Save rules & re-detect"}
                  </button>
                  <button
                    type="button"
                    disabled={resetRulesMutation.isPending}
                    onClick={() => resetRulesMutation.mutate()}
                    className="font-mono-label border-2 border-[#111114] px-4 py-2 text-[12px] disabled:opacity-50"
                  >
                    Restore defaults
                  </button>
                </div>
                {rulesMessage && (
                  <p role="status" className="border-t-2 border-[#111114] px-4 py-2 text-[14px]">{rulesMessage}</p>
                )}
                {rulesQuery.data?.error && (
                  <p role="alert" className="border-t-2 border-[#E8241A] px-4 py-2 text-[14px]">Stored rules have a problem: {rulesQuery.data.error}</p>
                )}
              </div>
              <div>
                <h3 className="font-mono-label text-[12px]">Rules in force</h3>
                <ul className="mt-2 space-y-2">
                  {(rulesQuery.data?.rules ?? []).map((r) => (
                    <li key={r.id} className="border-2 border-[#111114] bg-[#FBF8EF] px-3 py-2">
                      <p className="text-[14px] font-semibold">{r.name} <span className="font-mono-label text-[10px] text-[#6F6A5C]">{r.id}</span></p>
                      <p className="font-mono-label mt-0.5 text-[10px] text-[#6F6A5C]">
                        {r.techniqueId} · {r.stage} · conf {r.confidence}% · priority {r.priority} · {r.type}
                      </p>
                      <p className="mt-1 text-[13px] leading-snug">{r.description}</p>
                    </li>
                  ))}
                </ul>
                <p className="mt-3 border-l-4 border-[#F2A007] bg-[#E9E2CF] px-3 py-2 text-[13px] leading-relaxed">
                  Try it: add a rule matching a phrase in your own log, save, and watch the
                  mission list change. The example rule <span className="font-mono">midnight_db_export</span> fires
                  on “midnight database export” - a phrase that never appears in the synthetic set.
                </p>
              </div>
            </div>
          )}
        </section>

        {/* 05 - ENGINE */}
        <section id="ch-engine" className="chapter-link pt-14">
          <p className="font-mono-label text-[11px] text-[#E8241A]">05 · Engine - the loadout</p>
          <h2 className="font-display mt-2 text-[clamp(1.9rem,6vw,3.2rem)] leading-none">
            Four slots.<br />One pipeline.
          </h2>
          <div className="mt-6 grid gap-px border-2 border-[#111114] bg-[#111114] sm:grid-cols-2 lg:grid-cols-4">
            {(factsQuery.data?.loadout ?? []).map((slot) => (
              <div key={slot.slot} className="bg-[#FBF8EF] px-4 py-4">
                <p className="font-mono-label text-[10px] text-[#E8241A]">{slot.slot}</p>
                <p className="font-display mt-2 text-[18px] leading-tight">{slot.name}</p>
                <p className="mt-2 text-[13.5px] leading-relaxed">{slot.job}</p>
              </div>
            ))}
          </div>

          <div className="mt-4 border-2 border-[#F2A007] bg-[#111114] px-4 py-4 text-[#FBF8EF]">
            <h3 className="font-mono-label text-[12px] text-[#F2A007]">Read this before you judge the numbers</h3>
            <p className="mt-2 max-w-3xl text-[14px] leading-relaxed">
              This page runs the same detection, linking, scoring, graph, and reporting logic as
              the Python engine - ported into this artifact's server actions, because the
              artifact runtime is TypeScript/Bun with its own database, not Python. The Python
              engine itself - Python + DuckDB for storage + NetworkX for the graph, Sigma-style
              YAML rules, streaming parser, API, live mode, and the Sarvam Hindi adapter - is
              the design source, and it is where the 15/30/50&nbsp;GB tiers run. Nothing on this
              page claims Python, DuckDB, or NetworkX executes inside the artifact.
            </p>
          </div>

          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <div className="border-2 border-[#111114] bg-[#FBF8EF] px-4 py-4">
              <h3 className="font-mono-label text-[12px]">Data-set tiers</h3>
              <ul className="mt-3 space-y-3">
                {(factsQuery.data?.tiers ?? []).map((t) => (
                  <li key={t.tier} className="flex items-baseline justify-between gap-3 border-b border-[#D8D0BA] pb-3">
                    <span className="font-display text-[17px]">{t.tier} <span className="text-[#E8241A]">{t.size}</span></span>
                    <span className="max-w-[60%] text-right text-[13px] leading-snug">{t.tests}</span>
                    <span className="font-mono-label shrink-0 text-[11px]">{t.multiplier}</span>
                  </li>
                ))}
              </ul>
              <p className="mt-3 text-[13px] leading-relaxed text-[#6F6A5C]">
                Same planted attacks at every size, so results stay comparable. A bigger tier
                only earns more if accuracy stays above the minimum bar.
              </p>
            </div>
            <div className="border-2 border-[#111114] bg-[#FBF8EF] px-4 py-4">
              <h3 className="font-mono-label text-[12px]">Measured on the local Python run - synthetic only</h3>
              <ul className="mt-3 space-y-2">
                {(factsQuery.data?.measured ?? []).map((m) => (
                  <li key={m.label} className="flex items-baseline justify-between gap-3 border-b border-[#D8D0BA] pb-2">
                    <span className="text-[13px]">{m.label}</span>
                    <span className="text-right text-[13px] font-semibold">{m.value}</span>
                  </li>
                ))}
              </ul>
              <h3 className="font-mono-label mt-5 text-[12px]">Targets (Good / Great)</h3>
              <ul className="mt-2 space-y-1.5">
                {(factsQuery.data?.targets ?? []).map((t) => (
                  <li key={t.measure} className="flex items-baseline justify-between gap-3 text-[13px]">
                    <span>{t.measure} <span className="text-[#6F6A5C]">- {t.how}</span></span>
                    <span className="shrink-0 font-mono-label text-[10px]">{t.good} / {t.great}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          <div className="mt-4 grid gap-px border-2 border-[#111114] bg-[#111114] sm:grid-cols-3">
            {[
              ["Detect & label", "FR-1 · FR-2 · FR-3 - Stream in chunks, flag suspicious events, tag MITRE + kill-chain stage."],
              ["Connect & explain", "FR-4 · FR-5 · FR-6 - Link by host, user, IP and time (48 h window). Timeline + graph + next-reach."],
              ["Bonuses, all five", "B-1 risk ranking · B-2 plain-English + Hindi report · B-3 merged counts · B-4 config rules · B-5 live mode."],
            ].map(([title, body]) => (
              <div key={title} className="bg-[#1D1E22] px-4 py-4 text-[#FBF8EF]">
                <p className="font-display text-[17px]">{title}</p>
                <p className="mt-1 text-[13px] leading-relaxed text-[#A3A0A8]">{body}</p>
              </div>
            ))}
          </div>
        </section>

        {/* 06 - REPORT */}
        <section id="ch-report" className="chapter-link pt-14">
          <p className="font-mono-label text-[11px] text-[#E8241A]">06 · Report - in plain words</p>
          <h2 className="font-display mt-2 text-[clamp(1.9rem,6vw,3.2rem)] leading-none">
            The story,<br />written out.
          </h2>
          {!detail ? (
            <p className="mt-4 text-[15px]">Select a mission in chapter 01 to read its report.</p>
          ) : (
            <>
              <div className="mt-4 flex flex-wrap gap-2" role="group" aria-label="Report language">
                <button
                  type="button"
                  onClick={() => setReportLang("en")}
                  aria-pressed={reportLang === "en"}
                  className={`font-mono-label px-4 py-2 text-[12px] ${reportLang === "en" ? "bg-[#111114] text-[#FBF8EF]" : "border-2 border-[#111114] bg-[#FBF8EF]"}`}
                >
                  English - plain words
                </button>
                <button
                  type="button"
                  onClick={() => setReportLang("hi")}
                  aria-pressed={reportLang === "hi"}
                  className={`font-mono-label px-4 py-2 text-[12px] ${reportLang === "hi" ? "bg-[#111114] text-[#FBF8EF]" : "border-2 border-[#111114] bg-[#FBF8EF]"}`}
                >
                  हिन्दी - template
                </button>
              </div>
              <div className="mt-3 border-2 border-[#111114] bg-[#FBF8EF] px-5 py-5">
                <p className="font-mono-label text-[11px] text-[#E8241A]">
                  {detail.incident.missionLabel} · Risk {detail.incident.riskScore}/100 · {detail.incident.mergedAlerts} raw alerts merged into {detail.incident.detectionCount} detections
                </p>
                <p className="mt-3 max-w-3xl text-[17px] leading-relaxed">
                  {reportLang === "en" ? detail.englishReport : detail.hindiReport}
                </p>
                {reportLang === "hi" && (
                  <p className="mt-4 border-l-4 border-[#F2A007] bg-[#E9E2CF] px-3 py-2 text-[13px] leading-relaxed">
                    <strong>Template, not a translation.</strong> {detail.hindiWarning} In the Python
                    engine, a real Sarvam translation is used only when a Sarvam API key is set;
                    without one, the same labelled template is returned.
                  </p>
                )}
                <div className="mt-5 flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={async () => {
                      const ok = await copyText(reportLang === "en" ? detail.englishReport : detail.hindiReport);
                      setCopied(ok);
                      setTimeout(() => setCopied(false), 2000);
                    }}
                    className="font-mono-label bg-[#E8241A] px-4 py-2 text-[12px] text-[#FBF8EF] hover:bg-[#B3120C]"
                  >
                    {copied ? "Copied ✓" : "Copy report"}
                  </button>
                  <button
                    type="button"
                    onClick={() => downloadText(
                      `kill-chain-report-${detail.incident.id}-${reportLang}.txt`,
                      reportLang === "en" ? detail.englishReport : detail.hindiReport,
                    )}
                    className="font-mono-label border-2 border-[#111114] px-4 py-2 text-[12px]"
                  >
                    Download report (.txt)
                  </button>
                </div>
              </div>
            </>
          )}
        </section>
      </main>

      <footer className="border-t-2 border-[#111114] bg-[#111114] px-4 py-6 text-[#A3A0A8] sm:px-8">
        <p className="font-mono-label max-w-6xl mx-auto text-[11px] leading-relaxed">
          Kill Chain Attack Path Reconstruction - detect, label, connect, explain, look ahead.
          Built-in data is synthetic. The Python + DuckDB + NetworkX engine is the design source;
          this page ports its logic into the artifact runtime. This tool finds and explains attacks -
          it does not block or stop them.
        </p>
      </footer>
    </div>
  );
}
