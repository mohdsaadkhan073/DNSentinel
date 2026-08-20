import type { ConnectionStatus } from "../hooks/useTelemetry";

export default function SystemStatus({ status }: { status: ConnectionStatus }) {
  const online = status === "CONNECTED";
  return (
    <div className="system-status">
      <span className={`system-status__dot ${online ? "is-online" : "is-reconnecting"}`} />
      <span>{online ? "SYSTEM ONLINE" : "RECONNECTING"}</span>
      <span className="system-status__ws">WS: {status}</span>
    </div>
  );
}
