import { useEffect, useRef, useState, useCallback } from "react";
import { WS_URL } from "../services/api";
import type { SecurityDecision } from "../types/security";

export type ConnectionStatus = "CONNECTED" | "RECONNECTING" | "OFFLINE";

const MAX_EVENTS = 100;
const MAX_BACKOFF_MS = 16000;

export function useTelemetry() {
  const [events, setEvents] = useState<SecurityDecision[]>([]);
  const [status, setStatus] = useState<ConnectionStatus>("RECONNECTING");
  const wsRef = useRef<WebSocket | null>(null);
  const backoffRef = useRef(1000);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(true);

  const connect = useCallback(() => {
    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => {
      if (!mountedRef.current) return;
      setStatus("CONNECTED");
      backoffRef.current = 1000;
    };

    ws.onmessage = (msg) => {
      try {
        const event: SecurityDecision = JSON.parse(msg.data);
        setEvents((prev) => (prev.some((e) => e.id === event.id) ? prev : [event, ...prev].slice(0, MAX_EVENTS)));
      } catch {
        // ignore malformed frame
      }
    };

    ws.onclose = () => {
      if (!mountedRef.current) return;
      setStatus("RECONNECTING");
      const delay = Math.min(backoffRef.current, MAX_BACKOFF_MS);
      timerRef.current = setTimeout(connect, delay);
      backoffRef.current = Math.min(backoffRef.current * 2, MAX_BACKOFF_MS);
    };

    ws.onerror = () => {
      ws.close();
    };
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    connect();
    return () => {
      mountedRef.current = false;
      if (timerRef.current) clearTimeout(timerRef.current);
      wsRef.current?.close();
    };
  }, [connect]);

  return { events, status };
}
