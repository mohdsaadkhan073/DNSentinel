import { SirenIcon, CloseIcon } from "./icons";

export interface ToastItem {
  id: string;
  domain: string;
  risk_score: number;
}

interface ToastStackProps {
  toasts: ToastItem[];
  onDismiss: (id: string) => void;
  onOpen: (id: string) => void;
}

export default function ToastStack({ toasts, onDismiss, onOpen }: ToastStackProps) {
  if (toasts.length === 0) return null;

  return (
    <div className="toast-stack">
      {toasts.map((t) => (
        <div key={t.id} className="toast" onClick={() => onOpen(t.id)}>
          <SirenIcon className="toast__icon" />
          <div className="toast__body">
            <div className="toast__title">Blocked</div>
            <div className="toast__domain">{t.domain}</div>
            <div className="toast__meta">risk {t.risk_score}/100</div>
          </div>
          <button
            className="toast__close"
            onClick={(e) => {
              e.stopPropagation();
              onDismiss(t.id);
            }}
            aria-label="Dismiss"
          >
            <CloseIcon />
          </button>
        </div>
      ))}
    </div>
  );
}
