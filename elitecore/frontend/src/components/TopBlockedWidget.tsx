import { useEffect, useState } from "react";
import { getTopBlocked } from "../services/api";
import type { TopBlockedDomain } from "../types/security";
import { TrophyIcon } from "./icons";

export default function TopBlockedWidget() {
  const [items, setItems] = useState<TopBlockedDomain[]>([]);

  const refresh = () => {
    getTopBlocked(5).then((res) => setItems(res.items));
  };

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 8000);
    return () => clearInterval(interval);
  }, []);

  const max = Math.max(1, ...items.map((i) => i.count));

  return (
    <div className="panel">
      <div className="panel__title">
        <TrophyIcon className="panel__title-icon" />
        Top Blocked Domains
      </div>
      <div className="leaderboard">
        {items.map((item, i) => (
          <div key={item.domain} className="leaderboard-row">
            <span className="leaderboard-row__rank">#{i + 1}</span>
            <div className="leaderboard-row__main">
              <div className="leaderboard-row__domain" title={item.domain}>
                {item.domain}
              </div>
              <div className="leaderboard-row__bar">
                <div className="leaderboard-row__bar-fill" style={{ width: `${(item.count / max) * 100}%` }} />
              </div>
            </div>
            <span className="leaderboard-row__count">{item.count}</span>
          </div>
        ))}
        {items.length === 0 && <div className="incidents-empty">No blocked domains yet</div>}
      </div>
    </div>
  );
}
