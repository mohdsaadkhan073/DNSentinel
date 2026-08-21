import React from 'react';
import { Search, Sun, Moon, UploadCloud, RefreshCw, X } from 'lucide-react';

interface HeaderProps {
  wsConnected: boolean;
  theme: 'dark' | 'light';
  setTheme: (theme: 'dark' | 'light') => void;
  onOpenUpload: () => void;
  onOpenSearch?: () => void;
  onRefresh: () => void;
  globalSearch: string;
  setGlobalSearch: (search: string) => void;
}

export const Header: React.FC<HeaderProps> = ({
  theme,
  setTheme,
  onOpenUpload,
  onOpenSearch,
  onRefresh,
  globalSearch,
  setGlobalSearch
}) => {
  return (
    <header className={`border-b sticky top-0 z-30 w-full px-6 py-3.5 flex items-center justify-between gap-4 font-mono transition-colors rounded-none m-0 ${
      theme === 'light' 
        ? '!bg-white border-slate-200 text-slate-900 shadow-sm' 
        : '!bg-[#04160E] border-emerald-900/40 text-slate-100'
    }`}>
      
      {/* Left: Universal Command Palette Search Bar */}
      <div 
        onClick={() => onOpenSearch && onOpenSearch()}
        className="relative w-full max-w-md flex items-center cursor-pointer group"
      >
        <Search className="w-4 h-4 absolute left-3.5 text-slate-400 group-hover:text-emerald-500 pointer-events-none shrink-0 transition-colors" />
        <input
          type="text"
          placeholder="Search..."
          value={globalSearch}
          onFocus={() => onOpenSearch && onOpenSearch()}
          onChange={(e) => {
            setGlobalSearch(e.target.value);
            if (onOpenSearch) onOpenSearch();
          }}
          className={`w-full pl-10 pr-16 py-2 rounded-xl text-xs font-mono placeholder-slate-400 focus:outline-none transition-all shadow-sm cursor-pointer ${
            theme === 'light'
              ? '!bg-white !text-slate-900 border border-slate-300 focus:border-emerald-500'
              : '!bg-[#05120C] !text-slate-100 border border-emerald-500/80 focus:border-emerald-400'
          }`}
        />
        {globalSearch && (
          <div className="absolute right-3 flex items-center gap-1">
            <button
              onClick={(e) => {
                e.stopPropagation();
                setGlobalSearch('');
              }}
              className="text-slate-400 hover:text-rose-500 transition-colors p-0.5 rounded-full pointer-events-auto"
              title="Clear search"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
      </div>

      {/* Right: Iconic Action Buttons with High-Contrast Refresh Button */}
      <div className="flex items-center gap-2.5">
        
        {/* Upload Icon Button */}
        <button
          onClick={onOpenUpload}
          className="p-2 rounded-xl btn-emerald-primary text-white transition-all flex items-center justify-center shadow-sm"
          title="Upload PCAP / Zeek File"
        >
          <UploadCloud className="w-4 h-4" />
        </button>

        {/* Theme Switcher Icon Button */}
        <button
          onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
          className={`p-2 rounded-xl border transition-all flex items-center justify-center ${
            theme === 'light'
              ? 'bg-slate-100 border-slate-300 text-slate-700 hover:text-emerald-600'
              : 'bg-[#05120C] border-emerald-900/40 text-slate-300 hover:text-white hover:border-emerald-500'
          }`}
          title={theme === 'dark' ? "Switch to Light Enterprise Mode" : "Switch to Dark Command Mode"}
        >
          {theme === 'dark' ? (
            <Moon className="w-4 h-4 text-amber-300" />
          ) : (
            <Sun className="w-4 h-4 text-amber-500" />
          )}
        </button>

        {/* High-Contrast Refresh Button */}
        <button
          onClick={onRefresh}
          className={`p-2 rounded-xl border transition-all flex items-center justify-center font-bold ${
            theme === 'light'
              ? 'bg-slate-100 border-slate-300 text-slate-800 hover:text-emerald-600 hover:bg-slate-200'
              : 'bg-[#05120C] border-emerald-900/40 text-emerald-400 hover:text-white'
          }`}
          title="Refresh Data & Reload Animations"
        >
          <RefreshCw className="w-4 h-4" />
        </button>

      </div>

    </header>
  );
};
