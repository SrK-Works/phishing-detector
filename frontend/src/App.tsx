import { useState } from "react";
import EmailChecker from "./components/EmailChecker";
import PhoneChecker from "./components/PhoneChecker";
import StatsFooter from "./components/StatsFooter";
import UrlChecker from "./components/UrlChecker";

type Tab = "url" | "email" | "phone";

const TABS: { id: Tab; label: string }[] = [
  { id: "url", label: "URL" },
  { id: "email", label: "Email" },
  { id: "phone", label: "Phone" },
];

function TabBar({ active, onChange }: { active: Tab; onChange: (tab: Tab) => void }) {
  return (
    <div className="flex justify-center gap-1 rounded-lg bg-gray-800/60 p-1 mb-8">
      {TABS.map((tab) => (
        <button
          key={tab.id}
          type="button"
          onClick={() => onChange(tab.id)}
          className={`flex-1 rounded-md px-4 py-2 text-sm font-medium transition-colors ${
            active === tab.id
              ? "bg-indigo-600 text-white"
              : "text-gray-400 hover:text-gray-200"
          }`}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}

export default function App() {
  const [tab, setTab] = useState<Tab>("url");
  const [refreshToken, setRefreshToken] = useState(0);
  const bumpRefresh = () => setRefreshToken((t) => t + 1);

  return (
    <div className="min-h-screen flex flex-col items-center px-4 py-16">
      <div className="w-full max-w-xl">
        <TabBar active={tab} onChange={setTab} />
        {tab === "url" && <UrlChecker onChecked={bumpRefresh} />}
        {tab === "email" && <EmailChecker onChecked={bumpRefresh} />}
        {tab === "phone" && <PhoneChecker onChecked={bumpRefresh} />}
        <StatsFooter type={tab} refreshToken={refreshToken} />
      </div>
    </div>
  );
}
