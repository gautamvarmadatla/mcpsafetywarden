import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import Shell from "./components/layout/Shell";
import Overview from "./pages/Overview";
import Servers from "./pages/Servers";
import ServerDetail from "./pages/ServerDetail";
import Tools from "./pages/Tools";
import Findings from "./pages/Findings";
import History from "./pages/History";
import Graph from "./pages/Graph";
import Policies from "./pages/Policies";

export default function App() {
  return (
    <BrowserRouter>
      <Shell>
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/servers" element={<Servers />} />
          <Route path="/servers/:serverId" element={<ServerDetail />} />
          <Route path="/tools" element={<Tools />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/history" element={<History />} />
          <Route path="/graph" element={<Graph />} />
          <Route path="/policies" element={<Policies />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Shell>
    </BrowserRouter>
  );
}
