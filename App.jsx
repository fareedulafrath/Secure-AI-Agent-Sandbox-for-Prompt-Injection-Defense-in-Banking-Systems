import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { ThreatStoreProvider } from './lib/store/threatStore';
import Layout from './components/layout/Layout';
import ChatPage from './pages/ChatPage';
import AttackLabPage from './pages/AttackLabPage';
import AnalyticsPage from './pages/AnalyticsPage';
import AuditLogsPage from './pages/AuditLogsPage';
import AdminPage from './pages/AdminPage';

export default function App() {
  return (
    <ThreatStoreProvider>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route path="/" element={<Navigate to="/chat" replace />} />
            <Route path="/chat" element={<ChatPage />} />
            <Route path="/attack-lab" element={<AttackLabPage />} />
            <Route path="/analytics" element={<AnalyticsPage />} />
            <Route path="/audit-logs" element={<AuditLogsPage />} />
            <Route path="/admin" element={<AdminPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: 'rgba(17, 24, 39, 0.95)',
            color: '#f1f5f9',
            border: '1px solid rgba(148, 163, 184, 0.1)',
            backdropFilter: 'blur(12px)',
            fontSize: '14px',
          },
        }}
      />
    </ThreatStoreProvider>
  );
}
