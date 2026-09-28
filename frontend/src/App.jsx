import { Routes, Route, Navigate } from 'react-router-dom';

import AuthLayout from './layouts/AuthLayout.jsx';
import AppLayout from './layouts/AppLayout.jsx';

import Home from './pages/Home.jsx';
import Login from './pages/Login.jsx';
import Register from './pages/Register.jsx';
import Dashboard from './pages/Dashboard.jsx';
import Files from './pages/Files.jsx';
import Upload from './pages/Upload.jsx';
import Shared from './pages/Shared.jsx';
import Security from './pages/Security.jsx';
import Audit from './pages/Audit.jsx';
import Profile from './pages/Profile.jsx';
import NotFound from './pages/NotFound.jsx';

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="/status" element={<Home />} />

      {/* Public pages */}
      <Route element={<AuthLayout />}>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
      </Route>

      {/* App pages. Phase 5 wraps these in a ProtectedRoute that requires login. */}
      <Route element={<AppLayout />}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/files" element={<Files />} />
        <Route path="/upload" element={<Upload />} />
        <Route path="/shared" element={<Shared />} />
        <Route path="/security" element={<Security />} />
        <Route path="/audit" element={<Audit />} />
        <Route path="/profile" element={<Profile />} />
      </Route>

      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}