import { Routes, Route } from 'react-router-dom';
import Home from './pages/Home.jsx';

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      {/* Later phases: /login /register /dashboard /files /upload /shared /security /audit /profile */}
    </Routes>
  );
}