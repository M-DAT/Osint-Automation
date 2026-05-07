import { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import axios from 'axios';
import Scanner from './pages/Scanner';
import Osint from './pages/Osint';
import Login from './pages/Login';
import Settings from './pages/Settings';
import DashboardLayout from './components/DashboardLayout';

// Axios global setup
axios.interceptors.request.use(config => {
  const token = localStorage.getItem('token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

axios.interceptors.response.use(
  res => res,
  err => {
    if (err.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
      setUser(JSON.parse(savedUser));
    }
    setLoading(false);
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
  };

  if (loading) return null;

  return (
    <Router>
      <Routes>
        <Route path="/login" element={!user ? <Login onLoginSuccess={setUser} /> : <Navigate to="/" />} />
        
        <Route path="/" element={user ? (
          <DashboardLayout user={user} onLogout={handleLogout}>
            <Scanner />
          </DashboardLayout>
        ) : <Navigate to="/login" />} />

        <Route path="/osint" element={user ? (
          <DashboardLayout user={user} onLogout={handleLogout}>
            <Osint />
          </DashboardLayout>
        ) : <Navigate to="/login" />} />

        <Route path="/settings" element={user ? (
          <DashboardLayout user={user} onLogout={handleLogout}>
            <Settings />
          </DashboardLayout>
        ) : <Navigate to="/login" />} />

        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </Router>
  );
}

export default App;
