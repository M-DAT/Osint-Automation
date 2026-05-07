import { useState, useEffect } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { Search, Globe, Settings, LogOut, LayoutDashboard, ShieldCheck, User, Key, Save } from 'lucide-react';
import axios from 'axios';

export default function DashboardLayout({ children, user, onLogout }) {
  const location = useLocation();
  const navigate = useNavigate();
  const [showProfile, setShowProfile] = useState(false);
  const [profileData, setProfileData] = useState({ username: user?.username || '', new_password: '' });
  const [profileMsg, setProfileMsg] = useState('');

  const menuItems = [
    { name: 'Scanner', icon: <Search size={20} />, path: '/' },
    { name: 'Automated OSINT', icon: <Globe size={20} />, path: '/osint' },
    { name: 'Settings', icon: <Settings size={20} />, path: '/settings' },
  ];

  const handleLogout = () => {
    onLogout();
    navigate('/login');
  };

  const handleUpdateProfile = async (e) => {
    e.preventDefault();
    setProfileMsg('');
    try {
      if (profileData.username !== user.username) {
        const res = await axios.put(`/auth/users/${user.id}/username`, { username: profileData.username });
        if (res.data.ok) {
           const updatedUser = { ...user, username: profileData.username };
           localStorage.setItem('user', JSON.stringify(updatedUser));
           // Force a reload so App.jsx picks up the new username
           window.location.reload();
           return;
        }
      }
      if (profileData.new_password) {
        const pwdRes = await axios.put('/auth/users/password', { 
           old_password: profileData.old_password, 
           new_password: profileData.new_password 
        });
        if (pwdRes.data.ok) {
           setProfileMsg("Password updated successfully");
           setTimeout(() => { setShowProfile(false); setProfileData({...profileData, old_password: '', new_password: ''}) }, 2000);
        }
      } else {
        setProfileMsg("Profile updated successfully");
        setTimeout(() => setShowProfile(false), 2000);
      }
    } catch (e) {
      setProfileMsg(e.response?.data?.message || 'Failed to update profile');
    }
  };

  return (
    <div className="app-container" dir="ltr">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-logo">
          <ShieldCheck size={32} color="var(--primary)" />
          <span>VT SCANNER</span>
        </div>

        <nav className="sidebar-nav">
          {menuItems.map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={`nav-item ${location.pathname === item.path ? 'active' : ''}`}
            >
              {item.icon}
              <span>{item.name}</span>
            </Link>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="user-info" onClick={() => setShowProfile(true)} style={{ cursor: 'pointer', padding: '10px', borderRadius: '12px', background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.05)', transition: 'all 0.2s', marginBottom: '15px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div className="user-avatar">{user?.username?.[0].toUpperCase()}</div>
              <div className="user-details">
                <div className="username">{user?.username}</div>
                <div className="role">{user?.role === 'admin' ? 'Administrator' : 'Analyst'}</div>
              </div>
            </div>
            <div style={{ fontSize: '10px', color: 'var(--primary)', marginTop: '8px', textAlign: 'center' }}>Click to edit profile</div>
          </div>
          <button onClick={handleLogout} className="logout-btn">
            <LogOut size={16} />
            <span>Logout</span>
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="main-wrapper">
        <header className="main-header">
          <div className="header-title">
            {menuItems.find(i => i.path === location.pathname)?.name || 'Dashboard'}
          </div>
          <div className="header-actions">
            {/* Notifications or Search */}
          </div>
        </header>

        <main className="content-area">
          {children}
        </main>

        <footer className="main-footer">
          <p>© 2026 VT Hash Scanner - Advanced Threat Intelligence</p>
          <div className="footer-links">
            <span>Version 2.0.0</span>
          </div>
        </footer>
      </div>

      {/* Profile Modal */}
      {showProfile && (
        <div className="modal-overlay" onClick={() => setShowProfile(false)}>
          <div className="modal-content glass-panel" onClick={e => e.stopPropagation()}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '20px' }}>
              <User size={24} color="var(--primary)" />
              <h3 style={{ margin: 0, fontSize: '20px' }}>My Profile</h3>
            </div>
            <form onSubmit={handleUpdateProfile}>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '12px', color: 'var(--text-dim)', marginBottom: '6px' }}>Username</label>
                <input
                  type="text"
                  value={profileData.username}
                  onChange={e => setProfileData({ ...profileData, username: e.target.value })}
                  required
                  style={{ width: '100%', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '10px', padding: '10px', color: '#fff', outline: 'none' }}
                />
              </div>
              
              <div style={{ padding: '15px', background: 'rgba(255,255,255,0.02)', borderRadius: '12px', marginBottom: '16px', border: '1px solid rgba(255,255,255,0.05)' }}>
                <h4 style={{ margin: '0 0 10px 0', fontSize: '14px', color: 'var(--text-dim)' }}>Change Password</h4>
                <div style={{ marginBottom: '12px' }}>
                  <input
                    type="password"
                    placeholder="Current Password"
                    value={profileData.old_password || ''}
                    onChange={e => setProfileData({ ...profileData, old_password: e.target.value })}
                    style={{ width: '100%', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '10px', padding: '10px', color: '#fff', outline: 'none' }}
                  />
                </div>
                <div>
                  <input
                    type="password"
                    placeholder="New Password"
                    value={profileData.new_password || ''}
                    onChange={e => setProfileData({ ...profileData, new_password: e.target.value })}
                    style={{ width: '100%', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '10px', padding: '10px', color: '#fff', outline: 'none' }}
                  />
                </div>
              </div>

              {profileMsg && <div style={{ padding: '10px', borderRadius: '10px', fontSize: '13px', textAlign: 'center', marginBottom: '15px', background: profileMsg.includes('Failed') || profileMsg.includes('صحيحة') ? 'rgba(239, 68, 68, 0.1)' : 'rgba(16, 185, 129, 0.1)', color: profileMsg.includes('Failed') || profileMsg.includes('صحيحة') ? 'var(--danger)' : 'var(--success)' }}>{profileMsg}</div>}
              
              <div style={{ display: 'flex', gap: '10px' }}>
                <button type="button" onClick={() => setShowProfile(false)} style={{ flex: 1, padding: '12px', borderRadius: '10px', background: 'transparent', border: '1px solid rgba(255,255,255,0.1)', color: '#fff', cursor: 'pointer' }}>Cancel</button>
                <button type="submit" style={{ flex: 1, padding: '12px', borderRadius: '10px', background: 'linear-gradient(135deg, var(--primary), var(--secondary))', border: 'none', color: '#fff', fontWeight: 'bold', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
                  <Save size={16} /> Save Changes
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <style dangerouslySetInnerHTML={{
        __html: `
        .app-container {
          display: flex;
          min-height: 100vh;
          background: var(--bg-gradient);
          background-attachment: fixed;
          font-family: 'Inter', system-ui, sans-serif;
        }

        .sidebar {
          width: var(--sidebar-width, 280px);
          background: rgba(15, 15, 25, 0.7);
          backdrop-filter: blur(20px);
          border-right: 1px solid rgba(255, 255, 255, 0.05); /* LTR border */
          display: flex;
          flex-direction: column;
          padding: 24px;
          position: fixed;
          height: 100vh;
          left: 0; /* Changed from right to left */
          z-index: 100;
        }

        .sidebar-logo {
          display: flex;
          align-items: center;
          gap: 12px;
          font-size: 20px;
          font-weight: 800;
          color: #fff;
          margin-bottom: 40px;
          letter-spacing: 1px;
        }

        .sidebar-nav {
          flex: 1;
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        .nav-item {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 12px 16px;
          border-radius: 12px;
          color: var(--text-dim);
          text-decoration: none;
          font-weight: 500;
          transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .nav-item:hover {
          background: rgba(255, 255, 255, 0.05);
          color: #fff;
        }

        .nav-item.active {
          background: linear-gradient(135deg, rgba(99, 102, 241, 0.15), rgba(139, 92, 246, 0.15));
          color: var(--primary);
          border: 1px solid rgba(99, 102, 241, 0.2);
        }

        .sidebar-footer {
          margin-top: auto;
          padding-top: 24px;
          border-top: 1px solid rgba(255, 255, 255, 0.05);
        }

        .user-info {
          display: flex;
          align-items: center;
          gap: 12px;
          margin-bottom: 20px;
        }

        .user-avatar {
          width: 36px;
          height: 36px;
          border-radius: 10px;
          background: linear-gradient(135deg, var(--primary), var(--secondary));
          display: flex;
          align-items: center;
          justify-content: center;
          font-weight: bold;
          font-size: 14px;
          color: #fff;
        }

        .user-details .username {
          font-weight: 600;
          color: #fff;
          font-size: 13px;
        }

        .user-details .role {
          font-size: 11px;
          color: var(--text-dim);
        }

        .logout-btn {
          width: 100%;
          background: rgba(239, 68, 68, 0.1);
          color: #ef4444;
          border: 1px solid rgba(239, 68, 68, 0.1);
          box-shadow: none;
          padding: 10px;
          font-size: 13px;
        }

        .logout-btn:hover {
          background: rgba(239, 68, 68, 0.2);
          transform: none;
        }

        .main-wrapper {
          flex: 1;
          margin-left: var(--sidebar-width, 280px); /* Changed from margin-right */
          display: flex;
          flex-direction: column;
          min-height: 100vh;
        }

        .main-header {
          height: 70px;
          padding: 0 40px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          background: rgba(10, 10, 15, 0.3);
          backdrop-filter: blur(10px);
          border-bottom: 1px solid rgba(255, 255, 255, 0.05);
          position: sticky;
          top: 0;
          z-index: 90;
        }

        .header-title {
          font-size: 16px;
          font-weight: 600;
          color: var(--text-dim);
          letter-spacing: 0.5px;
        }

        .content-area {
          flex: 1;
          padding: 30px 40px;
          max-width: 1400px;
          margin: 0 auto;
          width: 100%;
        }

        .main-footer {
          padding: 20px 40px;
          display: flex;
          justify-content: space-between;
          align-items: center;
          border-top: 1px solid rgba(255, 255, 255, 0.05);
          color: var(--text-dim);
          font-size: 12px;
        }
        
        .user-info:hover {
          background: rgba(255,255,255,0.06) !important;
        }

        .modal-overlay {
          position: fixed; top: 0; left: 0; right: 0; bottom: 0;
          background: rgba(0,0,0,0.7); backdrop-filter: blur(5px);
          display: flex; align-items: center; justify-content: center;
          z-index: 1000;
        }
        .modal-content {
          width: 100%; max-width: 400px;
          padding: 24px;
          background: rgba(20, 20, 30, 0.95);
          border-radius: 16px;
          border: 1px solid rgba(255,255,255,0.1);
        }
      `}} />
    </div>
  );
}
