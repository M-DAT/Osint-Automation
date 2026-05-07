import { useState, useEffect } from 'react';
import axios from 'axios';
import { Save, UserPlus, Key, Shield, User, Trash2 } from 'lucide-react';

const SERVICES = ['whoisfreaks', 'dnsdumpster', 'ipinfo', 'urlscan', 'abuseipdb', 'virustotal'];

export default function Settings() {
  const [keys, setKeys] = useState({});
  const [keysStatus, setKeysStatus] = useState({});
  const [users, setUsers] = useState([]);
  const [newUserData, setNewUserData] = useState({ username: '', password: '', role: 'user' });
  const [pwdData, setPwdData] = useState({ old_password: '', new_password: '' });
  const [msg, setMsg] = useState('');
  const [userMsg, setUserMsg] = useState('');
  const [pwdMsg, setPwdMsg] = useState('');

  const [editingUser, setEditingUser] = useState(null);
  const [editData, setEditData] = useState({ username: '', role: '', status: '', new_password: '' });
  const [editMsg, setEditMsg] = useState('');

  const currentUser = JSON.parse(localStorage.getItem('user'));
  const isAdmin = currentUser?.role === 'admin';

  useEffect(() => {
    fetchKeysStatus();
    if (isAdmin) fetchUsers();
  }, [isAdmin]);

  const fetchKeysStatus = async () => {
    const res = await axios.get('/osint/api_keys');
    if (res.data.ok) setKeysStatus(res.data.keys_status);
  };

  const fetchUsers = async () => {
    try {
      const res = await axios.get('/auth/users');
      if (res.data.ok) {
        setUsers(res.data.users);
      } else {
        setUserMsg('Failed to load users: ' + res.data.message);
      }
    } catch (e) {
      setUserMsg('Failed to fetch users. Check console.');
    }
  };

  const saveKeys = async () => {
    try {
      const res = await axios.post('/osint/api_keys', keys);
      setMsg("Keys saved successfully");
      setKeys({});
      fetchKeysStatus();
      setTimeout(() => setMsg(''), 3000);
    } catch (e) {
      setMsg('Failed to save keys');
    }
  };

  const handleAddUser = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post('/auth/users', newUserData);
      if (res.data.ok) {
        setUserMsg("User added successfully");
        setNewUserData({ username: '', password: '', role: 'user' });
        fetchUsers();
        setTimeout(() => setUserMsg(''), 3000);
      }
    } catch (e) {
      setUserMsg(e.response?.data?.message || 'Failed to add user');
    }
  };

  const handleDeleteUser = async (userId) => {
    if (!window.confirm("Are you sure you want to delete this user?")) return;
    try {
      const res = await axios.delete(`/auth/users/${userId}`);
      if (res.data.ok) {
        setUserMsg("User deleted successfully");
        fetchUsers();
        setTimeout(() => setUserMsg(''), 3000);
      }
    } catch (e) {
      setUserMsg(e.response?.data?.message || 'Failed to delete user');
    }
  };

  const openEditUser = (user) => {
    setEditingUser(user);
    setEditData({ username: user.username, role: user.role, status: user.status || 'active', new_password: '' });
    setEditMsg('');
  };

  const handleUpdateUser = async (e) => {
    e.preventDefault();
    try {
      if (editData.username !== editingUser.username) {
        await axios.put(`/auth/users/${editingUser.id}/username`, { username: editData.username });
      }
      if (editData.role !== editingUser.role) {
        await axios.put(`/auth/users/${editingUser.id}/role`, { role: editData.role });
      }
      if (editData.status !== editingUser.status) {
        await axios.put(`/auth/users/${editingUser.id}/status`, { status: editData.status });
      }
      if (editData.new_password) {
        await axios.put(`/auth/users/${editingUser.id}/admin_password`, { new_password: editData.new_password });
      }
      setEditMsg("User updated successfully");
      fetchUsers();
      setTimeout(() => { setEditingUser(null); setEditMsg(''); }, 2000);
    } catch (e) {
      setEditMsg(e.response?.data?.message || 'Failed to update user');
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.put('/auth/users/password', pwdData);
      if (res.data.ok) {
        setPwdMsg("Password updated successfully");
        setPwdData({ old_password: '', new_password: '' });
        setTimeout(() => setPwdMsg(''), 3000);
      }
    } catch (e) {
      setPwdMsg(e.response?.data?.message || 'Failed to update password');
    }
  };

  return (
    <div className="settings-container animate-fade-in" dir="ltr">
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(450px, 1fr))', gap: '25px' }}>

        {/* API Keys Management */}
        <section className="glass-panel">
          <div className="section-header">
            <Key size={24} color="var(--primary)" />
            <h3>API Management</h3>
          </div>
          <p className="section-desc">Add and update service keys used for intelligence analysis.</p>

          <div className="keys-grid">
            {SERVICES.map(s => (
              <div key={s} className="key-input-box">
                <label>
                  {s.toUpperCase()}
                  {keysStatus[s] > 0 && <span className="status-badge">✓ {keysStatus[s]} loaded</span>}
                </label>
                <input
                  type="password"
                  value={keys[s] || ''}
                  onChange={e => setKeys({ ...keys, [s]: e.target.value })}
                  placeholder="Enter new key..."
                />
              </div>
            ))}
          </div>

          {msg && <div className="toast-msg success">{msg}</div>}
          <button onClick={saveKeys} className="w-full mt-4">
            <Save size={18} /> Save Keys
          </button>
        </section>

        {/* Change Password */}
        <section className="glass-panel">
          <div className="section-header">
            <Shield size={24} color="var(--warning)" />
            <h3>Security Settings</h3>
          </div>
          <p className="section-desc">Change your account password.</p>

          <form onSubmit={handleChangePassword} className="add-user-form">
            <div className="form-group">
              <label>Current Password</label>
              <input
                type="password"
                value={pwdData.old_password}
                onChange={e => setPwdData({ ...pwdData, old_password: e.target.value })}
                placeholder="Enter current password"
                required
              />
            </div>
            <div className="form-group" style={{ marginTop: '12px' }}>
              <label>New Password</label>
              <input
                type="password"
                value={pwdData.new_password}
                onChange={e => setPwdData({ ...pwdData, new_password: e.target.value })}
                placeholder="Enter new password"
                required
              />
            </div>
            {pwdMsg && <div className="toast-msg success" style={{ background: pwdMsg.includes('Failed') || pwdMsg.includes('غير صحيحة') ? 'rgba(239, 68, 68, 0.1)' : '', color: pwdMsg.includes('Failed') || pwdMsg.includes('غير صحيحة') ? 'var(--danger)' : '', borderColor: pwdMsg.includes('Failed') || pwdMsg.includes('غير صحيحة') ? 'rgba(239, 68, 68, 0.2)' : '' }}>{pwdMsg}</div>}
            <button type="submit" className="btn-secondary w-full" style={{ marginTop: '15px' }}>
              <Key size={18} /> Update Password
            </button>
          </form>
        </section>

        {/* User Management */}
        {isAdmin && (
          <section className="glass-panel">
            <div className="section-header">
              <Shield size={24} color="var(--secondary)" />
              <h3>User Management</h3>
            </div>
            <p className="section-desc">Add new users and assign roles.</p>

            <form onSubmit={handleAddUser} className="add-user-form">
              <div className="form-row">
                <div className="form-group">
                  <label>Username</label>
                  <input
                    type="text"
                    value={newUserData.username}
                    onChange={e => setNewUserData({ ...newUserData, username: e.target.value })}
                    placeholder="Username"
                    required
                  />
                </div>
                <div className="form-group">
                  <label>Password</label>
                  <input
                    type="password"
                    value={newUserData.password}
                    onChange={e => setNewUserData({ ...newUserData, password: e.target.value })}
                    placeholder="Password"
                    required
                  />
                </div>
              </div>
              <div className="form-group">
                <label>Role</label>
                <select
                  value={newUserData.role}
                  onChange={e => setNewUserData({ ...newUserData, role: e.target.value })}
                >
                  <option value="user">Analyst</option>
                  <option value="admin">Administrator</option>
                </select>
              </div>
              {userMsg && <div className="toast-msg success">{userMsg}</div>}
              <button type="submit" className="btn-secondary w-full">
                <UserPlus size={18} /> Add User
              </button>
            </form>

            <div className="users-list mt-4">
              <h4>Current Users</h4>
              <div className="table-container" style={{ maxHeight: '200px' }}>
                <table>
                  <thead>
                    <tr>
                      <th>Username</th>
                      <th>Role</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map(u => (
                      <tr key={u.id}>
                        <td style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <User size={14} /> {u.username}
                        </td>
                        <td>
                          <span className={`role-badge ${u.role}`}>
                            {u.role === 'admin' ? 'Admin' : 'Analyst'}
                          </span>
                        </td>
                        <td>
                          <span className={`role-badge ${u.status === 'suspended' ? 'suspended' : 'active'}`} style={{ marginLeft: '8px' }}>
                            {u.status === 'suspended' ? 'Suspended' : 'Active'}
                          </span>
                        </td>
                        <td style={{ display: 'flex', gap: '8px' }}>
                          <button 
                            onClick={() => openEditUser(u)}
                            className="btn-secondary"
                            style={{ padding: '4px 8px', fontSize: '12px', background: 'transparent', boxShadow: 'none', color: 'var(--primary)', border: '1px solid rgba(99, 102, 241, 0.2)' }}
                            title="Edit User"
                          >
                            Edit
                          </button>
                          {currentUser.username !== u.username && (
                            <button 
                              onClick={() => handleDeleteUser(u.id)}
                              className="btn-danger"
                              style={{ padding: '4px 8px', fontSize: '12px', background: 'transparent', boxShadow: 'none', color: 'var(--danger)', border: '1px solid rgba(239, 68, 68, 0.2)' }}
                              title="Delete User"
                            >
                              <Trash2 size={14} />
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </section>
        )}
      </div>

      {/* Edit User Modal */}
      {editingUser && (
        <div className="modal-overlay" onClick={() => setEditingUser(null)}>
          <div className="modal-content glass-panel" onClick={e => e.stopPropagation()}>
            <div className="section-header" style={{ marginBottom: '20px' }}>
              <User size={24} color="var(--primary)" />
              <h3>Edit User: {editingUser.username}</h3>
            </div>
            <form onSubmit={handleUpdateUser} className="add-user-form">
              <div className="form-row">
                <div className="form-group">
                  <label>Username</label>
                  <input
                    type="text"
                    value={editData.username}
                    onChange={e => setEditData({ ...editData, username: e.target.value })}
                    required
                  />
                </div>
                <div className="form-group">
                  <label>Reset Password (Optional)</label>
                  <input
                    type="password"
                    placeholder="Leave blank to keep current"
                    value={editData.new_password}
                    onChange={e => setEditData({ ...editData, new_password: e.target.value })}
                  />
                </div>
              </div>
              <div className="form-row">
                <div className="form-group">
                  <label>Role</label>
                  <select
                    value={editData.role}
                    onChange={e => setEditData({ ...editData, role: e.target.value })}
                    disabled={currentUser.username === editingUser.username}
                  >
                    <option value="user">Analyst</option>
                    <option value="admin">Administrator</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Status</label>
                  <select
                    value={editData.status}
                    onChange={e => setEditData({ ...editData, status: e.target.value })}
                    disabled={currentUser.username === editingUser.username}
                  >
                    <option value="active">Active</option>
                    <option value="suspended">Suspended</option>
                  </select>
                </div>
              </div>
              {editMsg && <div className="toast-msg success" style={{ background: editMsg.includes('Failed') || editMsg.includes('موجود') ? 'rgba(239, 68, 68, 0.1)' : '', color: editMsg.includes('Failed') || editMsg.includes('موجود') ? 'var(--danger)' : '', borderColor: editMsg.includes('Failed') || editMsg.includes('موجود') ? 'rgba(239, 68, 68, 0.2)' : '' }}>{editMsg}</div>}
              <div style={{ display: 'flex', gap: '10px', marginTop: '15px' }}>
                <button type="button" className="btn-secondary w-full" onClick={() => setEditingUser(null)} style={{ background: 'transparent', border: '1px solid rgba(255,255,255,0.1)' }}>
                  Cancel
                </button>
                <button type="submit" className="btn-secondary w-full">
                  <Save size={18} /> Save Changes
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <style dangerouslySetInnerHTML={{
        __html: `
        .section-header {
          display: flex;
          align-items: center;
          gap: 12px;
          margin-bottom: 8px;
        }
        .section-header h3 { margin: 0; font-size: 20px; }
        .section-desc { color: var(--text-dim); font-size: 14px; margin-bottom: 24px; }
        
        .keys-grid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 16px;
        }
        .key-input-box label {
          display: flex;
          justify-content: space-between;
          font-size: 12px;
          font-weight: 700;
          color: var(--text-dim);
          margin-bottom: 6px;
        }
        .status-badge { color: var(--success); font-size: 10px; }
        
        .add-user-form {
          background: rgba(0,0,0,0.2);
          padding: 20px;
          border-radius: 16px;
          border: 1px solid rgba(255,255,255,0.05);
        }
        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }
        .form-group label { display: block; font-size: 12px; color: var(--text-dim); margin-bottom: 6px; }
        .form-group input, .form-group select { width: 100%; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; padding: 10px; color: #fff; outline: none; }
        .form-group input:focus { border-color: var(--primary); }
        
        .toast-msg { padding: 10px; border-radius: 10px; font-size: 13px; text-align: center; margin: 15px 0; }
        .toast-msg.success { background: rgba(16, 185, 129, 0.1); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.2); }
        
        .role-badge { padding: 4px 10px; border-radius: 8px; font-size: 11px; font-weight: 700; }
        .role-badge.admin { background: rgba(139, 92, 246, 0.2); color: var(--secondary); }
        .role-badge.user { background: rgba(99, 102, 241, 0.2); color: var(--primary); }
        .role-badge.active { background: rgba(16, 185, 129, 0.2); color: var(--success); }
        .role-badge.suspended { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
        
        h4 { margin: 20px 0 10px; font-size: 15px; color: var(--text-dim); }

        .modal-overlay {
          position: fixed; top: 0; left: 0; right: 0; bottom: 0;
          background: rgba(0,0,0,0.7); backdrop-filter: blur(5px);
          display: flex; align-items: center; justify-content: center;
          z-index: 1000;
        }
        .modal-content {
          width: 100%; max-width: 500px;
          padding: 24px;
        }
      `}} />
    </div>
  );
}
