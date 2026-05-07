import { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { ShieldCheck, Lock, User, ArrowRight } from 'lucide-react';

export default function Login({ onLoginSuccess }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    
    try {
      const res = await axios.post('/auth/login', { username, password });
      if (res.data.ok) {
        localStorage.setItem('token', res.data.token);
        localStorage.setItem('user', JSON.stringify(res.data.user));
        onLoginSuccess(res.data.user);
        navigate('/');
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page" dir="ltr">
      <div className="login-glass">
        <div className="login-header">
          <div className="logo-box">
            <ShieldCheck size={48} color="var(--primary)" />
          </div>
          <h1>VT Hash Scanner</h1>
          <p>Advanced Threat Intelligence & Cybersecurity Platform</p>
        </div>

        <form onSubmit={handleLogin} className="login-form">
          <div className="input-group">
            <label>Username</label>
            <div className="input-wrapper">
              <User size={18} className="input-icon" />
              <input 
                type="text" 
                value={username} 
                onChange={(e) => setUsername(e.target.value)} 
                placeholder="Enter your username..."
                required
              />
            </div>
          </div>

          <div className="input-group">
            <label>Password</label>
            <div className="input-wrapper">
              <Lock size={18} className="input-icon" />
              <input 
                type="password" 
                value={password} 
                onChange={(e) => setPassword(e.target.value)} 
                placeholder="Enter your password..."
                required
              />
            </div>
          </div>

          {error && <div className="login-error">{error}</div>}

          <button type="submit" disabled={loading} className="login-btn">
            {loading ? 'Authenticating...' : (
              <>
                Sign In <ArrowRight size={18} />
              </>
            )}
          </button>
        </form>

        <div className="login-footer">
          <p>Secured by advanced encryption technology</p>
        </div>
      </div>

      <style dangerouslySetInnerHTML={{ __html: `
        .login-page {
          height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          background: radial-gradient(circle at 10% 20%, #1e1b4b 0%, #09090b 90%);
          overflow: hidden;
          position: relative;
        }

        .login-page::before {
          content: '';
          position: absolute;
          width: 500px;
          height: 500px;
          background: var(--primary);
          filter: blur(150px);
          opacity: 0.15;
          top: -100px;
          right: -100px;
        }

        .login-page::after {
          content: '';
          position: absolute;
          width: 400px;
          height: 400px;
          background: var(--secondary);
          filter: blur(150px);
          opacity: 0.1;
          bottom: -100px;
          left: -100px;
        }

        .login-glass {
          width: 100%;
          max-width: 450px;
          background: rgba(255, 255, 255, 0.03);
          backdrop-filter: blur(30px);
          border: 1px solid rgba(255, 255, 255, 0.08);
          border-radius: 32px;
          padding: 50px;
          box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
          z-index: 10;
          animation: slideUp 0.6s cubic-bezier(0.16, 1, 0.3, 1);
        }

        @keyframes slideUp {
          from { opacity: 0; transform: translateY(30px); }
          to { opacity: 1; transform: translateY(0); }
        }

        .login-header {
          text-align: center;
          margin-bottom: 40px;
        }

        .logo-box {
          margin-bottom: 20px;
          display: inline-block;
          padding: 20px;
          background: rgba(99, 102, 241, 0.1);
          border-radius: 24px;
        }

        .login-header h1 {
          font-size: 28px;
          margin-bottom: 8px;
        }

        .login-header p {
          color: var(--text-dim);
          font-size: 14px;
        }

        .input-group {
          margin-bottom: 24px;
        }

        .input-group label {
          display: block;
          margin-bottom: 8px;
          font-size: 14px;
          color: var(--text-dim);
          font-weight: 600;
        }

        .input-wrapper {
          position: relative;
        }

        .input-icon {
          position: absolute;
          left: 16px; /* Changed from right to left */
          top: 50%;
          transform: translateY(-50%);
          color: var(--text-dim);
        }

        .input-wrapper input {
          width: 100%;
          padding: 14px 16px 14px 44px; /* Adjusted padding for LTR icon */
          background: rgba(0, 0, 0, 0.3);
          border: 1px solid rgba(255, 255, 255, 0.08);
          border-radius: 12px;
          color: #fff;
          font-size: 14px;
          transition: all 0.3s;
        }

        .input-wrapper input:focus {
          border-color: var(--primary);
          background: rgba(0, 0, 0, 0.5);
          box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.1);
        }

        .login-error {
          background: rgba(239, 68, 68, 0.1);
          color: #ef4444;
          padding: 12px;
          border-radius: 12px;
          font-size: 13px;
          text-align: center;
          margin-bottom: 20px;
          border: 1px solid rgba(239, 68, 68, 0.2);
        }

        .login-btn {
          width: 100%;
          padding: 18px;
          border-radius: 16px;
          font-size: 16px;
          margin-top: 10px;
          background: linear-gradient(135deg, var(--primary), var(--secondary));
        }

        .login-footer {
          margin-top: 30px;
          text-align: center;
          color: var(--muted);
          font-size: 12px;
        }
      `}} />
    </div>
  );
}
