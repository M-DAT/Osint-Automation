import { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';
import html2pdf from 'html2pdf.js';
import { Play, Pause, Square, Trash2, Download, FileText, Upload, Globe } from 'lucide-react';

export default function Scanner() {
  const [globalApiKeys, setGlobalApiKeys] = useState([]);
  const [newKey, setNewKey] = useState('');
  const [hashesText, setHashesText] = useState('');
  const [validHashesCount, setValidHashesCount] = useState(0);
  const [delay, setDelay] = useState(5);
  
  const [isScanning, setIsScanning] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [shouldStop, setShouldStop] = useState(false);
  
  const [results, setResults] = useState([]);
  const [filter, setFilter] = useState('all');
  const [message, setMessage] = useState('');

  // Use refs for mutable state accessed inside async loops to get fresh values
  const isPausedRef = useRef(isPaused);
  const shouldStopRef = useRef(shouldStop);

  useEffect(() => {
    isPausedRef.current = isPaused;
    shouldStopRef.current = shouldStop;
  }, [isPaused, shouldStop]);

  useEffect(() => {
    axios.get('/get_api_keys').then(res => {
      if (res.data.ok) setGlobalApiKeys(res.data.keys);
    });
  }, []);



  const handleHashesChange = (e) => {
    setHashesText(e.target.value);
    const items = e.target.value.split(/[\s,;]+/);
    const valid = items.filter(h => h.trim().length > 10).length; // rough valid check for UI speed
    setValidHashesCount(valid);
  };

  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

  const startScan = async () => {
    if (globalApiKeys.length === 0) return setMessage("Please add a VirusTotal API Key in Settings");
    if (!hashesText.trim()) return setMessage("Please enter a list of targets");

    setIsScanning(true);
    setIsPaused(false);
    setShouldStop(false);
    setResults([]);
    setMessage('');

    try {
      const parseRes = await axios.post('/parse_hashes', { hashes: hashesText });
      const hashes = parseRes.data.hashes;
      
      if (hashes.length === 0) {
        setMessage("No valid items found");
        setIsScanning(false);
        return;
      }

      let currentKeyIndex = 0;
      let newResults = [];

      for (let i = 0; i < hashes.length; i++) {
        if (shouldStopRef.current) break;
        
        while (isPausedRef.current) {
          await sleep(500);
          if (shouldStopRef.current) break;
        }
        if (shouldStopRef.current) break;

        const currentHash = hashes[i];
        let scanSuccess = false;
        let hashResult = null;

        while (!scanSuccess && currentKeyIndex < globalApiKeys.length) {
          setMessage(`Scanning ${i+1}/${hashes.length}: ${currentHash}`);
          
          try {
            const scanRes = await axios.post('/scan_one', { api_key: globalApiKeys[currentKeyIndex], hash: currentHash });
            if (scanRes.data.ok) {
              const resObj = scanRes.data.result;
              if (resObj.label === "Rate Limit" || resObj.description === "Invalid API Key") {
                currentKeyIndex++;
                setMessage("Switching API key...");
                await sleep(1000);
              } else {
                hashResult = resObj;
                scanSuccess = true;
              }
            } else {
              hashResult = { hash: currentHash, status: "error", label: "Error" };
              break;
            }
          } catch(e) {
             hashResult = { hash: currentHash, status: "error", label: "Connection Error" };
             break;
          }
        }

        newResults = [...newResults, hashResult];
        setResults(newResults);

        if (delay > 0 && i < hashes.length - 1) {
          for (let d = 0; d < delay * 10; d++) {
            if (shouldStopRef.current) break;
            await sleep(100);
          }
        }
      }

      setMessage(`Completed. Scanned ${newResults.length} items.`);
    } catch(e) {
      setMessage("A general error occurred.");
    }

    setIsScanning(false);
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (ev) => {
        setHashesText(ev.target.result);
        const valid = ev.target.result.split(/[\s,;]+/).filter(h => h.trim().length > 10).length;
        setValidHashesCount(valid);
      };
      reader.readAsText(file);
    }
  };

  const clearAll = () => {
    setHashesText('');
    setValidHashesCount(0);
    setResults([]);
    setMessage('');
  };

  const exportCSV = () => {
    const toExport = filter === 'all' ? results : results.filter(r => r.status === filter);
    let csv = "hash,status,malicious,suspicious,harmless,file_name\n";
    toExport.forEach(r => {
      csv += `${r.hash},${r.status},${r.malicious || 0},${r.suspicious || 0},${r.harmless || 0},"${r.file_name || '-'}"\n`;
    });
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "vt_scan.csv"; a.click();
  };

  const exportPDF = () => {
    const toExport = filter === 'all' ? results : results.filter(r => r.status === filter);
    const element = document.createElement('div');
    element.dir = 'ltr';
    element.style.fontFamily = 'sans-serif';
    element.innerHTML = `<h2 style="text-align:center">VirusTotal Report</h2>
      <table border="1" style="width:100%; border-collapse:collapse; text-align:left; direction:ltr; font-size:12px;">
        <tr style="background:#eee"><th>Item</th><th>Status</th><th>Malicious</th><th>Suspicious</th></tr>
        ${toExport.map(r => `<tr><td>${r.hash}</td><td>${r.label}</td><td style="color:red">${r.malicious||'-'}</td><td style="color:orange">${r.suspicious||'-'}</td></tr>`).join('')}
      </table>`;
    html2pdf().set({ margin: 10, filename: 'vt_report.pdf', jsPDF: { format: 'a4', orientation: 'landscape' } }).from(element).save();
  };

  const stats = {
    total: results.length,
    clean: results.filter(r => r.status === 'clean').length,
    malicious: results.filter(r => r.status === 'malicious').length,
    suspicious: results.filter(r => r.status === 'suspicious').length,
  };

  const filteredResults = filter === 'all' ? results : results.filter(r => r.status === filter);
  
  const progress = validHashesCount > 0 ? (results.length / validHashesCount) * 100 : 0;
  const estimatedTimeLeft = Math.max(0, (validHashesCount - results.length) * (delay || 1));

  return (
    <div dir="ltr">
      <div className="glass-panel">
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '5px', marginBottom: '10px' }}>
          <div style={{ fontWeight: 'bold', color: 'var(--text-dim)' }}>List of targets to scan:</div>
          <div style={{ background: 'rgba(99,102,241,0.15)', color: 'var(--primary)', padding: '5px 12px', borderRadius: '12px', fontWeight: 'bold' }}>
            Valid Items: {validHashesCount}
          </div>
        </div>
        <textarea value={hashesText} onChange={handleHashesChange} placeholder="Paste hashes, IPs, or domains here (MD5, SHA-256, IP, Domain)..." />

        <div style={{ display: 'flex', gap: '15px', marginTop: '20px', flexWrap: 'wrap', alignItems: 'center' }}>
          <input type="number" value={delay} onChange={e => setDelay(Number(e.target.value))} title="Delay in seconds" style={{ width: '120px', textAlign: 'center' }} />
          
          {!isScanning ? (
            <>
              <button onClick={startScan} disabled={isScanning || validHashesCount === 0} style={{ width: '180px' }}>
                <Play size={18} /> Start Scan
              </button>
              <button onClick={clearAll} className="btn-danger"><Trash2 size={18}/> Clear All</button>
            </>
          ) : (
            <>
              <button onClick={() => setIsPaused(!isPaused)} className="btn-secondary" style={{ color: isPaused ? 'var(--success)' : '' }}>
                {isPaused ? <Play size={18}/> : <Pause size={18}/>} {isPaused ? 'Resume' : 'Pause'}
              </button>
              <button onClick={() => setShouldStop(true)} className="btn-danger"><Square size={18}/> Stop</button>
            </>
          )}

          <div style={{ marginLeft: 'auto', display: 'flex', gap: '10px' }}>
            <label className="btn-secondary" style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', cursor: 'pointer', padding: '10px 16px', borderRadius: '12px' }}>
              <Upload size={16} /> Import TXT
              <input type="file" accept=".txt" onChange={handleFileUpload} style={{ display: 'none' }} />
            </label>
            <button onClick={exportCSV} className="btn-secondary" style={{ padding: '10px 16px' }}><Download size={16}/> CSV</button>
            <button onClick={exportPDF} className="btn-secondary" style={{ padding: '10px 16px' }}><FileText size={16}/> PDF</button>
          </div>
        </div>
      </div>

      {(isScanning || progress > 0) && (
        <div className="glass-panel" style={{ marginTop: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px', fontSize: '14px' }}>
            <span>Scan Progress</span>
            <span style={{ fontWeight: 'bold', color: 'var(--primary)' }}>{Math.round(progress)}%</span>
          </div>
          <div className="progress-bar" style={{ background: 'rgba(255,255,255,0.1)', height: '8px', borderRadius: '4px', overflow: 'hidden' }}>
            <div className="progress-fill" style={{ width: `${progress}%`, background: 'var(--primary)', height: '100%', transition: 'width 0.3s' }}></div>
          </div>
          <div style={{ textAlign: 'center', marginTop: '10px', color: 'var(--text-dim)', fontSize: '13px' }}>
            Remaining time: ~{estimatedTimeLeft} seconds
          </div>
        </div>
      )}

      {results.length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '20px', marginTop: '20px' }}>
          <StatCard title="Malicious" value={stats.malicious} color="var(--danger)" />
          <StatCard title="Suspicious" value={stats.suspicious} color="var(--warning)" />
          <StatCard title="Clean / Undetected" value={stats.clean} color="var(--success)" />
        </div>
      )}

      {message && <div style={{ color: '#fde047', textAlign: 'center', fontWeight: 'bold', margin: '20px 0' }}>{message}</div>}

      <div className="glass-panel" style={{ marginTop: '30px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '20px', flexWrap: 'wrap', gap: '15px' }}>
          <div style={{ display: 'flex', gap: '10px' }}>
            {['all', 'clean', 'malicious', 'suspicious'].map(f => (
              <button key={f} onClick={() => setFilter(f)} className={filter === f ? '' : 'btn-secondary'} style={{ padding: '8px 16px', borderRadius: '20px' }}>
                {f.charAt(0).toUpperCase() + f.slice(1)}
              </button>
            ))}
          </div>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>Indicator</th>
                <th>Status</th>
                <th>Malicious</th>
                <th>Suspicious</th>
                <th>Harmless</th>
                <th>Name / Owner</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredResults.map((r, i) => (
                <tr key={i}>
                  <td>{i+1}</td>
                  <td style={{ fontFamily: 'Outfit', direction: 'ltr', textAlign: 'left', fontSize: '13px' }}>{r.hash}</td>
                  <td><span style={{ padding: '4px 10px', borderRadius: '10px', background: 'rgba(255,255,255,0.1)' }}>{r.label}</span></td>
                  <td style={{ color: r.malicious > 0 ? 'var(--danger)' : '', fontWeight: 'bold' }}>{r.malicious ?? '-'}</td>
                  <td style={{ color: r.suspicious > 0 ? 'var(--warning)' : '', fontWeight: 'bold' }}>{r.suspicious ?? '-'}</td>
                  <td>{r.harmless ?? '-'}</td>
                  <td style={{ fontSize: '13px', maxWidth: '150px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.file_name ?? '-'}</td>
                  <td>
                    {(r.hash.includes('.') || r.hash.includes(':')) && (
                      <Link to={`/osint?target=${r.hash}`} className="btn-secondary" style={{ padding: '4px 8px', fontSize: '11px', borderRadius: '8px', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                        <Globe size={12} /> OSINT
                      </Link>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function StatCard({ title, value, color }) {
  return (
    <div style={{ background: 'rgba(15,15,20,0.5)', padding: '20px', borderRadius: '20px', textAlign: 'center', borderTop: `3px solid ${color}` }}>
      <div style={{ color: 'var(--text-dim)', fontSize: '15px', fontWeight: 'bold' }}>{title}</div>
      <div style={{ fontSize: '40px', fontWeight: 'bold', fontFamily: 'Outfit', color: value > 0 ? color : '#fff', marginTop: '10px' }}>{value}</div>
    </div>
  );
}
