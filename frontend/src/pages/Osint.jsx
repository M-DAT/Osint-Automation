import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import axios from 'axios';
import { Search, Save, Key, Plus, Globe } from 'lucide-react';

const SERVICES = ['whoisfreaks','dnsdumpster','ipinfo','urlscan','abuseipdb'];
const TABS = [
  {id:'whois', icon:'🔍', label:'WHOIS & Identity'},
  {id:'dns', icon:'🌐', label:'DNS Records'},
  {id:'pdns', icon:'📡', label:'Passive DNS'},
  {id:'crtsh', icon:'🔗', label:'Subdomains & CT'},
  {id:'typo', icon:'⚠️', label:'Typosquatting'},
  {id:'urlscan', icon:'🖥️', label:'Live Analysis'},
  {id:'abuseipdb', icon:'🛡️', label:'AbuseIPDB'},
];

export default function Osint() {
  const [keys, setKeys] = useState({});
  const [keysStatus, setKeysStatus] = useState({});
  const [showKeys, setShowKeys] = useState(false);
  const [target, setTarget] = useState('');
  const [scanning, setScanning] = useState(false);
  const [report, setReport] = useState(null);
  const [msg, setMsg] = useState('');
  const [tab, setTab] = useState('whois');
  const [scanMode, setScanMode] = useState('osint');
  const [searchParams] = useSearchParams();

  useEffect(() => {
    const urlTarget = searchParams.get('target');
    if (urlTarget) {
      setTarget(urlTarget);
      // We can't trigger scan immediately because keysStatus might not be loaded yet, 
      // but we'll handle it once keysStatus is ready.
    }
  }, [searchParams]);
  useEffect(() => {
    axios.get('/osint/api_keys').then(r => {
      if (r.data.ok) {
        setKeysStatus(r.data.keys_status);
        const has = Object.values(r.data.keys_status).some(v => v > 0);
        if (!has) setShowKeys(true);
        
        // If target was provided in URL, trigger scan
        const urlTarget = searchParams.get('target');
        if (urlTarget && has && !report && !scanning) {
          scanWithTarget(urlTarget);
        }
      }
    });
  }, [searchParams]);

  const scanWithTarget = async (t) => {
    setScanning(true); setReport(null); setMsg('Running comprehensive analysis...');
    try {
      const r = await axios.post('/osint/scan', { target: t });
      if (r.data.ok) { setReport(r.data.data); setMsg('Analysis completed successfully'); setTab('whois'); }
      else setMsg(r.data.message || 'Failed');
    } catch(e) { setMsg('Connection error'); }
    setScanning(false);
  };

  const saveKeys = async () => {
    // Moved to Settings page
  };

  const scan = async () => {
    if (!target) return setMsg('Please enter a target');
    setScanning(true); setReport(null); 
    
    if (scanMode === 'osint') {
        setMsg('Running comprehensive analysis...');
        try {
          const r = await axios.post('/osint/scan', { target });
          if (r.data.ok) { setReport(r.data.data); setMsg('Analysis completed successfully'); setTab('whois'); }
          else setMsg(r.data.message || 'Failed');
        } catch(e) { setMsg('Connection error'); }
    } else {
        setMsg('Checking HaveIBeenPwned (this opens a browser to bypass Cloudflare)...');
        try {
          const r = await axios.post('/osint/hibp', { target, type: scanMode });
          if (r.data.ok) { 
              setReport({ type: 'hibp', target, result: r.data.result }); 
              setMsg('Check completed successfully'); 
          }
          else setMsg(r.data.message || 'Failed');
        } catch(e) { setMsg('Connection error'); }
    }
    setScanning(false);
  };

  return (
    <div>
      {/* Scan Input */}

      {/* Scan Input */}
      <div className="glass-panel">
        <div style={{display:'flex',gap:'15px',flexWrap:'wrap'}}>
          <select value={scanMode} onChange={e=>setScanMode(e.target.value)} style={{flex:0.5,fontSize:'16px',padding:'15px',borderRadius:'12px',background:'rgba(0,0,0,0.3)',color:'#fff',border:'1px solid rgba(255,255,255,0.1)'}}>
            <option value="osint">IP/Domain (OSINT)</option>
            <option value="email">Email (HIBP)</option>
            <option value="password">Password (HIBP)</option>
          </select>
          <input type="text" value={target} onChange={e=>setTarget(e.target.value)}
            onKeyDown={e=>e.key==='Enter'&&scan()}
            placeholder={scanMode==='osint' ? "Enter IP or Domain..." : scanMode==='email' ? "Enter Email Address..." : "Enter Password..."} style={{flex:2,fontSize:'18px',padding:'20px'}}/>
          <button onClick={scan} disabled={scanning} style={{flex:1,fontSize:'18px',padding:'20px'}}>
            <Search size={20}/> {scanning?'Analyzing...':'Start Analysis'}
          </button>
        </div>
      </div>

      {msg && <div style={{textAlign:'center',color:'#fde047',fontWeight:'bold',margin:'20px 0'}}>{msg}</div>}

      {/* HIBP Report */}
      {report && report.type==='hibp' && (
        <div className="glass-panel animate-fade-in" style={{marginTop:'25px', textAlign:'center'}}>
          <h2 style={{color:'var(--primary)',marginBottom:'20px'}}>
            HaveIBeenPwned Result: <span style={{color:'#fff',direction:'ltr',display:'inline-block'}}>{report.target}</span>
          </h2>
          <div style={{fontSize: '20px', padding: '20px', background: 'rgba(0,0,0,0.3)', borderRadius: '12px', color: report.result.includes('[!]') ? 'var(--danger)' : 'var(--success)'}}>
             {report.result}
          </div>
        </div>
      )}

      {/* OSINT Report */}
      {report && report.type==='domain' && (
        <div className="glass-panel animate-fade-in" style={{marginTop:'25px'}}>
          <h2 style={{textAlign:'center',color:'var(--primary)',marginBottom:'20px'}}>
            Comprehensive Intelligence Report: <span style={{color:'#fff',direction:'ltr',display:'inline-block'}}>{report.target}</span>
          </h2>
          {/* Tabs */}
          <div style={{display:'flex',gap:'8px',flexWrap:'wrap',marginBottom:'25px',justifyContent:'center'}}>
            {TABS.map(t=>(
              <button key={t.id} onClick={()=>setTab(t.id)} style={{
                background:tab===t.id?'rgba(99,102,241,0.25)':'rgba(255,255,255,0.05)',
                border:`1px solid ${tab===t.id?'var(--primary)':'rgba(255,255,255,0.08)'}`,
                padding:'10px 18px',borderRadius:'14px',fontSize:'14px',fontWeight:'bold',
                color:tab===t.id?'#a5b4fc':'var(--text-dim)',cursor:'pointer',boxShadow:'none'
              }}>{t.icon} {t.label}</button>
            ))}
          </div>

          {tab==='whois' && <WhoisTab data={report}/>}
          {tab==='dns' && <DnsTab data={report.dns}/>}
          {tab==='pdns' && <PdnsTab data={report.passive_dns}/>}
          {tab==='crtsh' && <CrtshTab data={report.crtsh}/>}
          {tab==='typo' && <TypoTab data={report.typosquatting}/>}
          {tab==='urlscan' && <UrlscanTab data={report.urlscan}/>}
          {tab==='abuseipdb' && <AbuseipdbTab data={report.abuseipdb}/>}
        </div>
      )}

      {report && report.type==='ip' && <IpTab data={report.ipinfo} abuseData={report.abuseipdb} vtData={report.virustotal}/>}
    </div>
  );
}

// ======== TAB COMPONENTS ========

function Card({title, children}) {
  return (
    <div style={{background:'rgba(15,15,20,0.4)',border:'1px solid rgba(255,255,255,0.05)',borderRadius:'16px',padding:'20px',marginBottom:'15px'}}>
      <h4 style={{margin:'0 0 15px',color:'var(--secondary)',fontSize:'17px',borderBottom:'1px solid rgba(255,255,255,0.05)',paddingBottom:'10px'}}>{title}</h4>
      {children}
    </div>
  );
}
function Row({label,value,color}) {
  return (
    <div style={{display:'flex',justifyContent:'space-between',padding:'8px 0',borderBottom:'1px dashed rgba(255,255,255,0.03)'}}>
      <span style={{color:'var(--text-dim)',fontSize:'14px',fontWeight:'bold'}}>{label}</span>
      <span style={{fontFamily:'Outfit',color:color||'#fff',direction:'ltr',maxWidth:'60%',textAlign:'left',wordBreak:'break-all'}}>{value||'-'}</span>
    </div>
  );
}

function WhoisTab({data}) {
  const w = data.whois || {};
  const h = data.whois_historical || {};
  return (
    <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(300px,1fr))',gap:'15px'}}>
      <Card title="📋 Current Registration Data (WHOIS)">
        {w.error ? <div style={{color:'var(--danger)'}}>{w.error}</div> : <>
          <Row label="Registrar" value={w.registrar_name||w.registrar?.registrar_name}/>
          <Row label="Creation Date" value={w.create_date}/>
          <Row label="Update Date" value={w.update_date}/>
          <Row label="Expiry Date" value={w.expiry_date}/>
          <Row label="Domain Status" value={(w.domain_status||[]).join(', ')}/>
          <Row label="Name Servers (NS)" value={(w.name_servers||[]).join(', ')}/>
          <Row label="Owner" value={w.registrant_contact?.name||w.registrant_name||'Protected'}/>
          <Row label="Email" value={w.registrant_contact?.email_address||w.registrant_email||'-'}/>
        </>}
      </Card>
      <Card title="📜 Historical Record (Historical WHOIS)">
        {h.error ? <div style={{color:'var(--danger)'}}>{h.error}</div> :
         h.records?.length ? (
          <div className="table-container"><table><thead><tr><th>Date</th><th>Registrar</th><th>Owner</th><th>Email</th></tr></thead><tbody>
            {h.records.map((r,i)=>(
              <tr key={i}><td>{r.create_date}</td><td style={{fontSize:'12px'}}>{r.registrar}</td><td>{r.registrant_name}</td><td style={{direction:'ltr',fontSize:'12px'}}>{r.registrant_email}</td></tr>
            ))}
          </tbody></table></div>
        ) : <div style={{color:'var(--text-dim)'}}>No historical records found</div>}
      </Card>
    </div>
  );
}

function DnsTab({data}) {
  const [sub, setSub] = useState('a');
  if (!data || data.error) return <Card title="🌐 DNS"><div style={{color:'var(--danger)'}}>{data?.error||'No data'}</div></Card>;
  return (
    <Card title="🌐 DNS Records">
      <div style={{display:'flex',gap:'8px',marginBottom:'15px'}}>
        {['a','mx','txt','ns'].map(t=>(
          <button key={t} onClick={()=>setSub(t)} style={{
            background:sub===t?'rgba(99,102,241,0.2)':'rgba(255,255,255,0.05)',
            border:`1px solid ${sub===t?'var(--primary)':'rgba(255,255,255,0.1)'}`,
            padding:'6px 14px',borderRadius:'10px',color:sub===t?'#a5b4fc':'var(--text-dim)',
            cursor:'pointer',fontWeight:'bold',fontSize:'13px',boxShadow:'none'
          }}>{t.toUpperCase()}</button>
        ))}
      </div>
      <div className="table-container"><table><thead><tr>
        {sub!=='txt'&&<><th>Host</th><th>IP</th><th>Location</th><th>ASN</th></>}
        {sub==='txt'&&<th>Value</th>}
      </tr></thead><tbody>
        {(data[sub]||[]).map((r,i)=>(
          <tr key={i}>
            {sub!=='txt'&&<><td style={{direction:'ltr',textAlign:'left'}}>{r.host||'-'}</td><td>{r.ips?.[0]?.ip||'-'}</td><td>{r.ips?.[0]?.country_name||'-'}</td><td style={{fontSize:'11px'}}>{r.ips?.[0]?.asn_name||'-'}</td></>}
            {sub==='txt'&&<td style={{direction:'ltr',textAlign:'left',fontSize:'12px'}}>{typeof r==='string'?r:JSON.stringify(r)}</td>}
          </tr>
        ))}
      </tbody></table></div>
    </Card>
  );
}

function PdnsTab({data}) {
  if (!data || data.error) return <Card title="📡 Passive DNS"><div style={{color:'var(--danger)'}}>{data?.error||'No data - VirusTotal key required'}</div></Card>;
  const vt = data.vt_analysis || {};
  return (
    <>
      {Object.keys(vt).length > 0 && (
        <Card title="🛡️ VirusTotal Domain Analysis">
          <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(200px,1fr))',gap:'10px'}}>
            <Row label="Reputation" value={vt.reputation} color={vt.reputation<0?'var(--danger)':'var(--success)'}/>
            <Row label="Engines detected as malicious" value={vt.malicious} color={vt.malicious>0?'var(--danger)':'var(--success)'}/>
            <Row label="Engines detected as suspicious" value={vt.suspicious} color={vt.suspicious>0?'var(--warning)':'var(--success)'}/>
            <Row label="Engines detected as harmless" value={vt.harmless}/>
            <Row label="Undetected" value={vt.undetected}/>
            <Row label="Registrar" value={vt.registrar}/>
            <Row label="Categories" value={Object.values(vt.categories||{}).join(', ')||'-'}/>
            <Row label="Tags" value={(vt.tags||[]).join(', ')||'-'}/>
            {vt.total_votes && <Row label="Community Votes" value={`👍 ${vt.total_votes.harmless||0}  👎 ${vt.total_votes.malicious||0}`}/>}
          </div>
        </Card>
      )}
      <Card title={`📡 Passive DNS - ${data.total||0} historical record`}>
        <div className="table-container"><table><thead><tr><th>IP Address</th><th>Date</th><th>Security Status</th></tr></thead><tbody>
          {(data.resolutions||[]).map((r,i)=>(
            <tr key={i}>
              <td style={{direction:'ltr',fontFamily:'Outfit'}}>{r.ip}</td>
              <td>{r.date?new Date(r.date*1000).toLocaleDateString('en-US'):'-'}</td>
              <td>{r.resolver?.malicious>0?<span style={{color:'var(--danger)'}}>⚠️ Malicious ({r.resolver.malicious})</span>:<span style={{color:'var(--success)'}}>✅ Harmless</span>}</td>
            </tr>
          ))}
        </tbody></table></div>
      </Card>
    </>
  );
}

function CrtshTab({data}) {
  const [view, setView] = useState('subs');
  if (!data || data.error) return <Card title="🔗 CT Logs"><div style={{color:'var(--danger)'}}>{data?.error||'No data'}</div></Card>;
  return (
    <Card title={`🔗 Certificate Transparency - ${data.total_subdomains||0} subdomains`}>
      <div style={{display:'flex',gap:'8px',marginBottom:'15px'}}>
        <button onClick={()=>setView('subs')} style={{background:view==='subs'?'rgba(99,102,241,0.2)':'rgba(255,255,255,0.05)',border:`1px solid ${view==='subs'?'var(--primary)':'rgba(255,255,255,0.1)'}`,padding:'6px 14px',borderRadius:'10px',color:view==='subs'?'#a5b4fc':'var(--text-dim)',cursor:'pointer',fontWeight:'bold',fontSize:'13px',boxShadow:'none'}}>Subdomains ({data.total_subdomains})</button>
        <button onClick={()=>setView('certs')} style={{background:view==='certs'?'rgba(99,102,241,0.2)':'rgba(255,255,255,0.05)',border:`1px solid ${view==='certs'?'var(--primary)':'rgba(255,255,255,0.1)'}`,padding:'6px 14px',borderRadius:'10px',color:view==='certs'?'#a5b4fc':'var(--text-dim)',cursor:'pointer',fontWeight:'bold',fontSize:'13px',boxShadow:'none'}}>Certificates ({data.total_certificates})</button>
      </div>
      {view==='subs' && (
        <div style={{display:'flex',flexWrap:'wrap',gap:'8px'}}>
          {(data.subdomains||[]).map((s,i)=>(
            <span key={i} style={{background:'rgba(99,102,241,0.1)',border:'1px solid rgba(99,102,241,0.2)',padding:'6px 14px',borderRadius:'10px',fontSize:'13px',direction:'ltr',color:'#a5b4fc'}}>{s}</span>
          ))}
        </div>
      )}
      {view==='certs' && (
        <div className="table-container"><table><thead><tr><th>Common Name</th><th>Issuer</th><th>From</th><th>To</th></tr></thead><tbody>
          {(data.certificates||[]).map((c,i)=>(
            <tr key={i}><td style={{direction:'ltr',fontSize:'12px'}}>{c.common_name}</td><td style={{fontSize:'11px'}}>{c.issuer?.substring(0,40)}</td><td>{c.not_before?.substring(0,10)}</td><td>{c.not_after?.substring(0,10)}</td></tr>
          ))}
        </tbody></table></div>
      )}
    </Card>
  );
}

function TypoTab({data}) {
  if (!data || data.error) return <Card title="⚠️ Typosquatting"><div style={{color:'var(--danger)'}}>{data?.error||'No data'}</div></Card>;
  return (
    <Card title={`⚠️ Typosquatting Analysis - ${data.total||0} نطاق Suspicious محتمل`}>
      <div className="table-container"><table><thead><tr><th>Domain الSuspicious</th><th>Technique</th><th>Type</th></tr></thead><tbody>
        {(data.variants||[]).map((v,i)=>(
          <tr key={i}><td style={{direction:'ltr',textAlign:'left',color:'var(--warning)',fontWeight:'bold'}}>{v.domain}</td><td style={{fontSize:'12px'}}>{v.technique}</td><td>{v.type}</td></tr>
        ))}
      </tbody></table></div>
    </Card>
  );
}

function UrlscanTab({data}) {
  if (!data || data.error) return <Card title="🖥️ URLScan"><div style={{color:'var(--danger)'}}>{data?.error||'No data'}</div></Card>;
  return (
    <Card title={`🖥️ Live Content Analysis - ${data.total||0} previous scans`}>
      {(data.scans||[]).map((s,i)=>(
        <div key={i} style={{background:'rgba(10,10,15,0.4)',borderRadius:'14px',padding:'15px',marginBottom:'12px',border:'1px solid rgba(255,255,255,0.05)'}}>
          <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(200px,1fr))',gap:'8px'}}>
            <Row label="URL" value={s.url}/>
            <Row label="Page Title" value={s.title}/>
            <Row label="IP" value={s.ip}/>
            <Row label="Country" value={s.country}/>
            <Row label="Server" value={s.server}/>
            <Row label="ASN" value={s.asnname}/>
            <Row label="Status" value={s.status}/>
            <Row label="Malicious؟" value={s.malicious?'Yes ⚠️':'No ✅'} color={s.malicious?'var(--danger)':'var(--success)'}/>
            <Row label="Date" value={s.time?.substring(0,10)}/>
            {s.report_url && <Row label="Report" value={<a href={s.report_url} target="_blank" rel="noreferrer" style={{color:'var(--info)'}}>Open ↗</a>}/>}
          </div>
          {s.screenshot && <img src={s.screenshot} alt="screenshot" style={{width:'100%',borderRadius:'12px',marginTop:'10px',border:'1px solid rgba(255,255,255,0.1)'}}/>}
        </div>
      ))}
      {(!data.scans||data.scans.length===0) && <div style={{color:'var(--text-dim)',textAlign:'center'}}>No توجد فحوصات سابقة لهذا Domain</div>}
    </Card>
  );
}

function IpTab({data, abuseData, vtData}) {
  if (!data) return null;
  return (
    <div className="glass-panel animate-fade-in" style={{marginTop:'25px'}}>
      <h2 style={{textAlign:'center',color:'var(--primary)',marginBottom:'20px'}}>Comprehensive IP Report</h2>
      <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(280px,1fr))',gap:'15px'}}>
        <Card title="🌍 Geolocation (IPInfo)">
          <Row label="Country" value={data.country}/><Row label="City" value={data.city}/>
          <Row label="الFromطقة" value={data.region}/><Row label="Coordinates" value={data.loc}/>
        </Card>
        <Card title="🏢 Service Provider">
          <Row label="Provider" value={data.org}/><Row label="Hostname" value={data.hostname}/>
        </Card>
        <Card title="🛡️ Security & Privacy">
          <Row label="VPN" value={data.privacy?.vpn?'Yes':'No'} color={data.privacy?.vpn?'var(--danger)':'var(--success)'}/>
          <Row label="Proxy" value={data.privacy?.proxy?'Yes':'No'} color={data.privacy?.proxy?'var(--danger)':'var(--success)'}/>
          <Row label="Tor" value={data.privacy?.tor?'Yes':'No'} color={data.privacy?.tor?'var(--danger)':'var(--success)'}/>
          <Row label="Relay" value={data.privacy?.relay?'Yes':'No'} color={data.privacy?.relay?'var(--danger)':'var(--success)'}/>
        </Card>
        {vtData && !vtData.error && (
          <Card title="🛡️ VirusTotal Analysis">
            <Row label="Reputation" value={vtData.reputation} color={vtData.reputation < 0 ? 'var(--danger)' : 'var(--success)'}/>
            <Row label="Engines detected as malicious" value={vtData.malicious} color={vtData.malicious > 0 ? 'var(--danger)' : 'var(--success)'}/>
            <Row label="Engines detected as suspicious" value={vtData.suspicious} color={vtData.suspicious > 0 ? 'var(--warning)' : 'var(--success)'}/>
            <Row label="Owner (ASN)" value={vtData.as_owner}/>
            <Row label="Tags" value={(vtData.tags||[]).join(', ')||'-'}/>
          </Card>
        )}
      </div>
      
      {vtData && vtData.whois && vtData.whois !== '-' && (
        <Card title="📜 سجل WHOIS (From VirusTotal)">
          <pre style={{direction:'ltr',textAlign:'left',fontSize:'12px',background:'rgba(0,0,0,0.2)',padding:'15px',borderRadius:'12px',overflowX:'auto',color:'var(--text-dim)'}}>
            {vtData.whois}
          </pre>
        </Card>
      )}

      {abuseData && <AbuseipdbTab data={abuseData}/>}
    </div>
  );
}

// ======== AbuseIPDB Tab ========
const ABUSE_CATEGORIES = {
  1:'DNS Compromise',2:'DNS Poisoning',3:'Fraud Orders',4:'DDoS Attack',
  5:'FTP Brute-Force',6:'Ping of Death',7:'Phishing',8:'Fraud VoIP',
  9:'Open Proxy',10:'Web Spam',11:'Email Spam',12:'Blog Spam',
  13:'VPN IP',14:'Port Scan',15:'Hacking',16:'SQL Injection',
  17:'Spoofing',18:'Brute-Force',19:'Bad Web Bot',20:'Exploited Host',
  21:'Web App Attack',22:'SSH',23:'IoT Targeted'
};

function AbuseipdbTab({data}) {
  if (!data) return null;
  if (data.error) return <Card title="🛡️ AbuseIPDB"><div style={{color:'var(--danger)'}}>{data.error}</div></Card>;

  const score = data.abuseConfidenceScore || 0;
  const scoreColor = score >= 75 ? 'var(--danger)' : score >= 25 ? 'var(--warning)' : 'var(--success)';
  const scoreLabel = score >= 75 ? 'Very Malicious' : score >= 25 ? 'Suspicious' : 'Harmless';

  return (
    <div style={{marginTop:'15px'}}>
      {/* Score Hero */}
      <Card title={`🛡️ AbuseIPDB - Reputation report for ${data.resolved_ip || data.ipAddress || ''}`}>
        <div style={{display:'flex',alignItems:'center',gap:'30px',flexWrap:'wrap',justifyContent:'center',marginBottom:'20px'}}>
          <div style={{position:'relative',width:'120px',height:'120px'}}>
            <svg viewBox="0 0 120 120" style={{width:'120px',height:'120px',transform:'rotate(-90deg)'}}>
              <circle cx="60" cy="60" r="52" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="12"/>
              <circle cx="60" cy="60" r="52" fill="none" stroke={scoreColor} strokeWidth="12"
                strokeDasharray={`${score * 3.27} ${327 - score * 3.27}`}
                strokeLinecap="round"
                style={{transition:'stroke-dasharray 1s ease'}}/>
            </svg>
            <div style={{position:'absolute',inset:0,display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center'}}>
              <span style={{fontSize:'28px',fontWeight:'800',color:scoreColor,fontFamily:'Outfit'}}>{score}%</span>
              <span style={{fontSize:'11px',color:'var(--text-dim)'}}>Confidence</span>
            </div>
          </div>
          <div>
            <div style={{fontSize:'24px',fontWeight:'800',color:scoreColor,marginBottom:'5px'}}>{scoreLabel}</div>
            <div style={{color:'var(--text-dim)',fontSize:'14px'}}>Risk Score: {score}%</div>
            {data.queried_domain && <div style={{color:'var(--text-dim)',fontSize:'13px',marginTop:'4px'}}>Domain: <span style={{color:'#a5b4fc',direction:'ltr',display:'inline-block'}}>{data.queried_domain}</span> → <span style={{color:'#fff',direction:'ltr',display:'inline-block'}}>{data.resolved_ip}</span></div>}
          </div>
        </div>

        <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(200px,1fr))',gap:'10px'}}>
          <Row label="IP Address" value={data.ipAddress} />
          <Row label="Country" value={`${data.countryName || ''} (${data.countryCode || ''})`} />
          <Row label="ISP" value={data.isp} />
          <Row label="Usage Type" value={data.usageType} />
          <Row label="Domain" value={data.domain} />
          <Row label="Report Count" value={data.totalReports} color={data.totalReports>0?'var(--danger)':'var(--success)'} />
          <Row label="Distinct Users" value={data.numDistinctUsers} />
          <Row label="Last Report" value={data.lastReportedAt !== '-' ? new Date(data.lastReportedAt).toLocaleDateString('en-US') : 'None'} />
          <Row label="Tor Node" value={data.isTor ? 'Yes ⚠️' : 'No'} color={data.isTor?'var(--danger)':'var(--success)'} />
          <Row label="Whitelisted" value={data.isWhitelisted ? 'Yes ✅' : 'No'} color={data.isWhitelisted?'var(--success)':'var(--text-dim)'} />
        </div>
      </Card>

      {/* Reports Table */}
      {data.reports && data.reports.length > 0 && (
        <Card title={`📋 Last ${data.reports.length} Reports`}>
          <div className="table-container"><table><thead><tr>
            <th>Date</th><th>Categories</th><th>Country</th><th>Comment</th>
          </tr></thead><tbody>
            {data.reports.map((rpt, i) => (
              <tr key={i}>
                <td style={{whiteSpace:'nowrap'}}>{rpt.reportedAt ? new Date(rpt.reportedAt).toLocaleDateString('en-US') : '-'}</td>
                <td>
                  <div style={{display:'flex',gap:'4px',flexWrap:'wrap'}}>
                    {(rpt.categories||[]).map((catId, j) => (
                      <span key={j} style={{background:'rgba(239,68,68,0.15)',color:'#fca5a5',padding:'2px 8px',borderRadius:'8px',fontSize:'11px',whiteSpace:'nowrap'}}>
                        {ABUSE_CATEGORIES[catId] || `Cat ${catId}`}
                      </span>
                    ))}
                  </div>
                </td>
                <td>{rpt.reporterCountryCode}</td>
                <td style={{fontSize:'12px',maxWidth:'300px',overflow:'hidden',textOverflow:'ellipsis',direction:'ltr',textAlign:'left'}}>{rpt.comment || '-'}</td>
              </tr>
            ))}
          </tbody></table></div>
        </Card>
      )}
    </div>
  );
}
