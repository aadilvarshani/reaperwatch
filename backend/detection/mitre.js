'use strict';

// MITRE ATT&CK technique metadata used by the detection rules and the API
// (e.g. to group alerts into the dashboard's "Alert Breakdown" categories).

const TECHNIQUES = {
  'T1059':     { name: 'Command and Scripting Interpreter', tactic: 'Execution' },
  'T1059.001': { name: 'PowerShell',                        tactic: 'Execution' },
  'T1059.005': { name: 'Visual Basic',                      tactic: 'Execution' },
  'T1105':     { name: 'Ingress Tool Transfer',              tactic: 'Command and Control' },
  'T1197':     { name: 'BITS Jobs',                          tactic: 'Defense Evasion' },
  'T1204':     { name: 'User Execution',                     tactic: 'Execution' },
  'T1218':     { name: 'System Binary Proxy Execution',      tactic: 'Defense Evasion' },
  'T1218.004': { name: 'InstallUtil',                        tactic: 'Defense Evasion' },
  'T1218.005': { name: 'Mshta',                              tactic: 'Defense Evasion' },
  'T1218.010': { name: 'Regsvr32',                           tactic: 'Defense Evasion' },
  'T1218.011': { name: 'Rundll32',                           tactic: 'Defense Evasion' },
  'T1548':     { name: 'Abuse Elevation Control Mechanism',  tactic: 'Privilege Escalation' },
};

const techniqueName   = id => TECHNIQUES[id]?.name ?? id;
const techniqueTactic = id => TECHNIQUES[id]?.tactic ?? 'Uncategorized';

module.exports = { TECHNIQUES, techniqueName, techniqueTactic };
