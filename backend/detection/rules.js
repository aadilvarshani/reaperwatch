'use strict';

// Detection rules, declared as data rather than code: each entry is an EQL
// query string (see dashboard/js/eql.js) plus the alert metadata to emit when
// it matches. Adding a detection means adding one entry here -- no new JS
// function required.
//
// A NOTE ON BACKSLASHES: EQL string literals use \\ for a literal backslash
// (see eql.js). Since these queries are themselves JS string literals in this
// file, a literal backslash that must reach the EQL parser needs FOUR
// backslashes here: JS unescapes \\\\ -> \\ (two chars), which the EQL
// tokenizer then unescapes -> \ (one char). This is verified in
// backend/detection/rules.test.js -- don't hand-edit a backslash-containing
// query without re-running that test.

module.exports = [
  {
    name: 'encoded_powershell',
    title: 'Encoded PowerShell command',
    query: 'process where wildcard(process.name, "*powershell*") and match(process.cmdline, "-e(nc(odedcommand)?)?\\\\b")',
    severity: 'critical',
    mitreId: 'T1059.001',
  },
  {
    name: 'certutil_download',
    title: 'certutil used to fetch a remote file',
    query: 'process where wildcard(process.name, "*certutil*") and wildcard(process.cmdline, "*urlcache*", "*http://*", "*https://*")',
    severity: 'high',
    mitreId: 'T1105',
  },
  {
    name: 'lolbin_rundll32',
    title: 'Living-off-the-land binary executed: rundll32.exe',
    query: 'process where process.name == "rundll32.exe"',
    severity: 'medium',
    mitreId: 'T1218.011',
  },
  {
    name: 'lolbin_regsvr32',
    title: 'Living-off-the-land binary executed: regsvr32.exe',
    query: 'process where process.name == "regsvr32.exe"',
    severity: 'medium',
    mitreId: 'T1218.010',
  },
  {
    name: 'lolbin_mshta',
    title: 'Living-off-the-land binary executed: mshta.exe',
    query: 'process where process.name == "mshta.exe"',
    severity: 'medium',
    mitreId: 'T1218.005',
  },
  {
    name: 'lolbin_script_host',
    title: 'Windows Script Host executed',
    query: 'process where process.name in ("wscript.exe", "cscript.exe")',
    severity: 'medium',
    mitreId: 'T1059.005',
  },
  {
    name: 'lolbin_bitsadmin',
    title: 'Living-off-the-land binary executed: bitsadmin.exe',
    query: 'process where process.name == "bitsadmin.exe"',
    severity: 'medium',
    mitreId: 'T1197',
  },
  {
    name: 'lolbin_installutil',
    title: 'Living-off-the-land binary executed: installutil.exe',
    query: 'process where process.name == "installutil.exe"',
    severity: 'medium',
    mitreId: 'T1218.004',
  },
  {
    name: 'suspicious_parent',
    title: 'Office application spawned a shell or script host',
    query: 'process where parent.name in ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mspub.exe") '
         + 'and process.name in ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe")',
    severity: 'high',
    mitreId: 'T1059',
  },
  {
    name: 'exec_from_userdir',
    title: 'Unsigned binary executed from a user-writable directory',
    query: 'process where process.signed == false and wildcard(process.path, "*\\\\Temp\\\\*", "*\\\\Downloads\\\\*")',
    severity: 'high',
    mitreId: 'T1204',
  },
  {
    name: 'system_shell',
    title: 'Shell running as SYSTEM from an unusual parent',
    query: 'process where user.is_system == true and process.name in ("cmd.exe", "powershell.exe", "pwsh.exe") '
         + 'and not parent.name in ("services.exe", "svchost.exe", "wininit.exe")',
    severity: 'medium',
    mitreId: 'T1548',
  },
];
