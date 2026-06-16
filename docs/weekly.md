# IT Weekly Intelligence Briefing
**Period:** June 09 – June 16, 2026  
**Generated:** 2026-06-16 09:24 UTC  
**Items reviewed:** 136  

## ⚡ Top Actions This Week

1. **Verify no credential overlap; confirm DLP and SIEM alerting is active.**  
   _iRhythm discloses data breach, says hackers stole patient info_  
   Source: BleepingComputer  

2. **Apply emergency patch or mitigation now; check vendor advisory for workarounds.**  
   _Cisco Releases Security Updates for Actively Exploited SD-WAN Manager Flaw_  
   Source: The Hacker News  

3. **Verify no credential overlap; confirm DLP and SIEM alerting is active.**  
   _Council of Europe investigates ShinyHunters data breach claims_  
   Source: BleepingComputer  

---

## 🔴 Critical — Immediate Awareness

### [iRhythm discloses data breach, says hackers stole patient info](https://www.bleepingcomputer.com/news/security/irhythm-discloses-data-breach-says-hackers-stole-patient-info/)
**Source:** BleepingComputer &nbsp;·&nbsp; **Date:** Jun 16  
**Why it matters:** Potential credential or data exposure.  
**Recommended action:** Verify no credential overlap; confirm DLP and SIEM alerting is active.  

### [Cisco Releases Security Updates for Actively Exploited SD-WAN Manager Flaw](https://thehackernews.com/2026/06/cisco-releases-security-updates-for.html)
**Source:** The Hacker News &nbsp;·&nbsp; **Date:** Jun 16  
**Why it matters:** General awareness item.  
**Recommended action:** Apply emergency patch or mitigation now; check vendor advisory for workarounds.  

### [Council of Europe investigates ShinyHunters data breach claims](https://www.bleepingcomputer.com/news/security/council-of-europe-investigates-shinyhunters-data-breach-claims/)
**Source:** BleepingComputer &nbsp;·&nbsp; **Date:** Jun 15  
**Why it matters:** Potential credential or data exposure.  
**Recommended action:** Verify no credential overlap; confirm DLP and SIEM alerting is active.  

### [Chinese hackers breach REDCap servers, steal medical research](https://www.bleepingcomputer.com/news/security/chinese-hackers-breach-redcap-servers-steal-medical-research/)
**Source:** BleepingComputer &nbsp;·&nbsp; **Date:** Jun 15  
**Why it matters:** Potential credential or data exposure.  
**Recommended action:** Verify no credential overlap; confirm DLP and SIEM alerting is active.  

### [Infinite Campus data breach affects 137,000 school staff accounts](https://www.bleepingcomputer.com/news/security/infinite-campus-data-breach-affects-137-000-school-staff-accounts/)
**Source:** BleepingComputer &nbsp;·&nbsp; **Date:** Jun 15  
**Why it matters:** Potential credential or data exposure.  
**Recommended action:** Verify no credential overlap; confirm DLP and SIEM alerting is active.  

### [Europol Disrupts AudiA6 Crypto Laundering Service Used by Ransomware Gangs](https://thehackernews.com/2026/06/europol-disrupts-audia6-crypto.html)
**Source:** The Hacker News &nbsp;·&nbsp; **Date:** Jun 12  
**Why it matters:** Elevated ransomware risk across the sector.  
**Recommended action:** Validate backups, confirm EDR coverage, and brief incident response team.  

---

## 🟠 Important — Review This Week

- [CVE-2026-34182 CMS AuthEnvelopedData Processing May Accept Forged Messages](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-34182)  
  **Microsoft Security Response Center (MSRC)** · Jun 16 · _General awareness item._  

- [CVE-2026-54411 Linux-PAM through 1.7.2 contains an observable timing discrepancy (CWE-208) in the pam_userdb module's plaintext-password comparison path in modules/pam_userdb/pam_userdb.c that allows a local or network-adjacent attacker able to repeatedly drive authentication through a calling service to recover the plaintext password of a target account by measuring response-timing differences. The comparison uses strncmp() (or strncasecmp() when PAM_ICASE_ARG is set) preceded by a length-equality check, so the time to reject a candidate depends on the index of the first differing byte and on whether the candidate's length matches the stored password, leaking the password length and individual prefix bytes. The vulnerable path is reached when the administrator configures pam_userdb with crypt=none, with an unrecognized crypt method, or without a crypt= argument, causing the module to store and compare credentials in plaintext.](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-54411)  
  **Microsoft Security Response Center (MSRC)** · Jun 16 · _General awareness item._  

- [CISA Flags LiteSpeed cPanel Plugin Flaw Exploited for Root Privilege Escalation](https://thehackernews.com/2026/06/cisa-flags-litespeed-cpanel-plugin-flaw.html)  
  **The Hacker News** · Jun 16 · _General awareness item._  

- [Chromium: CVE-2026-11690 Out of bounds read and write in Media](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11691)  
  **Microsoft Security Response Center (MSRC)** · Jun 16 · _General awareness item._  

- [Chromium: CVE-2026-11689 Insufficient validation of untrusted input in Passwords](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11690)  
  **Microsoft Security Response Center (MSRC)** · Jun 16 · _General awareness item._  

- [Chromium: CVE-2026-11688 Object lifecycle issue in SVG](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11689)  
  **Microsoft Security Response Center (MSRC)** · Jun 16 · _General awareness item._  

- [Chromium: CVE-2026-11687 Use after free in Dawn](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11688)  
  **Microsoft Security Response Center (MSRC)** · Jun 16 · _General awareness item._  

- [Chromium: CVE-2026-11686 Insufficient validation of untrusted input in Dawn](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-11687)  
  **Microsoft Security Response Center (MSRC)** · Jun 16 · _General awareness item._  

---

## 🔵 FYI — General Awareness

- [Critical Fortinet FortiSandbox flaws now exploited in attacks](https://www.bleepingcomputer.com/news/security/critical-fortinet-fortisandbox-flaws-now-exploited-in-attacks/) — BleepingComputer
- [Windows version of SprySOCKS Linux malware used to attack govt orgs](https://www.bleepingcomputer.com/news/security/windows-version-of-sprysocks-linux-malware-used-to-attack-govt-orgs/) — BleepingComputer
- [Fake Microsoft Alerts Used to Deploy North Korean NarwhalRAT Malware](https://thehackernews.com/2026/06/fake-microsoft-alerts-used-to-deploy.html) — The Hacker News
- [From a VHDX File to a Remcos RAT, (Tue, Jun 16th)](https://isc.sans.edu/diary/rss/33080) — SANS Internet Storm Center
- [ISC Stormcast For Tuesday, June 16th, 2026 https://isc.sans.edu/podcastdetail/9974, (Tue, Jun 16th)](https://isc.sans.edu/diary/rss/33078) — SANS Internet Storm Center
- [DOJ seizes CFAKE, SOCFAKE deepfake nude sites under TAKE IT DOWN Act](https://www.bleepingcomputer.com/news/security/doj-seizes-cfake-socfake-deepfake-nude-sites-under-take-it-down-act/) — BleepingComputer

---

_Auto-generated by [it-daily-rss](https://jaf1248.github.io/it-daily-rss/) · 13 critical · 84 important · 39 FYI_