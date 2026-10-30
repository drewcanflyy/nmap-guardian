# Nmap Guardian b darija

هاد l fichier kayjm3 l explication dyal l projet b darija, bach tb9a m3ak f l rapport w f l soutenance.

## 1. Chno howa l projet

Nmap Guardian howa dashboard local (Flask) kayf7es ghir `127.0.0.1`, kay9ra les ports li m7loulin, kay3ref chkoun kayasm3 3lihom f Windows, w kay3tik:

1. **Observation**: port, service, version, PID, process.
2. **Classification**: Good / Review / Danger.
3. **Recommandation**: chno tdir, chno ma tdirch, w 3lach.
4. **Evidence**: command, XML, قبل/بعد, rapport printable.

L objectif machi "nkhesser l PC", l objectif howa **tfhem l surface dyalek w t9arrer**.

## 2. Les 3 modes dyal scan

| Mode | Command | Les ports | Chno kayzid |
|---|---|---|---|
| Scan localhost | `nmap -sV --version-light -oX - 127.0.0.1` | top 1000 TCP | inventory سريع |
| Detailed versions | `nmap -sV --version-all -oX - 127.0.0.1` | نفس top 1000 | version أدق (أبطأ) |
| All TCP ports | `nmap -sV --version-light -p- -oX - 127.0.0.1` | 65,535 TCP | kayl9a ports ghayr standard |

Timeouts: 60s / 120s / 240s. Ma kaynch UDP، ma kaynch `-O`، ma kaynch `--script vuln`.

## 3. Les niveaux

- **Good**: l port mtwa9e3 (dashboard, wala m3tamed f baseline).
- **Review**: khass 9arar: chouf، 9ad، wala 7yed.
- **Danger**: أولوية عالية، خدمة khass t9arrer fiha.

mohim: **Good machi "safe"**، w **Danger machi "mخترق"**. hadi أولويات، machi حكم على قابلية الاختراق.

## 4. 3lach SMB (445) Danger

SMB = protocole dyal partage dyal Windows (fichiers, imprimantes, admin shares). Port 445.

l khatar kay3temad 3la:

- **version**: SMBv1 = EternalBlue/MS17-010، wormable.
- **exposition**: Internet > LAN > localhost.
- **partages**: permissions khayba = data leak.
- **authentication**: NTLM bla signing = relay.

l'app kat9ol Danger 7it l service kaykchef data w kaysta3mel f lateral movement، **machi 7it kol SMB sahel ytkhre9**. w l CVE badge **heuristique**: l'app katrbtha b l port, ma katverifich l version wala l patch.

## 5. Baseline w mitigation

- **Baseline**: «had l port mtwa9e3 عندي». Kayweli Good f scan jdid. تصريح، machi 7imaya.
- **Mitigation (declared)**: «l listener ba9i، walakin men برا محجوب». Kayweli Review + Mitigated، machi Good. Kaytsejjel f `data/mitigations.json` w kaydir scan jdida.

l'app **ma kat9derch t9ra l firewall** (`Get-NetFirewallRule` kaykhess admin)، donc khass nta t3lemha.

## 6. Limits dyal l'app

- katf7es ghir `127.0.0.1`.
- ma kat9rach l firewall.
- ma katverifich reachability mn PC akhor.
- ma katjarrbech exploit.
- CVE = heuristique.

## 7. Chno kaydir Nmap w chno l'app katzid

Nmap rasso kaydir bzaf ktar mn "port m7lol wala la": version detection, OS detection, UDP, NSE scripts (smb-os-discovery, vulners, vuln), timing. l'app deliberately katsta3mel subset sghir w آمن.

l'app katzid:

- owner mapping (PID + service) b PowerShell.
- baseline w score.
- règles dyal l 9arar.
- commandes copyable + تحذيرات.
- قبل/بعد + rapport.

## 8. Commandes utiles

```powershell
# verify listener
Get-NetTCPConnection -State Listen -LocalPort 445

# SMBv1
Get-SmbServerConfiguration | Select EnableSMB1Protocol, EnableSMB2Protocol

# partages
Get-SmbShare

# firewall block
New-NetFirewallRule -DisplayName "Nmap Guardian block TCP 445" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block

# verify mn PC akhor
Test-NetConnection -ComputerName <IP> -Port 445
```

## 9. Workflow dyal demo

1. `python -m http.server 8000 --bind 127.0.0.1`
2. Scan localhost.
3. Chouf 8000، l owner، w l 9arar.
4. **Stop server** wala `Ctrl+C`.
5. l app katdir scan jdida، w 8000 kayban f **Newly closed**.
6. Sajjel l قبل/بعد w export rapport.

## 10. Jomla dyal rapport

> Nmap Guardian is a local-only exposure inventory. It scans 127.0.0.1, maps each listener to its Windows process, classifies findings with explainable rules, proposes manual remediation, and verifies changes with a new scan. It does not exploit, patch, or change firewall rules, and its CVE references are heuristic associations that require confirmation.
