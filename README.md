# seclab

A set of small, local security labs that I use to practise and demonstrate defensive
security work. Each lab is its own project with its own server and web dashboard. A
portal on port 8100 starts them, stops them and shows whether each one is up.

Everything listens on 127.0.0.1 only. Nothing here is meant to be exposed to a network.

## Projects

| Project       | Port | What it is                                                                                  |
|---------------|------|---------------------------------------------------------------------------------------------|
| portal        | 8100 | Status page and launcher for the other projects                                             |
| malware-lab   | 8101 | Isolated sandbox for static and dynamic malware analysis, IOC extraction and reports         |
| threat-intel  | 8102 | Public threat intelligence, correlated by infrastructure, ransomware groups and techniques  |
| honeypot-net  | 8103 | Low-interaction honeypot sensors (SSH and Telnet on 2222 and 2323, HTTP on 8180) and analysis |
| ics-sim       | 8104 | Water treatment plant simulator with a PLC, a safety system, Modbus and attack scenarios    |
| ai-ids        | 8105 | Anomaly and ML intrusion detection with explanations and cross-system correlation           |

Each project has a `run.sh` that starts its server, a `GET /api/health` endpoint that the
portal polls, and a dashboard at its own port.

## Layout

```
seclab/
  portal/          launcher, status server and page (this project's code lives here)
    seclab         command line script for starting and stopping projects
    server.py      stdlib HTTP server on 127.0.0.1:8100
    static/        index.html plus the shared hud.css and hud.js
  _shared/         HUD files that are copied into each project's static/ folder
  malware-lab/     each sibling project is its own git repository
  threat-intel/
  honeypot-net/
  ics-sim/
  ai-ids/
  .run/            pid and log files written by seclab (not committed)
  seclab           symlink to portal/seclab
```

## Using the seclab script

Run it from the seclab folder, or through the symlink from anywhere.

```
./seclab start all          start every project in the background
./seclab start ics-sim      start one project
./seclab stop all           stop every project (TERM, then KILL after 5 seconds)
./seclab status             show port, pid, running state and health of each project
./seclab logs honeypot-net  follow one project's log
./seclab portal             run the portal in the foreground on 127.0.0.1:8100
./seclab tui [--once]       terminal view of every project (start with s, stop with x, q to quit)
```

`start` runs the project's `run.sh` in its own process group, so `stop` can end the whole
process tree. Logs go to `.run/<name>.log` and the pid goes to `.run/<name>.pid`. A
project that is already running is skipped rather than started twice.

## Using the portal

Start the portal with `./seclab portal` and open http://127.0.0.1:8100/ in a browser.
Each project has a card that shows whether it is up, its version and its port. The
Open button goes to the project's dashboard in a new tab, and it is only active while
the project answers its health check. Start and Stop call the same script as the
command line. The page refreshes every five seconds.

The portal only accepts requests addressed to 127.0.0.1 or localhost, and it only
starts or stops the five known project names.

## Notes

- The portal checks health on the server side, so the browser never talks to the
  project ports directly.
- Each sibling project is a separate git repository and is built and documented on its
  own. This folder only holds the launcher, the portal and the shared front-end files.
- Nothing is containerised by the portal itself. Any Docker use is inside the projects.

## Layout

The portal expects the projects as siblings in one folder:

```
seclab/
  portal/          this repo
  malware-lab/  threat-intel/  honeypot-net/  ics-sim/  ai-ids/
  seclab -> portal/seclab
```

Clone each repo into the same folder and run `ln -s portal/seclab seclab` once.
