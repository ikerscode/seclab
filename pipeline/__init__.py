"""Cross-lab pipeline: joins the five labs into one small SOC.

honeypot-net and malware-lab findings are enriched by threat-intel and sent to
ai-ids as external alerts, ics-sim alarms go to ai-ids as OT alerts, and the
ai-ids incidents are read back as the end of the chain.

Standard library only. Every call goes to 127.0.0.1 with a timeout.
"""

SOURCES = ("honeypot-net", "malware-lab", "ics-sim", "threat-intel")
