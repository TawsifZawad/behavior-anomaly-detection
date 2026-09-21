import os
import csv
import json
import base64
from datetime import datetime

from config.settings import REPORTS_DIR, ALERTS_CSV
from core.history import load_history, feature_series

# Chip label -> the model feature key, so a clicked chip can look up that
# user's recent history for the right feature.
LABEL_TO_FEATURE = {
    "login time": "login_hour",
    "logout time": "logout_hour",
    "session length": "session_span",
    "off-hours activity": "off_hours_ratio",
    "weekend activity": "weekend_activity",
    "activity rate": "event_rate",
    "active-hours spread": "active_hours",
    "process volume": "process_start",
    "file activity": "file_access",
    "program variety": "distinct_processes",
    "file/process ratio": "file_to_process_ratio",
    "failed logins": "failed_login",
    "login attempts": "login_attempts",
    "off-hours logins": "off_hours_logon",
    "file-type variety": "distinct_file_types",
    "usb device use": "usb_events",
    "removable-media activity": "removable_file_events",
    "network sources": "distinct_ips",
}


# For each behaviour, a plain everyday explanation of what it measures
# and why an attacker tends to push it out of the normal range. Shown in
# the pop-up when an analyst clicks a deviating-behaviour chip.
BEHAVIOR_MEANINGS = {
    "login time": "What time of day this person signed in.",
    "logout time": "What time of day this person signed off.",
    "session length": "How long they stayed logged in — from first to "
                      "last action.",
    "off-hours activity": "How much of their work happened outside normal "
                          "office hours (early morning or evening).",
    "weekend activity": "How much they did on Saturday or Sunday.",
    "activity rate": "How fast things were happening — how busy the "
                     "session was per hour.",
    "active-hours spread": "How many different hours of the day they were "
                           "active.",
    "process volume": "How many programs were opened during the session.",
    "file activity": "How many files were opened or touched.",
    "program variety": "How many different kinds of programs were run — "
                       "the mix, not just the number.",
    "file/process ratio": "Their working style — whether they mostly "
                          "touch files or mostly run programs.",
    "failed logins": "How many times a login was rejected (wrong "
                     "password, etc.).",
    "login attempts": "How many times they tried to log in in total.",
    "off-hours logins": "How many times they actually signed in outside "
                        "normal office hours (early morning or evening).",
    "file-type variety": "How many different kinds of files (by extension "
                         "— documents, spreadsheets, scripts) they opened.",
    "usb device use": "How much they plugged in or removed USB drives.",
    "removable-media activity": "How many files or programs came from a "
                                "USB or other removable drive.",
    "network sources": "How many different network locations (IP "
                       "addresses) they connected from.",
}

# Why a change in this behaviour can point to an attack — everyday words.
BEHAVIOR_ATTACK = {
    "login time": "Intruders and stolen accounts often act in the dead of "
                  "night to avoid being seen. Signing in far from someone's "
                  "usual time is a classic warning sign.",
    "logout time": "Finishing at a very odd hour can mean someone else is "
                   "using the account while the real owner is away.",
    "session length": "A session that is far too long or oddly short can "
                      "mean an automated tool is running, or someone left a "
                      "door open.",
    "off-hours activity": "Attackers prefer the quiet hours when nobody is "
                          "watching, so a jump in evening or early-morning "
                          "work is suspicious.",
    "weekend activity": "Most staff rest on weekends; an intruder does not. "
                        "Weekend spikes are worth a second look.",
    "activity rate": "People work at a human pace. A sudden burst of "
                     "activity usually means a script or malware doing many "
                     "things at machine speed.",
    "active-hours spread": "Normal work is spread across the day; a tight "
                           "burst in a couple of hours can be an automated "
                           "attack, not a person.",
    "process volume": "Malware and hacking tools launch lots of programs "
                      "quickly. A sudden flood of programs often means "
                      "something is running that the user never started.",
    "file activity": "Ransomware and data theft touch huge numbers of "
                     "files fast. A big jump can mean files are being "
                     "encrypted or stolen.",
    "program variety": "Attackers run many different tools (scanners, "
                       "password crackers, downloaders). An unusual mix of "
                       "programs can reveal a toolkit at work.",
    "file/process ratio": "A big shift in working style — say, suddenly "
                          "opening far more files than usual — can mean "
                          "data is being collected for theft.",
    "failed logins": "Lots of failed logins is the fingerprint of "
                     "password guessing (brute force) — the classic way in "
                     "from outside (R2L).",
    "login attempts": "A spike in login tries, successful or not, often "
                      "means someone is hammering the account to get in.",
    "off-hours logins": "Signing in for real at 2 a.m. is a classic sign of "
                        "a stolen account or an insider working when nobody "
                        "is watching (R2L / privilege abuse).",
    "file-type variety": "Suddenly touching many unusual file types can "
                         "mean someone is hunting for documents to steal, or "
                         "a tool is sweeping the disk.",
    "usb device use": "USB sticks are a favourite way to carry malware in "
                      "or data out, especially where the network is watched.",
    "removable-media activity": "Running a program or copying files from a "
                                "USB drive is a common way to smuggle malware "
                                "in or carry stolen data out.",
    "network sources": "Connecting from several different addresses at once "
                       "can mean an account is being used from places the "
                       "real owner never goes.",
}


class DashboardBuilder:
    """
    Assemble a single self-contained HTML dashboard from the artifacts
    other components already produce:

        reports/metrics.json         (ReportGenerator)
        reports/confusion_matrix.png (ReportGenerator)
        reports/roc_curve.png        (ReportGenerator)
        alerts/alerts.csv            (AlertManager)

    Images are embedded as base64 so the file opens offline and can be
    dropped straight into the thesis. Output: reports/dashboard.html.
    """

    STATUS_COLORS = {
        "CRITICAL": "#c0392b",
        "SUSPICIOUS": "#e67e22",
        "REVIEW": "#f1c40f",
        "SAFE": "#27ae60",
        "NORMAL": "#27ae60",
    }

    def __init__(self, reports_dir=REPORTS_DIR, alerts_csv=ALERTS_CSV):
        self.reports_dir = reports_dir
        self.alerts_csv = alerts_csv

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def _load_metrics(self):
        path = os.path.join(self.reports_dir, "metrics.json")
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def _load_summary(self):
        path = os.path.join(self.reports_dir, "summary.json")
        if not os.path.exists(path):
            return None
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def _load_sessions(self):
        path = os.path.join(self.reports_dir, "sessions.json")
        if not os.path.exists(path):
            return []
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def _load_alerts(self, limit=50):
        if not os.path.exists(self.alerts_csv):
            return []
        with open(self.alerts_csv, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        rows.reverse()  # newest first
        return rows[:limit]

    def _embed_image(self, filename):
        path = os.path.join(self.reports_dir, filename)
        if not os.path.exists(path):
            return None
        with open(path, "rb") as f:
            data = base64.b64encode(f.read()).decode("ascii")
        return f"data:image/png;base64,{data}"

    # ------------------------------------------------------------------
    # HTML fragments
    # ------------------------------------------------------------------

    def _metric_cards(self, metrics):
        if not metrics:
            return "<p class='muted'>No evaluation metrics yet. " \
                   "Run the pipeline to generate them.</p>"

        cards = [
            ("Accuracy", metrics.get("accuracy"),
             "This is how often the model gets the answer right overall. "
             "It counts every session it judged correctly — an attack "
             "called an attack, a normal session called normal. A score "
             "of 0.99 means it was right about 99 times out of 100."),
            ("Precision", metrics.get("precision"),
             "When the model does raise an alarm, this tells you how often "
             "that alarm is real. High precision means it rarely cries "
             "wolf, so the alerts an analyst sees can be trusted."),
            ("Recall", metrics.get("recall"),
             "Out of all the real attacks that happened, this is how many "
             "the model actually caught. High recall means very few "
             "attacks slip through without being noticed."),
            ("F1 Score", metrics.get("f1"),
             "A single balanced score that blends precision and recall. "
             "It only stays high when both are high, so it is a fair "
             "way to sum up the model in one number — few false alarms "
             "and few missed attacks together."),
        ]
        if "roc_auc" in metrics:
            cards.append((
                "ROC AUC", metrics["roc_auc"],
                "This measures how cleanly the model can tell attacks "
                "apart from normal activity, whatever cut-off you choose. "
                "A score of 1.0 is a perfect split, while 0.5 would be no "
                "better than flipping a coin."))

        support = metrics.get("support", {})

        html = ["<div class='cards'>"]
        for label, value, help_text in cards:
            shown = "-" if value is None else f"{value:.4f}"
            html.append(
                f"<div class='card'><div class='card-value'>{shown}</div>"
                f"<div class='card-label'>{label}</div>"
                f"<div class='card-help'>{help_text}</div></div>"
            )
        html.append(
            f"<div class='card'><div class='card-value'>"
            f"{support.get('total', 0)}</div>"
            f"<div class='card-label'>Samples "
            f"({support.get('normal', 0)}N / "
            f"{support.get('anomaly', 0)}A)</div>"
            f"<div class='card-help'>This is how many sessions were used "
            f"to measure the scores above: {support.get('normal', 0)} "
            f"genuinely normal ones (marked N) and "
            f"{support.get('anomaly', 0)} known attacks (marked A).</div>"
            f"</div>"
        )
        html.append("</div>")
        return "".join(html)

    def _cert_panel(self):
        """Real-scale evaluation on the CERT r4.2 insider-threat benchmark
        (reports/cert/metrics.json), shown with the metrics that are fair
        for rare positives - real session/user counts, ROC-AUC and
        per-insider detection at an analyst budget - not the misleading
        precision/F1 that a 1.5%-positive imbalance produces."""
        path = os.path.join(self.reports_dir, "cert", "metrics.json")
        if not os.path.exists(path):
            return ""
        try:
            with open(path, encoding="utf-8") as f:
                m = json.load(f)
        except Exception:
            return ""

        sup = m.get("support", {})
        budget = m.get("detection_at_budget", {})
        total = sup.get("total", m.get("sessions_total", 0))
        normal = sup.get("normal", 0)
        mal = sup.get("anomaly", m.get("malicious_sessions", 0))
        users = m.get("users", 0)
        insiders = m.get("insiders", 0)
        roc = m.get("roc_auc")
        d10 = budget.get("top_10pct_insiders")
        d20 = budget.get("top_20pct_insiders")

        def pct(x):
            return "-" if x is None else f"{x * 100:.1f}%"

        cards = [
            (f"{total:,}", "Real sessions tested",
             f"Real user-days from the CERT r4.2 benchmark used to test the "
             f"model: {normal:,} genuinely normal and {mal} real "
             f"insider-threat days."),
            (f"{users:,}", "Real users",
             "The model was tested across a thousand real, distinct users - "
             "not synthetic profiles - so the score reflects genuine "
             "behavioural variety at scale."),
            ("-" if roc is None else f"{roc:.2f}", "ROC AUC",
             "How cleanly the model ranks insider days above normal ones, "
             "whatever cut-off you pick. This is the fair headline when "
             "attacks are rare; 1.0 is perfect, 0.5 is a coin toss."),
            (pct(d10), "Insiders caught, top 10%",
             f"If an analyst reviews only the 10% most anomalous days, this "
             f"share of the {insiders} hidden insiders is caught - catching "
             f"any one of an insider's days flags the insider."),
            (pct(d20), "Insiders caught, top 20%",
             f"Reviewing the top 20% most anomalous days catches this share "
             f"of the {insiders} insiders."),
        ]
        html = ["<div class='cards'>"]
        for value, label, help_text in cards:
            html.append(
                f"<div class='card'><div class='card-value'>{value}</div>"
                f"<div class='card-label'>{label}</div>"
                f"<div class='card-help'>{help_text}</div></div>"
            )
        html.append("</div>")
        return "".join(html)

    def _cert_block(self):
        """Heading + real-scale CERT panel, or nothing when the CERT
        evaluation has not been run."""
        panel = self._cert_panel()
        if not panel:
            return ""
        return (
            "<h2>Real-Scale Evaluation "
            "<span class=\"tag\">CERT r4.2 &middot; real users</span></h2>"
            "<p class=\"lead\">The same behavioural model, tested on the "
            "CERT r4.2 insider-threat benchmark &mdash; a thousand real "
            "users and hundreds of thousands of real sessions &mdash; rather "
            "than the smaller curated set above. With genuine insiders only "
            "1.5&#37; of the data, ROC-AUC and per-insider detection are the "
            "honest measures; raw accuracy/precision would mislead.</p>"
            + panel
        )

    def _ml_panel(self, sessions, history):
        """Prominent panel: the ML behavioral-anomaly verdict for EVERY
        scanned session (not only alerts), so live monitoring shows the
        current status even when a scan is benign — the anomaly score as a
        meter plus WHICH behaviours deviated."""
        cards = []
        for s in sessions:
            raw = s.get("ml_score")
            if raw in (None, ""):
                continue
            try:
                score = float(raw)
            except (TypeError, ValueError):
                continue

            label = s.get("ml_prediction", "")
            status = s.get("final_status", "")
            user = self._esc(s.get("username"))
            pct = max(0, min(100, score))
            color = ("#c0392b" if score >= 55
                     else "#e67e22" if score >= 50 else "#27ae60")

            new_badge = ("<span class='newu'>NEW</span>"
                         if s.get("is_new") else "")

            devs = [d for d in (s.get("ml_deviations") or []) if d]
            if devs:
                chips = "".join(self._chip(s.get("username"), d, history)
                                for d in devs)
                dev_html = ("<div class='bdevs'>"
                            "<span class='bdev-label'>Deviating behaviours "
                            "(click for details):</span>" + chips + "</div>")
            else:
                dev_html = ("<div class='bdevs muted'>within normal "
                            "behavioural range</div>")

            drift_html = self._drift_html(
                s.get("username"), s.get("drift") or [], history)

            cards.append(
                "<div class='mlcard'>"
                f"<div class='mlhead'><span class='mluser'>{user}"
                f"{new_badge}</span>"
                f"<span class='mllabel' style='color:{color}'>"
                f"{self._esc(label)} &middot; {self._esc(status)}</span></div>"
                "<div class='meter'>"
                f"<div class='meter-fill' style='width:{pct}%;"
                f"background:{color}'></div>"
                f"<span class='meter-val'>{score:.0f}/100</span></div>"
                f"{dev_html}"
                f"{drift_html}"
                "</div>"
            )

        if not cards:
            return ("<p class='muted'>No sessions scanned yet — "
                    "run Own or Live monitoring.</p>")
        return "<div class='mlgrid'>" + "".join(cards) + "</div>"

    def _drift_html(self, username, drift, history=None):
        """Longer-horizon drift/trend row for a session: how the user's
        RECENT sessions differ from their earlier ones (from the rolling
        history). Informational — it never changes the verdict; it tells
        the analyst a slow shift is under way. Each pill is clickable and
        opens the SAME detail pop-up as the deviation chips (what it means,
        recent vs earlier, the trend sparkline, why it can point to an
        attack). Security-relevant drifts are highlighted."""
        items = [d for d in drift if d and d.get("text")]
        if not items:
            return ""
        pills = "".join(self._drift_pill(username, d, history) for d in items)
        return (
            "<div class='drift'>"
            "<span class='drift-label' title='How recent sessions compare "
            "with earlier ones for this user — a slow shift that per-session "
            "scoring can miss'>&#8599; Longer-horizon drift "
            "(click for details):</span>"
            + pills + "</div>"
        )

    def _drift_pill(self, username, d, history=None):
        """One clickable drift pill, wired to the shared showDev() pop-up."""
        label = (d.get("label") or "").lower().strip()
        direction = "higher than" if d.get("z", 0) >= 0 else "lower than"

        meaning = ("Longer-horizon trend. "
                   + BEHAVIOR_MEANINGS.get(
                       label, "A behavioural measure of this user."))
        attack = BEHAVIOR_ATTACK.get(
            label, "A steady drift away from a person's own past behaviour "
                   "is a classic slow-burn insider / account-takeover sign.")

        value = str(d.get("recent", ""))
        usual = str(d.get("baseline", ""))

        # Recent history for THIS feature, so the pop-up sparkline shows the
        # actual slope the drift is measuring.
        feature = d.get("feature")
        series = feature_series(history or {}, username, feature) \
            if feature else []
        hist_json = json.dumps(series)

        sd = abs(float(d.get("z", 0) or 0))
        if sd >= 6:
            sd_note = (f"Over the recent window this sits about {sd:.0f} times "
                       f"further from the user's own earlier average "
                       f"({direction} it) than their normal day-to-day wobble "
                       f"— a pronounced, sustained shift.")
        elif sd >= 3:
            sd_note = (f"Over the recent window this is roughly {sd:.0f} times "
                       f"the user's usual day-to-day wobble ({direction} their "
                       f"earlier average) — a real, sustained drift worth "
                       f"watching.")
        else:
            sd_note = (f"A mild but consistent drift ({direction} the user's "
                       f"earlier average) — noted, not alarming on its own.")

        cls = "dpill sec" if d.get("security") else "dpill"
        return (
            f"<span class='{cls}' onclick='showDev(this)' tabindex='0'"
            f" data-user=\"{self._attr(username)}\""
            f" data-text=\"{self._attr(d.get('text'))}\""
            f" data-meaning=\"{self._attr(meaning)}\""
            f" data-attack=\"{self._attr(attack)}\""
            f" data-value=\"{self._attr(value)}\""
            f" data-usual=\"{self._attr(usual)}\""
            f" data-hist=\"{self._attr(hist_json)}\""
            f" data-sd=\"{self._attr(sd_note)}\">"
            f"{self._esc(d.get('text'))}</span>"
        )

    @staticmethod
    def _attr(value):
        """Escape a string for safe use inside a double-quoted HTML
        attribute."""
        return (str(value or "")
                .replace("&", "&amp;").replace('"', "&quot;")
                .replace("<", "&lt;").replace(">", "&gt;"))

    def _chip(self, username, text, history=None):
        """One clickable deviating-behaviour chip carrying everything the
        pop-up shows: what it means, this-session-vs-normal, the recent
        trend, why attackers cause it, and how unusual it is."""
        import re

        label = text
        higher = True
        for sep in (" up (", " down ("):
            if sep in text:
                label = text.split(sep, 1)[0]
                higher = "up" in sep
                break
        key = label.lower().strip()
        direction = "higher than" if higher else "lower than"

        meaning = BEHAVIOR_MEANINGS.get(
            key, "A behavioural measure of this session.")
        attack = BEHAVIOR_ATTACK.get(
            key, "A large, unexplained change from a person's normal "
                 "behaviour is worth a closer look.")

        # this session's value vs the user's usual value
        vm = re.search(r"\(([-\d.]+)\s*vs\s*usual\s*([-\d.]+)", text)
        value = vm.group(1) if vm else ""
        usual = vm.group(2) if vm else ""

        # recent trend: this user's past values for THIS feature
        featkey = LABEL_TO_FEATURE.get(key)
        series = feature_series(history or {}, username, featkey) \
            if featkey else []
        try:
            cur = round(float(value), 3)
            if not series or abs(series[-1] - cur) > 1e-9:
                series = series + [cur]
        except (TypeError, ValueError):
            pass
        hist_json = json.dumps(series)

        m = re.search(r"([+-]?\d+(?:\.\d+)?)\s*SD", text)
        sd = abs(float(m.group(1))) if m else 0.0
        if sd >= 6:
            sd_note = (f"This is about {sd:.0f} times further from normal "
                       f"than the usual day-to-day wobble ({direction} their "
                       f"average) — a gap you would essentially never see by "
                       f"accident. A strong red flag.")
        elif sd >= 3:
            sd_note = (f"This is roughly {sd:.0f} times the usual day-to-day "
                       f"wobble ({direction} their average) — genuinely out "
                       f"of character and worth investigating.")
        else:
            sd_note = (f"This is a bit outside their usual range "
                       f"({direction} their average) — mild, but noted.")

        return (
            "<span class='bchip' onclick='showDev(this)' tabindex='0'"
            f" data-user=\"{self._attr(username)}\""
            f" data-text=\"{self._attr(text)}\""
            f" data-meaning=\"{self._attr(meaning)}\""
            f" data-attack=\"{self._attr(attack)}\""
            f" data-value=\"{self._attr(value)}\""
            f" data-usual=\"{self._attr(usual)}\""
            f" data-hist=\"{self._attr(hist_json)}\""
            f" data-sd=\"{self._attr(sd_note)}\">"
            f"{self._esc(text)}</span>"
        )

    def _charts(self):
        cm = self._embed_image("confusion_matrix.png")
        roc = self._embed_image("roc_curve.png")

        blocks = []
        if cm:
            blocks.append(
                f"<figure><img src='{cm}' alt='Confusion Matrix'>"
                f"<figcaption>Confusion Matrix</figcaption></figure>"
            )
        if roc:
            blocks.append(
                f"<figure><img src='{roc}' alt='ROC Curve'>"
                f"<figcaption>ROC Curve</figcaption></figure>"
            )
        if not blocks:
            return "<p class='muted'>No charts available yet.</p>"
        return "<div class='charts'>" + "".join(blocks) + "</div>"

    def _alerts_table(self, alerts):
        if not alerts:
            return "<p class='muted'>No alerts recorded yet.</p>"

        head = (
            "<tr><th>Time</th><th>User</th><th>Score</th><th>Level</th>"
            "<th>ML</th><th>Status</th><th>Top Correlation</th>"
            "<th>MITRE</th></tr>"
        )

        body = []
        for a in alerts:
            status = a.get("final_status", "")
            color = self.STATUS_COLORS.get(status, "#7f8c8d")
            ts = a.get("timestamp", "")[:19].replace("T", " ")
            body.append(
                "<tr>"
                f"<td>{ts}</td>"
                f"<td>{self._esc(a.get('username'))}</td>"
                f"<td>{self._esc(a.get('risk_score'))}</td>"
                f"<td>{self._esc(a.get('risk_level'))}</td>"
                f"<td>{self._esc(a.get('ml_prediction'))}</td>"
                f"<td><span class='pill' style='background:{color}'>"
                f"{self._esc(status)}</span></td>"
                f"<td>{self._esc(a.get('top_correlation'))}</td>"
                f"<td>{self._esc(a.get('mitre'))}</td>"
                "</tr>"
            )

            # Evidence sub-row: the concrete harmful commands / files /
            # signatures that triggered this alert.
            indicators = [
                i.strip()
                for i in (a.get("indicators") or "").split("||")
                if i.strip()
            ]
            if indicators:
                chips = "".join(
                    f"<span class='ind'>{self._esc(i)}</span>"
                    for i in indicators
                )
                body.append(
                    "<tr class='evidence'><td colspan='8'>"
                    "<span class='ind-label'>Indicators:</span> "
                    f"{chips}</td></tr>"
                )

        return f"<table>{head}{''.join(body)}</table>"

    @staticmethod
    def _esc(value):
        text = "" if value is None else str(value)
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def build(self, output_path=None, auto_refresh=None):

        metrics = self._load_metrics()
        alerts = self._load_alerts()
        summary = self._load_summary()
        sessions = self._load_sessions()
        history = load_history()

        generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total_alerts = self._count_alerts()
        critical = self._count_alerts(status="CRITICAL")

        if summary:
            monitored = (
                f" &middot; {summary.get('total', 0)} users monitored "
                f"({summary.get('known', 0)} known, "
                f"{summary.get('new', 0)} new) &middot; "
                f"{summary.get('flagged', 0)} flagged"
            )
        else:
            monitored = ""

        # In live/watch mode the page reloads itself so new alerts appear
        # without the analyst refreshing the browser.
        refresh_meta = (
            f'<meta http-equiv="refresh" content="{int(auto_refresh)}">'
            if auto_refresh else ""
        )
        live_badge = (
            "<span class='live'>● LIVE</span>" if auto_refresh else ""
        )

        html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{refresh_meta}
<title>Behavior Anomaly Detection — Dashboard</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
    margin: 0; padding: 2rem; line-height: 1.5;
    background: #f6f7f9; color: #1a1a1a;
  }}
  @media (prefers-color-scheme: dark) {{
    body {{ background: #14171c; color: #e6e6e6; }}
    .card, figure, table {{ background: #1e232b !important; }}
    th {{ background: #262c36 !important; }}
    td {{ border-color: #2c333d !important; }}
  }}
  h1 {{ font-size: 1.5rem; margin: 0 0 .25rem; }}
  .sub {{ color: #7f8c8d; margin-bottom: 1.5rem; font-size: .9rem; }}
  h2 {{ font-size: 1.05rem; margin: 2rem 0 .75rem; }}
  .cards {{ display: flex; flex-wrap: wrap; gap: 1rem; }}
  .card {{
    background: #fff; border-radius: 10px; padding: 1rem 1.25rem;
    min-width: 200px; flex: 1 1 200px; box-shadow: 0 1px 3px rgba(0,0,0,.08);
  }}
  .card-value {{ font-size: 1.6rem; font-weight: 700; }}
  .card-label {{ color: #374151; font-size: .82rem; font-weight: 600;
    margin-top: .2rem; }}
  .card-help {{ color: #7f8c8d; font-size: .74rem; line-height: 1.35;
    margin-top: .4rem; }}
  @media (prefers-color-scheme: dark) {{
    .card-label {{ color: #cbd5e1 !important; }} }}
  .charts {{ display: flex; flex-wrap: wrap; gap: 1.5rem; }}
  figure {{
    margin: 0; background: #fff; border-radius: 10px; padding: 1rem;
    box-shadow: 0 1px 3px rgba(0,0,0,.08);
  }}
  figure img {{ max-width: 100%; height: auto; display: block; }}
  figcaption {{ text-align: center; color: #7f8c8d; font-size: .85rem;
    margin-top: .5rem; }}
  .table-wrap {{ overflow-x: auto; }}
  table {{
    border-collapse: collapse; width: 100%; background: #fff;
    border-radius: 10px; overflow: hidden; font-size: .87rem;
    box-shadow: 0 1px 3px rgba(0,0,0,.08);
  }}
  th, td {{ padding: .55rem .75rem; text-align: left;
    border-bottom: 1px solid #eee; white-space: nowrap; }}
  th {{ background: #f0f2f5; font-weight: 600; }}
  .pill {{ color: #fff; padding: .1rem .5rem; border-radius: 999px;
    font-size: .78rem; font-weight: 600; }}
  .muted {{ color: #7f8c8d; }}
  .live {{ color: #fff; background: #c0392b; font-size: .7rem;
    font-weight: 700; padding: .12rem .5rem; border-radius: 999px;
    vertical-align: middle; margin-left: .5rem; }}
  .tag {{ font-size: .7rem; font-weight: 700; color: #fff;
    background: #6c5ce7; padding: .12rem .5rem; border-radius: 999px;
    vertical-align: middle; }}
  .lead {{ color: #555; max-width: 760px; margin: .25rem 0 1rem;
    font-size: .9rem; }}
  @media (prefers-color-scheme: dark) {{ .lead {{ color: #aab; }} }}
  .mlgrid {{ display: flex; flex-wrap: wrap; gap: 1rem; }}
  .mlcard {{ background: #fff; border-radius: 12px; padding: 1rem 1.15rem;
    min-width: 300px; flex: 1; box-shadow: 0 1px 3px rgba(0,0,0,.08);
    border-left: 4px solid #6c5ce7; }}
  @media (prefers-color-scheme: dark) {{
    .mlcard {{ background: #1e232b !important; }} }}
  .mlhead {{ display: flex; justify-content: space-between;
    align-items: baseline; }}
  .mluser {{ font-weight: 700; font-size: 1.05rem; }}
  .newu {{ font-size: .62rem; font-weight: 700; color: #fff;
    background: #6c5ce7; padding: .08rem .35rem; border-radius: 999px;
    margin-left: .4rem; vertical-align: middle; }}
  .mllabel {{ font-weight: 700; font-size: .85rem; }}
  .meter {{ position: relative; height: 20px; border-radius: 999px;
    background: #eceff3; margin: .6rem 0; overflow: hidden; }}
  @media (prefers-color-scheme: dark) {{
    .meter {{ background: #2a3038 !important; }} }}
  .meter-fill {{ position: absolute; left: 0; top: 0; bottom: 0;
    border-radius: 999px; }}
  .meter-val {{ position: absolute; right: .5rem; top: 0; line-height: 20px;
    font-size: .72rem; font-weight: 700; color: #333; }}
  @media (prefers-color-scheme: dark) {{
    .meter-val {{ color: #eee; }} }}
  .bdev-label {{ color: #7f8c8d; font-size: .72rem; font-weight: 600;
    text-transform: uppercase; display: block; margin-bottom: .3rem; }}
  .bchip {{ display: inline-block; font-size: .78rem; background: #efeaff;
    color: #5b3fd6; border-radius: 5px; padding: .12rem .45rem;
    margin: .15rem .25rem .15rem 0; cursor: pointer;
    border: 1px solid transparent; transition: all .12s; }}
  .bchip:hover, .bchip:focus {{ background: #5b3fd6; color: #fff;
    outline: none; }}
  @media (prefers-color-scheme: dark) {{
    .bchip {{ background: #2d2a44 !important; color: #b9a9ff !important; }}
    .bchip:hover, .bchip:focus {{ background: #6c5ce7 !important;
      color: #fff !important; }} }}
  .drift {{ margin-top: .55rem; padding-top: .5rem;
    border-top: 1px dashed #e2e5ec; }}
  .drift-label {{ color: #b45309; font-size: .72rem; font-weight: 700;
    text-transform: uppercase; display: block; margin-bottom: .3rem;
    cursor: help; }}
  .dpill {{ display: inline-block; font-size: .76rem; background: #fef3c7;
    color: #92400e; border-radius: 5px; padding: .12rem .45rem;
    margin: .15rem .25rem .15rem 0; border: 1px solid #fde68a;
    cursor: pointer; transition: all .12s; }}
  .dpill:hover, .dpill:focus {{ background: #d97706; color: #fff;
    border-color: #d97706; outline: none; }}
  .dpill.sec {{ background: #fee2e2; color: #991b1b;
    border-color: #fecaca; font-weight: 600; }}
  .dpill.sec:hover, .dpill.sec:focus {{ background: #b91c1c; color: #fff;
    border-color: #b91c1c; outline: none; }}
  @media (prefers-color-scheme: dark) {{
    .drift {{ border-top-color: #333a45; }}
    .drift-label {{ color: #f59e0b; }}
    .dpill {{ background: #3a2f18 !important; color: #fcd34d !important;
      border-color: #5c4a1f !important; }}
    .dpill:hover, .dpill:focus {{ background: #d97706 !important;
      color: #fff !important; }}
    .dpill.sec {{ background: #3a1f1f !important; color: #fca5a5 !important;
      border-color: #5c2626 !important; }}
    .dpill.sec:hover, .dpill.sec:focus {{ background: #b91c1c !important;
      color: #fff !important; }} }}
  .modal {{ display: none; position: fixed; inset: 0; z-index: 50;
    background: rgba(17,20,26,.55); align-items: center;
    justify-content: center; padding: 1rem; }}
  .modal-box {{ background: #fff; border-radius: 12px; max-width: 460px;
    width: 100%; padding: 1.4rem 1.5rem; position: relative;
    box-shadow: 0 10px 40px rgba(0,0,0,.3); border-top: 5px solid #5b3fd6; }}
  @media (prefers-color-scheme: dark) {{
    .modal-box {{ background: #1e232b !important; color: #e6e6e6; }} }}
  .modal-x {{ position: absolute; top: .6rem; right: .8rem; border: none;
    background: none; font-size: 1.4rem; cursor: pointer; color: #9ca3af;
    line-height: 1; }}
  .modal-user {{ font-size: .75rem; font-weight: 700; color: #5b3fd6;
    text-transform: uppercase; letter-spacing: .04em; }}
  .modal-title {{ font-size: 1.05rem; font-weight: 700; margin: .2rem 0 .8rem;
    font-family: Consolas, monospace; }}
  .modal-mean {{ font-size: .92rem; line-height: 1.5; margin: 0 0 .9rem; }}
  .mlabel {{ font-size: .7rem; font-weight: 700; color: #7f8c8d;
    text-transform: uppercase; letter-spacing: .04em; margin: 0 0 .35rem; }}
  .cmp {{ margin: 0 0 1rem; }}
  .cmp-row {{ display: flex; align-items: center; gap: .5rem;
    margin: .28rem 0; }}
  .cmp-lbl {{ width: 92px; font-size: .78rem; color: #6b7280;
    flex: 0 0 auto; }}
  .cmp-bar {{ flex: 1; height: 16px; background: #eceff3;
    border-radius: 999px; overflow: hidden; }}
  .cmp-fill {{ display: block; height: 100%; border-radius: 999px; }}
  .cmp-fill.usual {{ background: #9aa4b2; }}
  .cmp-fill.cur {{ background: #c0392b; }}
  .cmp-num {{ width: 60px; text-align: right; font-size: .78rem;
    font-weight: 700; flex: 0 0 auto; }}
  @media (prefers-color-scheme: dark) {{
    .cmp-bar {{ background: #2a3038 !important; }} }}
  .spark {{ display: flex; align-items: flex-end; gap: 3px; height: 56px;
    margin: 0 0 1rem; padding: .4rem .5rem; background: #f7f8fa;
    border-radius: 8px; }}
  @media (prefers-color-scheme: dark) {{
    .spark {{ background: #232830 !important; }} }}
  .spark-bar {{ flex: 1; min-width: 5px; background: #9aa4b2;
    border-radius: 3px 3px 0 0; }}
  .spark-bar.now {{ background: #c0392b; }}
  .spark-none {{ font-size: .82rem; color: #9ca3af; align-self: center; }}
  .modal-why {{ font-size: .9rem; line-height: 1.5; margin: 0 0 .9rem;
    background: #fdf3ef; border-left: 3px solid #c0392b; border-radius: 6px;
    padding: .6rem .8rem; }}
  .modal-why b {{ color: #c0392b; }}
  @media (prefers-color-scheme: dark) {{
    .modal-why {{ background: #2a211f !important; }} }}
  .modal-sd {{ font-size: .88rem; line-height: 1.45; margin: 0;
    background: #f3f4f6; border-radius: 8px; padding: .6rem .8rem;
    color: #374151; }}
  @media (prefers-color-scheme: dark) {{
    .modal-sd {{ background: #262c36 !important; color: #cbd5e1; }} }}
  tr.evidence td {{ white-space: normal; background: #fbfcfd;
    padding-top: .35rem; padding-bottom: .6rem; }}
  @media (prefers-color-scheme: dark) {{
    tr.evidence td {{ background: #191d24 !important; }}
  }}
  .ind-label {{ color: #7f8c8d; font-size: .75rem; font-weight: 600;
    text-transform: uppercase; letter-spacing: .03em; margin-right: .3rem; }}
  .ind {{ display: inline-block; font-family: Consolas, monospace;
    font-size: .8rem; background: #eef1f4; color: #b03a2e;
    border-radius: 5px; padding: .12rem .45rem; margin: .15rem .25rem .15rem 0;
    word-break: break-all; }}
  @media (prefers-color-scheme: dark) {{
    .ind {{ background: #2a3038 !important; color: #ff8a80 !important; }}
  }}
</style>
</head>
<body>
  <h1>Behavior Anomaly Detection — Dashboard {live_badge}</h1>
  <div class="sub">Generated {generated} &middot;
    {total_alerts} total alerts &middot; {critical} critical{monitored}</div>

  <h2>Behavioral Anomaly Detection <span class="tag">ML · UEBA</span></h2>
  <p class="lead">The Isolation Forest models each session across 18
    distinct behavioral dimensions (timing, volume, intensity, variety,
    authentication, device &amp; network) and flags deviations from
    learned-normal behaviour — catching novel activity no signature
    rule describes.</p>
  {self._ml_panel(sessions, history)}

  <h2>Model Performance</h2>
  {self._metric_cards(metrics)}

  {self._cert_block()}

  <h2>Evaluation Charts</h2>
  {self._charts()}

  <h2>Recent Alerts</h2>
  <div class="table-wrap">{self._alerts_table(alerts)}</div>

  <div id="devModal" class="modal" onclick="hideDev(event)">
    <div class="modal-box" onclick="event.stopPropagation()">
      <button class="modal-x" onclick="hideDev()" aria-label="Close">&times;</button>
      <div class="modal-user" id="mUser"></div>
      <div class="modal-title" id="mText"></div>
      <p class="modal-mean" id="mMean"></p>
      <p class="mlabel">This session vs. their normal</p>
      <div class="cmp">
        <div class="cmp-row"><span class="cmp-lbl">Their normal</span>
          <span class="cmp-bar"><i id="mBarUsual" class="cmp-fill usual"></i></span>
          <span class="cmp-num" id="mUsualVal"></span></div>
        <div class="cmp-row"><span class="cmp-lbl">This session</span>
          <span class="cmp-bar"><i id="mBarCur" class="cmp-fill cur"></i></span>
          <span class="cmp-num" id="mCurVal"></span></div>
      </div>
      <p class="mlabel">Recent trend (older &rarr; now)</p>
      <div class="spark" id="mSpark"></div>
      <div class="modal-why"><b>Why this can point to an attack</b><br>
        <span id="mAttack"></span></div>
      <p class="modal-sd" id="mSd"></p>
    </div>
  </div>
  <script>
    function showDev(el) {{
      document.getElementById('mUser').textContent = el.dataset.user;
      document.getElementById('mText').textContent = el.dataset.text;
      document.getElementById('mMean').textContent = el.dataset.meaning;
      document.getElementById('mAttack').textContent = el.dataset.attack;
      document.getElementById('mSd').textContent = el.dataset.sd;
      var v = parseFloat(el.dataset.value), u = parseFloat(el.dataset.usual);
      if (isNaN(v)) v = 0; if (isNaN(u)) u = 0;
      var mx = Math.max(Math.abs(v), Math.abs(u), 0.001);
      document.getElementById('mBarCur').style.width =
        (Math.abs(v) / mx * 100) + '%';
      document.getElementById('mBarUsual').style.width =
        (Math.abs(u) / mx * 100) + '%';
      document.getElementById('mCurVal').textContent = el.dataset.value;
      document.getElementById('mUsualVal').textContent = el.dataset.usual;

      var hist = [];
      try {{ hist = JSON.parse(el.dataset.hist || '[]'); }} catch (err) {{}}
      var box = document.getElementById('mSpark');
      box.innerHTML = '';
      if (hist.length < 2) {{
        box.innerHTML = "<span class='spark-none'>Not enough history yet " +
          "— the trend fills in as this machine is scanned over time.</span>";
      }} else {{
        var mx = Math.max.apply(null, hist.map(function (x) {{
          return Math.abs(x); }})) || 1;
        hist.forEach(function (v, i) {{
          var bar = document.createElement('span');
          bar.className = 'spark-bar' + (i === hist.length - 1 ? ' now' : '');
          bar.style.height = Math.max(8, Math.abs(v) / mx * 100) + '%';
          bar.title = v;
          box.appendChild(bar);
        }});
      }}
      document.getElementById('devModal').style.display = 'flex';
    }}
    function hideDev(e) {{
      document.getElementById('devModal').style.display = 'none';
    }}
    document.addEventListener('keydown', function (e) {{
      if (e.key === 'Escape') hideDev();
    }});
    document.querySelectorAll('.bchip, .dpill').forEach(function (c) {{
      c.addEventListener('keydown', function (e) {{
        if (e.key === 'Enter' || e.key === ' ') {{ e.preventDefault(); showDev(c); }}
      }});
    }});
  </script>
</body>
</html>"""

        if output_path is None:
            output_path = os.path.join(self.reports_dir, "dashboard.html")

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"Dashboard written to {output_path}")
        return output_path

    def _count_alerts(self, status=None):
        if not os.path.exists(self.alerts_csv):
            return 0
        with open(self.alerts_csv, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        if status is None:
            return len(rows)
        return sum(1 for r in rows if r.get("final_status") == status)


if __name__ == "__main__":
    DashboardBuilder().build()
