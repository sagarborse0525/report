import os
import time
import logging
from typing import Dict, List, Optional, Tuple
from scrum_name import scrum_ids
import requests
import pandas as pd
from dateutil import parser
from openpyxl import load_workbook
from openpyxl.styles import Border, Side, PatternFill, Font
from openpyxl.chart import BarChart, Reference
from datetime import datetime, timedelta, timezone
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------- Configuration ---------------------- #
GITLAB_ACCESS_TOKEN = os.environ.get("GRAPHQL_API_TOKEN")  # PAT/OAuth token
BASE_URL = "https://gitlab.com/api/v4"
OUTPUT_XLSX = "gitlab_vuln.xlsx"

# Tune network behavior
DEFAULT_PER_PAGE = 50
DEFAULT_TIMEOUT: Tuple[int, int] = (10, 60)  # (connect, read)
MAX_RETRIES = 5
BACKOFF_FACTOR = 0.5

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("gitlab-vuln-report")


# ---------------------- HTTP Session with Retries ---------------------- #
def make_session(token: str) -> requests.Session:
    if not token:
        raise RuntimeError("GRAPHQL_API_TOKEN environment variable is required for authentication.")
    retry = Retry(
        total=MAX_RETRIES,
        connect=MAX_RETRIES,
        read=MAX_RETRIES,  # important for ChunkedEncodingError / premature EOF
        backoff_factor=BACKOFF_FACTOR,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods={"GET", "HEAD", "OPTIONS"},
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=50)
    s = requests.Session()
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.trust_env = True  # respect proxies from environment if present
    s.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Connection": "keep-alive",
        # If you suspect proxy issues with compressed chunked responses, uncomment:
        # "Accept-Encoding": "identity",
    })
    return s


SESSION = make_session(GITLAB_ACCESS_TOKEN)


# ---------------------- Helpers ---------------------- #
def _sleep_if_rate_limited(resp: requests.Response) -> None:
    """Sleep if we hit rate limits (429) and Retry-After header is present."""
    if resp.status_code == 429:
        retry_after = resp.headers.get("Retry-After")
        if retry_after:
            try:
                delay = int(retry_after)
                logger.warning("Rate limited. Sleeping for %s seconds...", delay)
                time.sleep(delay)
            except ValueError:
                logger.warning("Rate limited without numeric Retry-After; backing off 2 seconds.")
                time.sleep(2)


def _get_json(url: str, params: Dict) -> Optional[List[Dict]]:
    """
    GET JSON with retries and basic 429 handling.
    Returns list/dict from JSON or None on error.
    """
    try:
        resp = SESSION.get(url, params=params, timeout=DEFAULT_TIMEOUT)
    except requests.exceptions.ChunkedEncodingError:
        # Extra guard despite urllib3 retry: brief backoff before surfacing to caller
        logger.warning("ChunkedEncodingError: transient network hiccup for %s. Backing off 0.5s.", url)
        time.sleep(0.5)
        try:
            resp = SESSION.get(url, params=params, timeout=DEFAULT_TIMEOUT)
        except Exception as e:
            logger.error("Repeated chunk error on %s: %s", url, e)
            return None
    except Exception as e:
        logger.error("HTTP error: %s", e)
        return None

    if resp.status_code == 429:
        _sleep_if_rate_limited(resp)
        # retry once after sleeping
        resp = SESSION.get(url, params=params, timeout=DEFAULT_TIMEOUT)

    if resp.status_code != 200:
        logger.error("GET %s failed (%s): %s", url, resp.status_code, resp.text[:500])
        return None

    try:
        return resp.json()
    except Exception as e:
        logger.error("JSON parse error for %s: %s", url, e)
        return None


def _parse_utc(dt_str: str) -> Optional[datetime]:
    """Robust ISO timestamp parsing into timezone-aware UTC datetime."""
    if not dt_str:
        return None
    try:
        dt = parser.isoparse(dt_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


# ---------------------- GitLab API Accessors ---------------------- #
def get_projects_in_group(group_id: str) -> List[Dict]:
    """List projects for a group (including subgroups, excluding archived)."""
    projects: List[Dict] = []
    page = 1
    logger.info("Fetching projects for group %s ...", group_id)
    while True:
        url = f"{BASE_URL}/groups/{group_id}/projects"
        params = {"per_page": DEFAULT_PER_PAGE, "page": page, "include_subgroups": True, "archived": False}
        data = _get_json(url, params)
        if data is None:
            break
        if not data:
            break
        projects.extend(data)
        page += 1
    logger.info("Group %s: %d projects", group_id, len(projects))
    return projects


def iter_project_vulnerabilities(project_id: str, state: Optional[str] = None):
    """
    Iterate all vulnerabilities for a project.
    state: e.g., 'detected' to filter open, or None for all states.
    """
    page = 1
    while True:
        url = f"{BASE_URL}/projects/{project_id}/vulnerabilities"
        params = {"per_page": DEFAULT_PER_PAGE, "page": page}
        if state:
            params["state"] = state
        data = _get_json(url, params)
        if data is None:
            break
        if not data:
            break
        for v in data:
            yield v
        page += 1


def get_open_counts(project_id: str) -> Tuple[int, int]:
    """
    Count current open (state='detected') High and Critical vulnerabilities for a project.
    Returns: (critical_count, high_count)
    """
    critical = 0
    high = 0
    for v in iter_project_vulnerabilities(project_id, state="detected"):
        sev = (v.get("severity") or "").lower()
        sta = (v.get("state") or "").lower()
        if sev == "critical" and sta == "detected":
            critical += 1
        elif sev == "high" and sta == "detected":
            high += 1
    return critical, high


def get_vulns_last_n_days_all_states(project_id: str, days_back: int) -> List[Dict]:
    """
    Fetch ALL vulnerabilities created in the last N days across ALL states.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)
    results: List[Dict] = []
    for v in iter_project_vulnerabilities(project_id, state=None):
        created_at = _parse_utc(v.get("created_at", ""))
        if created_at and created_at >= cutoff:
            results.append(v)
    return results


def get_30Days(project_id: str, days_back: int = 30) -> Dict[str, int]:
    """
    Returns counts of Critical and High vulnerabilities created in the last N days,
    across ALL states.
    """
    items = get_vulns_last_n_days_all_states(project_id, days_back=days_back)
    critical_n = 0
    high_n = 0
    for v in items:
        sev = (v.get("severity") or "").lower()
        if sev == "critical":
            critical_n += 1
        elif sev == "high":
            high_n += 1
    return {"critical": critical_n, "high": high_n}


# ---------------------- Excel Utilities ---------------------- #
def autosize_and_style_sheet(ws):
    """Apply borders, header style, and autosize columns."""
    thin_border = Border(
        left=Side(style="thin"),
        right=Side(style="thin"),
        top=Side(style="thin"),
        bottom=Side(style="thin"),
    )
    header_fill = PatternFill(start_color="4F81BD", end_color="4F81BD", fill_type="solid")
    header_font = Font(bold=True, color="FFFFFF")

    # Header (first row)
    if ws.max_row >= 1:
        for cell in ws[1]:
            cell.border = thin_border
            cell.fill = header_fill
            cell.font = header_font

    # Body
    for row in ws.iter_rows(min_row=2):
        for cell in row:
            cell.border = thin_border

    # Autosize columns
    for col in ws.columns:
        max_length = max(len(str(cell.value)) if cell.value is not None else 0 for cell in col)
        ws.column_dimensions[col[0].column_letter].width = min(max_length + 2, 60)


def add_summary_chart(ws):
    max_row = ws.max_row
    max_col = ws.max_column
    if max_row < 2 or max_col < 3:
        return
    # Data series start at row 1 for titles, categories exclude header.
    data = Reference(ws, min_col=2, max_col=max_col, min_row=1, max_row=max_row)
    cats = Reference(ws, min_col=1, min_row=2, max_row=max_row)
    chart = BarChart()
    chart.type = "col"
    chart.style = 10
    chart.title = "Vulnerabilities Summary"
    chart.y_axis.title = "Count"
    chart.x_axis.title = "Scrum"
    chart.add_data(data, titles_from_data=True)
    chart.set_categories(cats)
    chart.width = 45
    chart.height = 18
    ws.add_chart(chart, "H2")


def move_sheet_first(wb, sheet_name: str):
    ws = wb[sheet_name]
    try:
        # openpyxl 3.1+ has move_sheet
        wb.move_sheet(ws, offset=-wb.index(ws))
    except Exception:
        # Fallback to private attribute (commonly used workaround)
        idx = wb.sheetnames.index(sheet_name)
        wb._sheets.insert(0, wb._sheets.pop(idx))


# ---------------------- NEW: Percentage change table (30/60/90 vs current) ---------------------- #
def _compute_pct_change_against_current(window_count: int, current_count: int) -> Optional[float]:
    """
    Compute fractional percent change (suitable for Excel percent formatting)
    comparing window_count vs current_count:
        pct = (window_count - current_count) / current_count

    Returns:
      - float fraction (e.g., 0.25 for +25%) when defined
      - 0.0 when both are zero
      - None when current_count == 0 and window_count > 0 (undefined/infinite)
    """
    try:
        wc = int(window_count)
        cc = int(current_count)
    except Exception:
        return None

    if cc == 0:
        if wc == 0:
            return 0.0
        else:
            return None  # undefined / infinite
    return (wc - cc) / cc


def add_percentage_table(ws, summary_df: pd.DataFrame):
    """
    Writes a percentage-change table under Summary that shows how each window (30/60/90 day)
    compares to CURRENT open counts (Critical / High).
    The Excel numeric cells use a custom number_format to render + / - sign: '+0.00%;-0.00%;0.00%'
    """
    pct_rows = []
    for r in summary_df.to_dict("records"):
        scrum = r.get("ScrumName")
        current_c = int(r.get("Critical", 0))
        current_h = int(r.get("High", 0))

        c30 = int(r.get("30DaysCritical", 0))
        h30 = int(r.get("30DaysHigh", 0))
        c60 = int(r.get("60DaysCritical", 0))
        h60 = int(r.get("60DaysHigh", 0))
        c90 = int(r.get("90DaysCritical", 0))
        h90 = int(r.get("90DaysHigh", 0))

        pct_rows.append({
            "ScrumName": scrum,
            "30Day Critical % change": _compute_pct_change_against_current(c30, current_c),
            "30Day High % change": _compute_pct_change_against_current(h30, current_h),
            "60Day Critical % change": _compute_pct_change_against_current(c60, current_c),
            "60Day High % change": _compute_pct_change_against_current(h60, current_h),
            "90Day Critical % change": _compute_pct_change_against_current(c90, current_c),
            "90Day High % change": _compute_pct_change_against_current(h90, current_h),
        })

    # Start writing two rows below the end of existing Summary table
    start_row = ws.max_row + 2

    # Title row
    title_cell = ws.cell(row=start_row, column=1, value="Percent change of CURRENT open vs last N days (positive = increase)")
    title_cell.font = Font(bold=True)
    start_row += 1

    headers = [
        "ScrumName",
        "30Day Critical % change",
        "30Day High % change",
        "60Day Critical % change",
        "60Day High % change",
        "90Day Critical % change",
        "90Day High % change",
    ]

    thin_border = Border(
        left=Side(style="thin"), right=Side(style="thin"),
        top=Side(style="thin"),  bottom=Side(style="thin"),
    )
    header_fill = PatternFill(start_color="4F81BD", end_color="4F81BD", fill_type="solid")
    header_font = Font(bold=True, color="FFFFFF")

    # Write header row
    for col, h in enumerate(headers, start=1):
        c = ws.cell(row=start_row, column=col, value=h)
        c.border = thin_border
        c.fill = header_fill
        c.font = header_font

    # Data rows
    for i, r in enumerate(pct_rows, start=1):
        base_row = start_row + i
        # ScrumName
        c = ws.cell(row=base_row, column=1, value=r["ScrumName"])
        c.border = thin_border

        # Write percentage columns (either numeric fraction or "N/A")
        for j, key in enumerate(headers[1:], start=2):
            val = r.get(key)
            cell = ws.cell(row=base_row, column=j)
            cell.border = thin_border
            if val is None:
                cell.value = "N/A"
            else:
                # Write as fractional value for Excel percent formatting
                # Use number format that shows + sign for positive values
                cell.value = float(val)
                cell.number_format = "+0.00%;-0.00%;0.00%"

    # Small note row below table describing "N/A"
    note_row = start_row + len(pct_rows) + 2
    note_cell = ws.cell(row=note_row, column=1, value="Note: 'N/A' appears when current open count is 0 and window count > 0 (undefined/infinite percent increase).")
    note_cell.font = Font(italic=True)


# ---------------------- Main ---------------------- #
def main():
    # Example sanity check for 30/60/90 days on a sample project
    sample30 = get_30Days("27224759", days_back=30)
    sample60 = get_30Days("27224759", days_back=60)
    sample90 = get_30Days("27224759", days_back=90)
    logger.info(
        "Sample project -> Last30 (C:%s H:%s), Last60 (C:%s H:%s), Last90 (C:%s H:%s)",
        sample30["critical"], sample30["high"],
        sample60["critical"], sample60["high"],
        sample90["critical"], sample90["high"],
    )

    # Collect data per scrum and write to Excel
    summary_rows: List[Dict] = []
    with pd.ExcelWriter(OUTPUT_XLSX, engine="openpyxl") as writer:
        for scrum_name, group_id in scrum_ids.items():
            logger.info("Processing scrum '%s' (group id %s)", scrum_name.lower(), group_id)
            data_rows: List[Dict] = []

            projects = get_projects_in_group(group_id)
            for proj in projects:
                pid = proj.get("id")
                pname = proj.get("name") or str(pid)

                # Open counts (current state == detected)
                critical_open, high_open = get_open_counts(pid)

                # Last 30/60/90 days across ALL states
                last30 = get_30Days(pid, days_back=30)
                last60 = get_30Days(pid, days_back=60)
                last90 = get_30Days(pid, days_back=90)

                data_rows.append({
                    "ScrumName": scrum_name.lower(),
                    "ProjectName": pname.lower(),
                    "Critical": critical_open,
                    "High": high_open,
                    "30DaysCritical": last30["critical"],
                    "30DaysHigh": last30["high"],
                    "60DaysCritical": last60["critical"],
                    "60DaysHigh": last60["high"],
                    "90DaysCritical": last90["critical"],
                    "90DaysHigh": last90["high"],
                })

            # Stable column order
            columns = [
                "ScrumName", "ProjectName",
                "Critical", "High",
                "30DaysCritical", "30DaysHigh",
                "60DaysCritical", "60DaysHigh",
                "90DaysCritical", "90DaysHigh",
            ]
            df = pd.DataFrame(data_rows, columns=columns)
            df.to_excel(writer, sheet_name=scrum_name.lower(), index=False)

            # Prepare summary aggregation in-memory
            def _sum(col: str) -> int:
                return int(df[col].fillna(0).sum()) if (not df.empty and col in df.columns) else 0

            summary_rows.append({
                "ScrumName": scrum_name.lower(),
                "Critical": _sum("Critical"),
                "High": _sum("High"),
                "30DaysCritical": _sum("30DaysCritical"),
                "30DaysHigh": _sum("30DaysHigh"),
                "60DaysCritical": _sum("60DaysCritical"),
                "60DaysHigh": _sum("60DaysHigh"),
                "90DaysCritical": _sum("90DaysCritical"),
                "90DaysHigh": _sum("90DaysHigh"),
            })

        # Write Summary sheet (same column order as above but grouped)
        summary_cols = [
            "ScrumName",
            "Critical", "High",
            "30DaysCritical", "30DaysHigh",
            "60DaysCritical", "60DaysHigh",
            "90DaysCritical", "90DaysHigh",
        ]
        summary_df = pd.DataFrame(summary_rows, columns=summary_cols)
        summary_df.to_excel(writer, sheet_name="Summary", index=False)

    # ---- Post-process with openpyxl (after writer is closed/saved) ----
    wb = load_workbook(OUTPUT_XLSX)

    # Append the percentage-change table to Summary (does not touch existing tables)
    if "Summary" in wb.sheetnames:
        add_percentage_table(wb["Summary"], summary_df)

    # Style & autosize all sheets (keeps original styling logic intact)
    for sheet_name in wb.sheetnames:
        ws = wb[sheet_name]
        autosize_and_style_sheet(ws)

    # Move Summary to first position and save
    if "Summary" in wb.sheetnames:
        move_sheet_first(wb, "Summary")
        # Optional: chart of counts (not of percentages). Uncomment if you want it.
        # add_summary_chart(wb["Summary"])

    wb.save(OUTPUT_XLSX)
    logger.info("Summary sheet updated successfully with percentage table: %s", OUTPUT_XLSX)


if __name__ == "__main__":
    main()
