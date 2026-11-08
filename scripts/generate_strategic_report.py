#!/usr/bin/env python3
"""Generate the current malware collection and model results PDF."""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import legal, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    KeepTogether,
    LongTable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/malware"
COHORT = DATA / "revision4/family-heldout-balanced-224-v1-20261014"
RECOMPUTED = COHORT / "reports/balanced_9network_9host/recomputed_20261015"
PREDICTIONS = RECOMPUTED / "category_analysis/sample_predictions.csv"
INVENTORY = DATA / "malware_sample_inventory_all_expansions_20261014.csv"
DATASET = COHORT / "labeled_sample_dataset_full_35host_9network.csv"
METRICS = RECOMPUTED / "cv_metrics.json"
CATEGORY_METRICS = RECOMPUTED / "category_analysis/category_metrics.csv"
IMPORTANCE = RECOMPUTED / "feature_importance.csv"
OUTPUT = ROOT / "reports/ali_report.pdf"

INK = colors.HexColor("#18323A")
TEAL = colors.HexColor("#087E83")
PALE_TEAL = colors.HexColor("#E8F3F1")
ORANGE = colors.HexColor("#C47A35")
PALE_ORANGE = colors.HexColor("#FBF1E5")
MID_GRAY = colors.HexColor("#68777C")
LIGHT_GRAY = colors.HexColor("#EEF1F1")
GRID = colors.HexColor("#D1DADB")
WHITE = colors.white

CATEGORY_ORDER = ("backdoor", "botnet", "ddos", "other_elf", "ransomware", "trojan")
CATEGORY_NAMES = {
    "backdoor": "Backdoor",
    "botnet": "Botnet",
    "ddos": "DDoS",
    "other_elf": "Other ELF",
    "ransomware": "Ransomware",
    "trojan": "Trojan",
}
SOURCE_ORDER = (
    "revision3_original_138",
    "additional_20261014_batch_42",
    "expanded_20261014_additional_38",
    "newly_acquired_7_staged",
    "revision4_prior_6",
)
SOURCE_NAMES = {
    "revision3_original_138": "Revision 3 original cohort",
    "additional_20261014_batch_42": "October 14 additional batch",
    "expanded_20261014_additional_38": "October 14 expanded batch",
    "newly_acquired_7_staged": "Newly acquired, staged set",
    "revision4_prior_6": "Revision 4 prior samples",
}
FEATURE_SET_NAMES = {"network": "Network", "host": "Host/eBPF", "hybrid": "Hybrid"}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as source:
        return list(csv.DictReader(source))


def read_inputs() -> dict:
    inventory_rows = read_csv(INVENTORY)
    prediction_rows = [row for row in read_csv(PREDICTIONS) if row["feature_set"] == "hybrid"]
    dataset_rows = read_csv(DATASET)
    with METRICS.open(encoding="utf-8") as source:
        metric_summary = json.load(source)
    category_rows = [
        row for row in read_csv(CATEGORY_METRICS) if row["feature_set"] == "hybrid"
    ]
    importance_rows = [
        row for row in read_csv(IMPORTANCE) if row["feature_set"] == "hybrid"
    ]

    inventory_by_hash = {row["sha256"].lower(): row for row in inventory_rows}
    predictions_by_hash = {row["sha256"].lower(): row for row in prediction_rows}
    if len(inventory_by_hash) != len(inventory_rows):
        raise ValueError("The acquisition inventory has duplicate SHA-256 values")
    if len(predictions_by_hash) != len(prediction_rows):
        raise ValueError("The hybrid prediction file has duplicate SHA-256 values")

    malware_dataset = {
        row["sample_artifact"].removesuffix(".zip").lower(): row
        for row in dataset_rows
        if row["class_name"] == "malware"
    }
    if set(predictions_by_hash) != set(malware_dataset):
        raise ValueError("Hybrid predictions do not exactly cover the malware dataset")
    declared_model_hashes = {
        row["sha256"].lower()
        for row in inventory_rows
        if row["included_in_expanded_family_grouped_model"].casefold() == "yes"
    }
    if declared_model_hashes != set(predictions_by_hash):
        raise ValueError("Inventory inclusion flags do not match the hybrid predictions")
    if set(predictions_by_hash) - set(inventory_by_hash):
        raise ValueError("A modelled sample is missing from the acquisition inventory")

    samples = []
    for digest, inventory_row in inventory_by_hash.items():
        prediction = predictions_by_hash.get(digest)
        category = (prediction or {}).get("category") or inventory_row.get("malwarebazaar_category", "")
        family = (prediction or {}).get("malware_family") or inventory_row.get("malware_family", "")
        if not category:
            raise ValueError(f"No metadata category is available for sample {digest}")
        if prediction and prediction["source_cohort"] != inventory_row["source_cohort"]:
            raise ValueError(f"Source cohort mismatch for sample {digest}")
        samples.append(
            {
                "sha256": digest,
                "category": category,
                "family": family or "Unassigned",
                "source": inventory_row["source_cohort"],
                "run_status": (prediction or {}).get("sample_run_status")
                or inventory_row.get("sample_run_status", "unknown"),
                "collection_status": inventory_row.get("collection_status", "unknown"),
                "modelled": prediction is not None,
                "score": float(prediction["probability_malware"]) if prediction else None,
                "prediction": int(prediction["predicted_label"]) if prediction else None,
            }
        )

    if len(samples) != 231 or sum(sample["modelled"] for sample in samples) != 224:
        raise ValueError("Expected 231 acquired samples, of which 224 are modelled")
    class_counts = Counter(row["class_name"] for row in dataset_rows)
    if class_counts != Counter({"malware": 224, "benign": 138}):
        raise ValueError(f"Unexpected evaluation dataset classes: {dict(class_counts)}")

    fold_by_artifact = {}
    for row in read_csv(RECOMPUTED / "out_of_fold_predictions.csv"):
        if row["feature_set"] == "hybrid":
            fold_by_artifact[row["sample_artifact"]] = row["fold"]
    group_folds: dict[str, set[str]] = {}
    for row in dataset_rows:
        group_folds.setdefault(row["group_id"], set()).add(
            fold_by_artifact[row["sample_artifact"]]
        )
    if any(len(folds) != 1 for folds in group_folds.values()):
        raise ValueError("At least one evaluation group crosses cross-validation folds")

    return {
        "samples": samples,
        "dataset_rows": dataset_rows,
        "metrics": metric_summary,
        "category_metrics": category_rows,
        "importance": sorted(importance_rows, key=lambda row: float(row["importance"]), reverse=True),
        "group_count": len(group_folds),
        "modelled_count": len(predictions_by_hash),
        "unmodelled_count": len(samples) - len(predictions_by_hash),
    }


def percent(value: float) -> str:
    return f"{100 * value:.1f}%"


def make_styles():
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=26,
            leading=30,
            textColor=INK,
            alignment=TA_LEFT,
            spaceAfter=5,
        )
    )
    styles.add(
        ParagraphStyle(
            "ReportSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=13,
            leading=17,
            textColor=MID_GRAY,
            spaceAfter=10,
        )
    )
    styles.add(
        ParagraphStyle(
            "SectionHeading",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=17,
            textColor=TEAL,
            spaceBefore=10,
            spaceAfter=5,
            keepWithNext=True,
        )
    )
    styles.add(
        ParagraphStyle(
            "Subheading",
            parent=styles["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            textColor=INK,
            spaceBefore=7,
            spaceAfter=3,
            keepWithNext=True,
        )
    )
    styles.add(
        ParagraphStyle(
            "BodyCompact",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11.5,
            textColor=INK,
            spaceAfter=5,
        )
    )
    styles.add(
        ParagraphStyle(
            "SmallNote",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=7,
            leading=9,
            textColor=MID_GRAY,
            spaceAfter=4,
        )
    )
    styles.add(
        ParagraphStyle(
            "TableCell",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=7,
            leading=8.5,
            textColor=INK,
            wordWrap="CJK",
        )
    )
    styles.add(
        ParagraphStyle(
            "TableHeader",
            parent=styles["TableCell"],
            fontName="Helvetica-Bold",
            fontSize=6.8,
            leading=8,
            textColor=WHITE,
        )
    )
    styles.add(
        ParagraphStyle(
            "HashCell",
            parent=styles["TableCell"],
            fontName="Courier",
            fontSize=5.8,
            leading=7,
            wordWrap="CJK",
        )
    )
    styles.add(
        ParagraphStyle(
            "Kpi",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=INK,
            alignment=TA_CENTER,
        )
    )
    styles.add(
        ParagraphStyle(
            "KpiValue",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=22,
            textColor=TEAL,
            alignment=TA_CENTER,
        )
    )
    return styles


def paragraph(text: str, style):
    return Paragraph(text, style)


def cell(value, style):
    if isinstance(value, Paragraph):
        return value
    return Paragraph(escape(str(value)), style)


def make_table(rows, widths, styles, *, font_size=7, hash_columns=(), repeat_rows=1):
    body_style = styles["TableCell"]
    header_style = styles["TableHeader"]
    hash_style = styles["HashCell"]
    data = []
    for row_index, row in enumerate(rows):
        prepared = []
        for column_index, value in enumerate(row):
            if row_index < repeat_rows:
                prepared.append(cell(value, header_style))
            elif column_index in hash_columns:
                prepared.append(cell(value, hash_style))
            else:
                prepared.append(cell(value, body_style))
        data.append(prepared)

    table = LongTable(data, colWidths=widths, repeatRows=repeat_rows, hAlign="LEFT")
    commands = [
        ("BACKGROUND", (0, 0), (-1, repeat_rows - 1), INK),
        ("GRID", (0, 0), (-1, -1), 0.35, GRID),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    if len(data) > repeat_rows:
        commands.append(("ROWBACKGROUNDS", (0, repeat_rows), (-1, -1), [WHITE, LIGHT_GRAY]))
    if font_size != 7:
        commands.append(("FONTSIZE", (0, 0), (-1, -1), font_size))
    table.setStyle(TableStyle(commands))
    return table


def page_chrome(canvas, document):
    canvas.saveState()
    page_width, page_height = document.pagesize
    canvas.setStrokeColor(GRID)
    canvas.setLineWidth(0.5)
    canvas.line(document.leftMargin, page_height - 0.42 * inch, page_width - document.rightMargin, page_height - 0.42 * inch)
    canvas.setFont("Helvetica-Bold", 7)
    canvas.setFillColor(TEAL)
    canvas.drawString(document.leftMargin, page_height - 0.32 * inch, "MALWARE COLLECTION AND DETECTION")
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MID_GRAY)
    canvas.drawString(document.leftMargin, 0.28 * inch, "Evidence cutoff: 15 October 2026 | Local research artifacts")
    canvas.drawRightString(page_width - document.rightMargin, 0.28 * inch, f"{document.page}")
    canvas.restoreState()


def add_section(story, title, styles):
    story.append(Paragraph(title, styles["SectionHeading"]))


def add_bullet(story, lead: str, detail: str, styles):
    story.append(
        Paragraph(
            f"<font color='{TEAL.hexval()}'><b>{escape(lead)}</b></font> {escape(detail)}",
            styles["BodyCompact"],
        )
    )


def create_report(inputs: dict) -> Path:
    styles = make_styles()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    page_size = landscape(legal)
    doc = SimpleDocTemplate(
        str(OUTPUT),
        pagesize=page_size,
        rightMargin=0.55 * inch,
        leftMargin=0.55 * inch,
        topMargin=0.62 * inch,
        bottomMargin=0.52 * inch,
        title="Strategic Report: Malware Collection and Hybrid Detection",
        author="Malware Detection Study",
        subject="Revision 4 collection and family-held-out model results",
    )
    story = []
    samples = inputs["samples"]
    modeled_samples = [sample for sample in samples if sample["modelled"]]
    acquisition_counts = Counter(sample["source"] for sample in samples)
    model_counts = Counter(sample["source"] for sample in modeled_samples)
    acquired_by_category = Counter(sample["category"] for sample in samples)
    modeled_by_category = Counter(sample["category"] for sample in modeled_samples)
    category_source_counts = Counter((sample["category"], sample["source"]) for sample in samples)
    run_status_counts = Counter(sample["run_status"] for sample in modeled_samples)
    category_metrics = {row["category"]: row for row in inputs["category_metrics"]}
    metric_sets = inputs["metrics"]["feature_sets"]

    story.append(Spacer(1, 0.12 * inch))
    story.append(Paragraph("Strategic Report", styles["ReportTitle"]))
    story.append(
        Paragraph(
            "Isolated Linux Malware Collection, Telemetry, and Family-Held-Out Detection",
            styles["ReportSubtitle"],
        )
    )
    story.append(
        Paragraph(
            "Current evidence only: revision 4 acquisition cohorts and the evaluation recomputed on 15 October 2026. "
            "Earlier model results are intentionally omitted.",
            styles["BodyCompact"],
        )
    )

    kpi_width = (page_size[0] - doc.leftMargin - doc.rightMargin) / 5
    kpi_data = [[
        Paragraph("<b><font size='20' color='#087E83'>231</font></b><br/>acquired samples", styles["Kpi"]),
        Paragraph("<b><font size='20' color='#087E83'>224</font></b><br/>modelled malware", styles["Kpi"]),
        Paragraph("<b><font size='20' color='#087E83'>138</font></b><br/>benign controls", styles["Kpi"]),
        Paragraph("<b><font size='20' color='#087E83'>57</font></b><br/>held-out groups", styles["Kpi"]),
        Paragraph(
            f"<b><font size='20' color='#087E83'>{percent(metric_sets['hybrid']['pooled_oof']['balanced_accuracy'])}</font></b><br/>hybrid balanced accuracy",
            styles["Kpi"],
        ),
    ]]
    kpi_table = Table(kpi_data, colWidths=[kpi_width] * 5, rowHeights=[0.62 * inch])
    kpi_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), PALE_TEAL),
                ("BOX", (0, 0), (-1, -1), 0.6, GRID),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, WHITE),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(kpi_table)
    story.append(Spacer(1, 0.08 * inch))

    add_section(story, "Executive Readout", styles)
    story.append(
        Paragraph(
            "The latest family-held-out comparison favors hybrid host and network telemetry on pooled out-of-fold "
            "results: 92.9% balanced accuracy, compared with 91.8% for host/eBPF alone and 87.4% for network alone. "
            "Hybrid produced 5 fewer malware misses than host-only at the same 9 false positives. The gain is modest, "
            "and fold-average accuracy and F1 do not show a uniform hybrid advantage; treat this as promising cohort-specific "
            "evidence, not a deployment claim.",
            styles["BodyCompact"],
        )
    )
    story.append(
        Paragraph(
            "The acquisition inventory contains 231 MalwareBazaar-derived ELF candidates across five source cohorts. "
            "The model uses 224 samples with usable archived telemetry plus 138 generated benign controls. Seven acquired "
            "samples are retained in the appendix with metadata type and source, but are marked unscored because collection "
            "or output transfer failed.",
            styles["BodyCompact"],
        )
    )

    add_section(story, "1. Recent Cohort and Provenance", styles)
    story.append(
        Paragraph(
            "Sample identity is SHA-256. Source cohorts identify acquisition batches, not distinct malware families. "
            "Type and family labels come from MalwareBazaar metadata and tags; they describe source classification, "
            "not independently verified runtime behavior.",
            styles["BodyCompact"],
        )
    )
    source_rows = [["Source cohort", "Acquired", "Modelled", "Not scored"]]
    for source in SOURCE_ORDER:
        acquired = acquisition_counts[source]
        modelled = model_counts[source]
        source_rows.append([SOURCE_NAMES[source], acquired, modelled, acquired - modelled])
    source_rows.append(["Total", len(samples), len(modeled_samples), len(samples) - len(modeled_samples)])
    story.append(make_table(source_rows, [3.65 * inch, 1.0 * inch, 1.0 * inch, 1.0 * inch], styles))
    story.append(Spacer(1, 0.06 * inch))

    category_rows = [["Metadata type", "Acquired", "Modelled", "Not scored"]]
    for category in CATEGORY_ORDER:
        category_rows.append(
            [
                CATEGORY_NAMES[category],
                acquired_by_category[category],
                modeled_by_category[category],
                acquired_by_category[category] - modeled_by_category[category],
            ]
        )
    category_rows.append(["Total", len(samples), len(modeled_samples), len(samples) - len(modeled_samples)])
    story.append(make_table(category_rows, [2.4 * inch, 1.0 * inch, 1.0 * inch, 1.0 * inch], styles))
    story.append(
        Paragraph(
            "All seven unscored acquisitions are classified in the inventory: four botnet, two DDoS, and one other-ELF "
            "sample. Their status is not counted as a model false negative.",
            styles["SmallNote"],
        )
    )

    add_section(story, "2. Containment and Automated Execution", styles)
    add_bullet(
        story,
        "Clean-state isolation.",
        "The VirtualBox batch harness restores a named clean snapshot before each sample and again during cleanup. "
        "Before boot it rejects NAT, bridged, host-only, and other host-connected adapters; the malware guest is restricted "
        "to an internal network, with an emulated sink as its peer.",
        styles,
    )
    add_bullet(
        story,
        "Stage and validate.",
        "Encrypted ZIP samples are unpacked inside the guest. The harness selects an ELF or executable, records architecture, "
        "and skips binaries outside the guest's supported x86_64/i386 execution path. Sample archives are not copied into "
        "the guest on each iteration; the clean snapshot already contains the cohort.",
        styles,
    )
    add_bullet(
        story,
        "Bounded run.",
        "The latest batch uses a 20-second per-sample limit, 0.5-second telemetry windows, packet capture on enp0s3, "
        "and eBPF enabled. The runner terminates the sample process group at the limit. Resume mode skips completed runs "
        "with archived output and does not re-launch those samples.",
        styles,
    )
    add_bullet(
        story,
        "Return artifacts safely.",
        "The guest packs collector output into one archive; the host pulls that file, checks its size, and extracts it "
        "without preserving ownership or permissions. Idempotent archive/copy operations may be retried; sample execution "
        "is not retried in-place.",
        styles,
    )
    story.append(
        Paragraph(
            "Runner status and sensor availability are different fields. A malware process that times out, is signaled, "
            "or exits nonzero remains malware-labeled; status describes execution, while usable telemetry determines "
            "whether it can enter the model.",
            styles["BodyCompact"],
        )
    )

    add_section(story, "3. Collector Design and CSV Path", styles)
    collector_rows = [
        ["Collector", "Design and output"],
        [
            "Network / packet capture",
            "tcpdump records a per-run PCAP on the isolated guest interface. The runner parses packets into 0.5-second "
            "windows and derives packet count, packet bytes, and directional IP/protocol/port flow counts. The model uses "
            "aggregate signals, not payloads or destination identities.",
        ],
        [
            "Host / eBPF",
            "A separate bpftrace process attaches syscall and scheduler tracepoints before launch. Events are scoped to the "
            "sample process and observed fork descendants. It records syscall counts, successful open/write returns, and "
            "positive write-byte totals; raw events are exported to ebpf_events.csv.",
        ],
        [
            "Window telemetry",
            "malware_runner.py samples process/system counters and filesystem-watch diagnostics alongside packet and eBPF "
            "features into telemetry.csv. Watchdog, psutil, and filename observations are diagnostic only; they are not in "
            "the equal-budget model feature sets.",
        ],
        [
            "Merge and provenance",
            "merge_collector_csvs.py combines telemetry.csv and ebpf_events.csv. Rows carry record_type, sample artifact, "
            "sample status, run ID, source file, and eBPF status so windows and raw events remain distinguishable.",
        ],
    ]
    story.append(make_table(collector_rows, [1.65 * inch, 9.8 * inch], styles))
    story.append(
        Paragraph(
            "Boundary: this malware evaluation uses sandbox tcpdump plus bpftrace telemetry. It is not a live Tofino/P4 "
            "hardware benchmark and does not claim that the separate P4 + HostMon collector produced these model inputs.",
            styles["SmallNote"],
        )
    )

    add_section(story, "4. Feature Engineering and Model Scoring", styles)
    story.append(
        Paragraph(
            "The comparison selects nine network signal families and nine host/eBPF signal families. Each window-level "
            "signal is aggregated to one sample row using mean, maximum, sum, standard deviation, and active-window count: "
            "45 features per sensor and 90 hybrid features.",
            styles["BodyCompact"],
        )
    )
    feature_rows = [
        ["Network signal families", "Host/eBPF signal families"],
        [
            "Captured bytes; bytes/second; received bytes; sent bytes; flow count; captured packets; packets/second; "
            "received packets; sent packets.",
            "connect calls; successful pwrite64; write bytes; successful write; successful writev; successful openat2; "
            "successful openat; sendto; socket calls.",
        ],
    ]
    story.append(make_table(feature_rows, [5.7 * inch, 5.7 * inch], styles))
    story.append(
        Paragraph(
            "The learner uses median imputation followed by a 500-tree Random Forest (sqrt feature sampling, minimum leaf "
            "size 2, balanced_subsample class weights). Five-fold StratifiedGroupKFold uses seed 42 and keeps every malware "
            "signature and benign package family in one fold. The current 362-row evaluation has 57 groups and the report "
            "builder verifies no group crosses folds.",
            styles["BodyCompact"],
        )
    )
    story.append(
        Paragraph(
            "For each held-out sample, probability_malware is the model's class-1 probability. The reported binary decision "
            "uses threshold 0.50: score >= 0.50 is predicted malware. These are out-of-fold ranking/classification scores, "
            "not calibrated estimates of operational risk. Malware labels come from cohort provenance, not run outcome.",
            styles["BodyCompact"],
        )
    )

    add_section(story, "5. Overall Results", styles)
    metric_rows = [["Feature set", "Features", "Accuracy", "Balanced acc.", "Precision", "Recall", "F1", "ROC-AUC", "TN", "FP", "FN", "TP"]]
    for feature_set in ("network", "host", "hybrid"):
        result = metric_sets[feature_set]
        score = result["pooled_oof"]
        metric_rows.append(
            [
                FEATURE_SET_NAMES[feature_set],
                result["feature_count"],
                percent(score["accuracy"]),
                percent(score["balanced_accuracy"]),
                percent(score["precision"]),
                percent(score["recall"]),
                percent(score["f1"]),
                percent(score["roc_auc"]),
                score["tn"],
                score["fp"],
                score["fn"],
                score["tp"],
            ]
        )
    story.append(
        make_table(
            metric_rows,
            [1.02 * inch, 0.58 * inch, 0.77 * inch, 0.9 * inch, 0.74 * inch, 0.65 * inch, 0.55 * inch, 0.72 * inch, 0.38 * inch, 0.38 * inch, 0.38 * inch, 0.38 * inch],
            styles,
        )
    )
    story.append(
        Paragraph(
            "Hybrid pooled out-of-fold confusion counts are 129 true negatives, 9 false positives, 17 false negatives, "
            "and 207 true positives. Compared with host-only, hybrid has the same false-positive count and five fewer "
            "malware misses. Network-only is weaker on this cohort.",
            styles["BodyCompact"],
        )
    )
    host_fold = metric_sets["host"]["fold_mean"]
    hybrid_fold = metric_sets["hybrid"]["fold_mean"]
    story.append(
        Paragraph(
            f"Stability check: fold-mean accuracy is {percent(host_fold['accuracy'])} for host-only and "
            f"{percent(hybrid_fold['accuracy'])} for hybrid; fold-mean F1 is {percent(host_fold['f1'])} and "
            f"{percent(hybrid_fold['f1'])}, respectively. The pooled ranking is not uniform across folds, so the "
            "1.1-point pooled balanced-accuracy gain should be considered exploratory. No confidence interval or "
            "external validation set is reported here.",
            styles["SmallNote"],
        )
    )

    add_section(story, "6. Results by Metadata Malware Type", styles)
    category_result_rows = [["Metadata type", "Modelled", "Detected", "Missed", "Recall", "Mean malware score"]]
    for category in CATEGORY_ORDER:
        result = category_metrics[category]
        category_result_rows.append(
            [
                CATEGORY_NAMES[category],
                result["samples"],
                result["detected"],
                result["missed"],
                percent(float(result["recall"])),
                percent(float(result["mean_malware_score"])),
            ]
        )
    story.append(
        make_table(
            category_result_rows,
            [2.3 * inch, 1.0 * inch, 1.0 * inch, 1.0 * inch, 1.0 * inch, 1.65 * inch],
            styles,
        )
    )
    story.append(
        Paragraph(
            "These are slices of the global hybrid model's out-of-fold predictions, not separately trained malware-type "
            "classifiers or multiclass predictions. The two-sample Trojan result is especially uncertain. MalwareBazaar "
            "signatures can span multiple metadata types; taxonomy is not an independent behavior label.",
            styles["SmallNote"],
        )
    )

    top_rows = [["Hybrid feature", "Importance"]]
    for row in inputs["importance"][:6]:
        feature = row["feature"].removeprefix("host__").removeprefix("network__").replace("__", " / ").replace("_", " ")
        top_rows.append([feature, percent(float(row["importance"]))])
    story.append(Paragraph("Largest hybrid feature importances", styles["Subheading"]))
    story.append(make_table(top_rows, [3.5 * inch, 1.15 * inch], styles))
    story.append(
        Paragraph(
            "The highest-ranked individual features are successful openat counts and successful write-byte measures. "
            "Mean, sum, and maximum of the same base signal are correlated summaries; impurity importance is descriptive, "
            "not evidence of causal behavior.",
            styles["SmallNote"],
        )
    )

    add_section(story, "7. Strategic Interpretation and Next Work", styles)
    add_bullet(
        story,
        "Keep the hybrid path, but validate the gain.",
        "It gives the best pooled result and fewer misses than host-only here, but the margin is small and fold means vary. "
        "Repeat on additional family-held-out cohorts and report uncertainty before presenting it as a general advantage.",
        styles,
    )
    add_bullet(
        story,
        "Broaden benign coverage.",
        "The 138 controls are generated Linux command workloads grouped into 28 package families. Add independently collected "
        "ordinary host/service activity and more workload families to test false-positive behavior outside this control mix.",
        styles,
    )
    add_bullet(
        story,
        "Close collection gaps.",
        "The seven acquisitions without usable telemetry are four botnet, two DDoS, and one other-ELF sample. Improve "
        "architecture compatibility and output-transfer reliability, then recapture only from a verified clean snapshot.",
        styles,
    )
    add_bullet(
        story,
        "Separate metadata from behavior.",
        "Preserve source signatures and category tags as provenance, while adding independent behavioral review if type-level "
        "claims are required. Avoid interpreting category slices as a multiclass detector.",
        styles,
    )
    add_bullet(
        story,
        "Keep the hardware claim bounded.",
        "Current network features are packet-capture aggregates intended to resemble implementable counters. A separate "
        "P4/HostMon integration and live target evaluation remain future validation, not a result of this dataset run.",
        styles,
    )

    story.append(Paragraph("Evidence base", styles["Subheading"]))
    story.append(
        Paragraph(
            "Latest dataset: data/malware/revision4/family-heldout-balanced-224-v1-20261014/. "
            "Evaluation: reports/balanced_9network_9host/recomputed_20261015/cv_metrics.json. "
            "Per-sample type/source/scores: reports/balanced_9network_9host/recomputed_20261015/category_analysis/sample_predictions.csv. "
            "Acquisition and collection status: data/malware/malware_sample_inventory_all_expansions_20261014.csv. "
            "Collection implementation: scripts/vbox_malware_batch.sh, src/malware_runner.py, and scripts/merge_collector_csvs.py.",
            styles["SmallNote"],
        )
    )

    story.append(PageBreak())
    add_section(story, "Appendix A. All Acquired Samples by Type and Source", styles)
    story.append(
        Paragraph(
            "Every acquired sample is listed once by SHA-256. Type and family are source metadata; source is the acquisition "
            "cohort. The 224 scored rows include an out-of-fold hybrid malware score and binary decision. The remaining seven "
            "are explicitly marked not scored; their run/collection status is shown for triage. A missed sample is a false "
            "negative at the fixed 0.50 threshold, not a change to its malware label.",
            styles["BodyCompact"],
        )
    )

    source_category_rows = [["Type", *[SOURCE_NAMES[source] for source in SOURCE_ORDER], "Total"]]
    for category in CATEGORY_ORDER:
        source_category_rows.append(
            [CATEGORY_NAMES[category]]
            + [category_source_counts[(category, source)] for source in SOURCE_ORDER]
            + [acquired_by_category[category]]
        )
    source_category_rows.append(
        ["Total"]
        + [acquisition_counts[source] for source in SOURCE_ORDER]
        + [len(samples)]
    )
    story.append(
        make_table(
            source_category_rows,
            [1.0 * inch, 1.62 * inch, 1.62 * inch, 1.62 * inch, 1.62 * inch, 1.62 * inch, 0.55 * inch],
            styles,
        )
    )
    story.append(Spacer(1, 0.08 * inch))

    sample_rows = [["Type", "Family/signature", "Source cohort", "SHA-256", "Execution / collection", "Hybrid OOF score / decision"]]
    source_rank = {source: index for index, source in enumerate(SOURCE_ORDER)}
    sorted_samples = sorted(
        samples,
        key=lambda sample: (
            CATEGORY_ORDER.index(sample["category"]) if sample["category"] in CATEGORY_ORDER else len(CATEGORY_ORDER),
            source_rank.get(sample["source"], len(SOURCE_ORDER)),
            sample["family"].casefold(),
            sample["sha256"],
        ),
    )
    for sample in sorted_samples:
        category = CATEGORY_NAMES.get(sample["category"], sample["category"].replace("_", " ").title())
        if sample["modelled"]:
            outcome = "Detected (TP)" if sample["prediction"] == 1 else "Missed (FN)"
            score_text = f"{sample['score']:.3f} / {outcome}"
            execution = sample["run_status"]
        else:
            score_text = "Not scored"
            execution = sample["collection_status"] or sample["run_status"]
        sample_rows.append(
            [
                category,
                sample["family"],
                SOURCE_NAMES.get(sample["source"], sample["source"]),
                sample["sha256"],
                execution,
                score_text,
            ]
        )
    story.append(
        make_table(
            sample_rows,
            [0.9 * inch, 1.35 * inch, 1.75 * inch, 3.7 * inch, 1.65 * inch, 1.5 * inch],
            styles,
            hash_columns=(3,),
        )
    )

    doc.build(story, onFirstPage=page_chrome, onLaterPages=page_chrome)
    if not OUTPUT.is_file() or OUTPUT.stat().st_size < 20_000:
        raise RuntimeError("The generated PDF is missing or unexpectedly small")
    return OUTPUT


def main() -> int:
    from generate_ali_report import main as compact_report_main

    return compact_report_main()


if __name__ == "__main__":
    raise SystemExit(main())