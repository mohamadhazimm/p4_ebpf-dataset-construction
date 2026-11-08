#!/usr/bin/env python3
"""Build a concise, model-focused PDF from the latest completed evaluation."""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.graphics import renderPDF
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Flowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
COHORT = ROOT / "data/malware/revision4/family-heldout-balanced-224-v1-20261014"
RESULTS = COHORT / "reports/balanced_9network_9host/recomputed_20261015"
CATEGORY_RESULTS = RESULTS / "category_analysis"
DATASET = COHORT / "labeled_sample_dataset_full_35host_9network.csv"
METRICS = RESULTS / "cv_metrics.json"
OOF = RESULTS / "out_of_fold_predictions.csv"
CATEGORY_SCORES = CATEGORY_RESULTS / "overall_and_category_scores.csv"
CATEGORY_METRICS = CATEGORY_RESULTS / "category_metrics.csv"
OUTPUT = ROOT / "reports/ali_report.pdf"

INK = colors.HexColor("#18323A")
TEAL = colors.HexColor("#087E83")
CORAL = colors.HexColor("#D66B4D")
GOLD = colors.HexColor("#C58A2A")
PALE = colors.HexColor("#EAF3F1")
GRAY = colors.HexColor("#66767A")
GRID = colors.HexColor("#D6DEDE")
ROW = colors.HexColor("#F3F6F5")
WHITE = colors.white

MODELS = ("network", "host", "hybrid")
MODEL_NAMES = {"network": "Network", "host": "Host / eBPF", "hybrid": "Hybrid"}
MODEL_COLORS = {"network": TEAL, "host": CORAL, "hybrid": GOLD}
CATEGORIES = ("backdoor", "botnet", "ddos", "other_elf", "ransomware", "trojan")
CATEGORY_NAMES = {
    "backdoor": "Backdoor",
    "botnet": "Botnet",
    "ddos": "DDoS",
    "other_elf": "Other ELF",
    "ransomware": "Ransomware",
    "trojan": "Trojan",
}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as source:
        return list(csv.DictReader(source))


def read_inputs() -> dict:
    with METRICS.open(encoding="utf-8") as source:
        summary = json.load(source)
    dataset = read_csv(DATASET)
    oof_rows = read_csv(OOF)
    category_scores = read_csv(CATEGORY_SCORES)
    category_metrics = read_csv(CATEGORY_METRICS)

    class_counts = Counter(row["class_name"] for row in dataset)
    if class_counts != Counter({"malware": 224, "benign": 138}):
        raise ValueError(f"Unexpected evaluation cohort: {dict(class_counts)}")
    if set(summary["feature_sets"]) != set(MODELS):
        raise ValueError("Expected network, host, and hybrid model metrics")
    if len(oof_rows) != len(dataset) * len(MODELS):
        raise ValueError("Out-of-fold predictions do not cover all models and samples")

    folds_by_artifact: dict[str, set[str]] = {}
    for row in oof_rows:
        folds_by_artifact.setdefault(row["sample_artifact"], set()).add(row["fold"])
    groups_by_id: dict[str, set[str]] = {}
    for row in dataset:
        if row["sample_artifact"] not in folds_by_artifact:
            raise ValueError(f"Missing out-of-fold prediction: {row['sample_artifact']}")
        groups_by_id.setdefault(row["group_id"], set()).update(
            folds_by_artifact[row["sample_artifact"]]
        )
    if any(len(folds) != 1 for folds in groups_by_id.values()):
        raise ValueError("A malware signature or benign package group crosses folds")

    overall = {
        row["feature_set"]: row
        for row in category_scores
        if row["score_scope"] == "overall"
    }
    by_category = {
        (row["category"], row["feature_set"]): row
        for row in category_scores
        if row["score_scope"] == "attack_category_vs_benign"
    }
    category_detection = {
        row["category"]: row
        for row in category_metrics
        if row["feature_set"] == "hybrid"
    }
    if set(overall) != set(MODELS):
        raise ValueError("Overall scores are missing a model")
    if set(by_category) != {(category, model) for category in CATEGORIES for model in MODELS}:
        raise ValueError("Category scores are missing one or more model/category pairs")
    if set(category_detection) != set(CATEGORIES):
        raise ValueError("Hybrid category detection counts are incomplete")

    for model in MODELS:
        metric = summary["feature_sets"][model]["pooled_oof"]
        recorded = overall[model]
        for field in ("accuracy", "balanced_accuracy", "precision", "recall", "f1", "roc_auc"):
            if abs(float(recorded[field]) - float(metric[field])) > 1e-9:
                raise ValueError(f"Mismatch between model summary and category report: {model}/{field}")

    return {
        "summary": summary,
        "overall": overall,
        "by_category": by_category,
        "category_detection": category_detection,
        "malware_count": class_counts["malware"],
        "benign_count": class_counts["benign"],
        "group_count": len(groups_by_id),
    }


def pct(value: float) -> str:
    return f"{100 * value:.1f}%"


def styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ReportTitle", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=26, leading=29, textColor=INK, alignment=TA_LEFT, spaceAfter=3,
        ),
        "subtitle": ParagraphStyle(
            "Subtitle", parent=base["Normal"], fontName="Helvetica",
            fontSize=11, leading=14, textColor=GRAY, spaceAfter=7,
        ),
        "section": ParagraphStyle(
            "Section", parent=base["Heading2"], fontName="Helvetica-Bold",
            fontSize=13, leading=16, textColor=TEAL, spaceBefore=7, spaceAfter=4,
            keepWithNext=True,
        ),
        "body": ParagraphStyle(
            "Body", parent=base["BodyText"], fontName="Helvetica",
            fontSize=8.5, leading=11.3, textColor=INK, spaceAfter=4,
        ),
        "note": ParagraphStyle(
            "Note", parent=base["BodyText"], fontName="Helvetica",
            fontSize=7, leading=9, textColor=GRAY, spaceAfter=3,
        ),
        "cell": ParagraphStyle(
            "Cell", parent=base["BodyText"], fontName="Helvetica",
            fontSize=7.2, leading=8.5, textColor=INK,
        ),
        "header": ParagraphStyle(
            "Header", parent=base["BodyText"], fontName="Helvetica-Bold",
            fontSize=7, leading=8.4, textColor=WHITE,
        ),
        "kpi": ParagraphStyle(
            "Kpi", parent=base["Normal"], fontName="Helvetica",
            fontSize=7.2, leading=9, textColor=INK, alignment=TA_CENTER,
        ),
    }


def text_cell(value, style):
    return Paragraph(escape(str(value)), style)


def make_table(rows, widths, sheet, *, highlight_rows=()):
    data = []
    for index, row in enumerate(rows):
        style = sheet["header"] if index == 0 else sheet["cell"]
        data.append([text_cell(value, style) for value in row])
    table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), INK),
        ("GRID", (0, 0), (-1, -1), 0.35, GRID),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for index in range(1, len(rows)):
        commands.append(("BACKGROUND", (0, index), (-1, index), WHITE if index % 2 else ROW))
    for index in highlight_rows:
        commands.append(("BACKGROUND", (0, index), (-1, index), PALE))
    table.setStyle(TableStyle(commands))
    return table


def kpi_strip(values, widths, sheet):
    data = [[
        Paragraph(
            f"<font size='19' color='{TEAL.hexval()}'><b>{escape(value)}</b></font><br/>{escape(label)}",
            sheet["kpi"],
        )
        for value, label in values
    ]]
    table = Table(data, colWidths=widths, rowHeights=[0.54 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), PALE),
                ("BOX", (0, 0), (-1, -1), 0.5, GRID),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, WHITE),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


class ChartFlowable(Flowable):
    def __init__(self, drawing: Drawing, width: float, height: float):
        super().__init__()
        self.drawing = drawing
        self.width = width
        self.height = height

    def draw(self):
        renderPDF.draw(self.drawing, self.canv, 0, 0)


def grouped_bar_chart(title, category_names, metrics, width, height):
    drawing = Drawing(width, height)
    drawing.add(String(0, height - 12, title, fontName="Helvetica-Bold", fontSize=9, fillColor=INK))

    chart = VerticalBarChart()
    chart.x = 42
    chart.y = 31
    chart.width = width - 155
    chart.height = height - 62
    chart.data = [[float(value) for value in metrics[model]] for model in MODELS]
    chart.categoryAxis.categoryNames = category_names
    chart.categoryAxis.labels.fontName = "Helvetica"
    chart.categoryAxis.labels.fontSize = 6.4
    chart.categoryAxis.labels.fillColor = INK
    chart.categoryAxis.strokeColor = GRID
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = 1.0
    chart.valueAxis.valueStep = 0.2
    chart.valueAxis.labelTextFormat = "%.1f"
    chart.valueAxis.labels.fontName = "Helvetica"
    chart.valueAxis.labels.fontSize = 6.5
    chart.valueAxis.labels.fillColor = GRAY
    chart.valueAxis.strokeColor = GRID
    chart.valueAxis.gridStrokeColor = GRID
    chart.valueAxis.gridStrokeWidth = 0.4
    chart.barWidth = 9 if len(category_names) > 3 else 15
    chart.groupSpacing = 8
    for index, model in enumerate(MODELS):
        chart.bars[index].fillColor = MODEL_COLORS[model]
        chart.bars[index].strokeColor = MODEL_COLORS[model]
    drawing.add(chart)

    legend = Legend()
    legend.x = width - 100
    legend.y = height / 2 + 7
    legend.fontName = "Helvetica"
    legend.fontSize = 7
    legend.dx = 8
    legend.dy = 8
    legend.deltay = 12
    legend.colorNamePairs = [(MODEL_COLORS[model], MODEL_NAMES[model]) for model in MODELS]
    drawing.add(legend)
    return ChartFlowable(drawing, width, height)


def draw_page(canvas, doc):
    canvas.saveState()
    page_width, page_height = doc.pagesize
    canvas.setStrokeColor(GRID)
    canvas.setLineWidth(0.5)
    canvas.line(doc.leftMargin, page_height - 0.38 * inch, page_width - doc.rightMargin, page_height - 0.38 * inch)
    canvas.setFont("Helvetica-Bold", 7)
    canvas.setFillColor(TEAL)
    canvas.drawString(doc.leftMargin, page_height - 0.29 * inch, "MALWARE DETECTION | MODEL COMPARISON")
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(GRAY)
    canvas.drawString(doc.leftMargin, 0.25 * inch, "Evaluation: 15 October 2026")
    canvas.drawRightString(page_width - doc.rightMargin, 0.25 * inch, str(doc.page))
    canvas.restoreState()


def create_report(data: dict) -> Path:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    sheet = styles()
    page_size = landscape(letter)
    doc = SimpleDocTemplate(
        str(OUTPUT),
        pagesize=page_size,
        leftMargin=0.48 * inch,
        rightMargin=0.48 * inch,
        topMargin=0.53 * inch,
        bottomMargin=0.42 * inch,
        title="Ali Report: Malware Detection Model Comparison",
        author="Malware Detection Study",
        subject="Latest completed three-model evaluation",
    )
    content_width = page_size[0] - doc.leftMargin - doc.rightMargin
    story = []
    summary = data["summary"]["feature_sets"]

    story.append(Spacer(1, 0.08 * inch))
    story.append(Paragraph("Malware Lab and Detection Results", sheet["title"]))
    story.append(Paragraph("Two-VM isolated collection | latest completed evaluation", sheet["subtitle"]))
    story.append(Paragraph("Malware lab setup", sheet["section"]))
    vm_rows = [
        ["Virtual machine", "Role and network setup"],
        [
            "Ubuntu-Clean-24.04\nMalware VM",
            "Runs one staged sample from a clean snapshot. Its enabled network adapter is restricted to the internal "
            "malnet network; NAT, bridged, and host-only networking are rejected.",
        ],
        [
            "Sink\nNetwork-services VM",
            "Runs INetSim and local DNS on the same internal network to emulate services a sample may try to reach. "
            "The malware guest has no direct public-network adapter.",
        ],
    ]
    story.append(make_table(vm_rows, [1.8 * inch, content_width - 1.8 * inch], sheet))
    story.append(Spacer(1, 0.04 * inch))
    story.append(
        Paragraph(
            "<b>Sample acquisition.</b> Linux ELF candidates were queried from MalwareBazaar. The downloader records "
            "metadata, deduplicates by SHA-256, downloads encrypted archives, and verifies archive hashes before staging. "
            "Archives are extracted inside the isolated guest, not on the host.",
            sheet["body"],
        )
    )
    story.append(
        Paragraph(
            "<b>Batch automation.</b> <font name='Courier'>vbox_malware_batch.sh</font> checks VM isolation, restores "
            "the clean snapshot before each sample, checks architecture, then invokes <font name='Courier'>malware_runner.py</font> "
            "with a 20-second limit. Resume mode skips completed captures. The script packages each run's output and copies "
            "it back to the host; cleanup restores the clean snapshot again.",
            sheet["body"],
        )
    )
    story.append(
        Paragraph(
            "<b>Collectors and CSV.</b> tcpdump captures a per-run PCAP while bpftrace/eBPF records sample-process "
            "syscalls. The runner emits 0.5-second telemetry windows; <font name='Courier'>merge_collector_csvs.py</font> "
            "combines window telemetry and raw eBPF events with sample/run provenance. The model compares aggregate "
            "network features, host features, and both together.",
            sheet["body"],
        )
    )

    lab_story = story
    story = []
    story.append(Paragraph("Overall model comparison", sheet["section"]))

    overall_rows = [["Model", "Features", "Accuracy", "Balanced accuracy", "Precision", "Recall", "F1", "ROC-AUC", "TN", "FP", "FN", "TP"]]
    for model in MODELS:
        values = summary[model]["pooled_oof"]
        overall_rows.append(
            [
                MODEL_NAMES[model],
                summary[model]["feature_count"],
                pct(values["accuracy"]),
                pct(values["balanced_accuracy"]),
                pct(values["precision"]),
                pct(values["recall"]),
                pct(values["f1"]),
                pct(values["roc_auc"]),
                values["tn"],
                values["fp"],
                values["fn"],
                values["tp"],
            ]
        )
    overall_widths = [1.05 * inch, 0.62 * inch, 0.77 * inch, 1.05 * inch, 0.8 * inch, 0.68 * inch, 0.58 * inch, 0.75 * inch, 0.42 * inch, 0.42 * inch, 0.42 * inch, 0.42 * inch]
    story.append(make_table(overall_rows, overall_widths, sheet, highlight_rows=(3,)))
    story.append(Spacer(1, 0.04 * inch))

    overall_chart_data = {
        model: [
            summary[model]["pooled_oof"][metric]
            for metric in ("accuracy", "balanced_accuracy", "precision", "recall", "f1", "roc_auc")
        ]
        for model in MODELS
    }
    story.append(
        grouped_bar_chart(
            "Out-of-fold performance (0–1)",
            ["Accuracy", "Balanced\naccuracy", "Precision", "Recall", "F1", "ROC-AUC"],
            overall_chart_data,
            content_width,
            1.9 * inch,
        )
    )

    hybrid = summary["hybrid"]["pooled_oof"]
    host = summary["host"]["pooled_oof"]
    network = summary["network"]["pooled_oof"]
    story.append(Paragraph("What the comparison says", sheet["section"]))
    story.append(
        Paragraph(
            f"Hybrid leads this evaluation at {pct(hybrid['balanced_accuracy'])} balanced accuracy and "
            f"{pct(hybrid['roc_auc'])} ROC-AUC. Against host/eBPF, it improves balanced accuracy by "
            f"{100 * (hybrid['balanced_accuracy'] - host['balanced_accuracy']):.1f} percentage points and "
            f"reduces malware misses from {host['fn']} to {hybrid['fn']} while keeping false positives at "
            f"{hybrid['fp']}. Compared with network-only, hybrid improves balanced accuracy by "
            f"{100 * (hybrid['balanced_accuracy'] - network['balanced_accuracy']):.1f} points. This supports "
            "combining host behavior with network activity for this evaluated sample set.",
            sheet["body"],
        )
    )
    story.append(
        Paragraph(
            "Scores are pooled out-of-fold results from five-fold StratifiedGroupKFold (seed 42), with malware signatures "
            "and benign package families kept within a single fold. A 0.50 malware-probability threshold determines FP/FN. "
            "Hybrid uses both 45-feature sensor sets; the single-sensor models use 45 each.",
            sheet["note"],
        )
    )

    overall_story = story
    story = lab_story
    story.append(Spacer(1, 0.04 * inch))
    story.append(Paragraph("Malware types and model detection", sheet["title"]))
    story.append(
        Paragraph(
            "The 224 evaluated malware samples are grouped by metadata type. The following tables show type coverage, "
            "then how accurately each binary model separates one type from benign controls.",
            sheet["subtitle"],
        )
    )

    count_rows = [["Malware type", "Samples", "Share of malware set"]]
    for category in CATEGORIES:
        count = int(data["category_detection"][category]["samples"])
        count_rows.append([CATEGORY_NAMES[category], count, pct(count / data["malware_count"])])
    count_rows.append(["Total", data["malware_count"], "100.0%"])
    story.append(Paragraph("Samples by family type", sheet["section"]))
    story.append(make_table(count_rows, [2.3 * inch, 1.0 * inch, 1.6 * inch], sheet))
    story.append(Spacer(1, 0.08 * inch))

    category_rows = [["Malware type", "N", "Network acc.", "Host acc.", "Hybrid acc.", "Network recall", "Host recall", "Hybrid recall"]]
    for category in CATEGORIES:
        category_rows.append(
            [
                CATEGORY_NAMES[category],
                data["category_detection"][category]["samples"],
                *[pct(float(data["by_category"][(category, model)]["accuracy"])) for model in MODELS],
                *[pct(float(data["by_category"][(category, model)]["recall"])) for model in MODELS],
            ]
        )
    widths = [1.05 * inch, 0.42 * inch, 0.9 * inch, 0.85 * inch, 0.9 * inch, 0.96 * inch, 0.9 * inch, 0.96 * inch]
    story.append(Paragraph("Accuracy and detection rate by type", sheet["section"]))
    story.append(make_table(category_rows, widths, sheet))
    story.append(Spacer(1, 0.08 * inch))
    story.append(
        Paragraph(
            "For each row, accuracy and recall are calculated for that malware type versus the same 138 benign controls; "
            "other malware types are excluded from that comparison. These are slices of each global binary model, not "
            "separately trained malware-type classifiers. Type labels come from MalwareBazaar metadata. The Trojan result "
            "has only two samples and should be treated cautiously.",
            sheet["body"],
        )
    )

    story.append(PageBreak())
    story.extend(overall_story)

    doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    if not OUTPUT.is_file() or OUTPUT.stat().st_size < 5_000:
        raise RuntimeError("The generated PDF is missing or unexpectedly small")
    return OUTPUT


def main() -> int:
    data = read_inputs()
    output = create_report(data)
    print(
        json.dumps(
            {
                "output": str(output),
                "bytes": output.stat().st_size,
                "evaluation_samples": data["malware_count"] + data["benign_count"],
                "malware_samples": data["malware_count"],
                "benign_controls": data["benign_count"],
                "held_out_groups": data["group_count"],
                "models": list(MODELS),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())