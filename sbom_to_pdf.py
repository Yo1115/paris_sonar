#!/usr/bin/env python3
"""
sbom_to_pdf.py
將 CycloneDX 格式的 SBOM JSON 檔案轉換為排版精美的 PDF 報告。
不依賴任何 AI model，使用 fpdf2 與 Python 標準函式庫。
支援 Windows / Linux / macOS。

相依套件：
    pip install fpdf2

字型（擇一即可，程式會自動搜尋）：
  Windows : 微軟正黑體（系統內建，不需額外安裝）
  Linux   : Noto Sans CJK TC（sudo apt install fonts-noto-cjk）
  macOS   : PingFang TC（系統內建）
  通用    : 將 NotoSansTC-Regular.ttf / NotoSansTC-Bold.ttf 放在程式同目錄

用法：
    python sbom_to_pdf.py <input.json> [output.pdf]
"""

import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone

from fpdf import FPDF
from fpdf.enums import XPos, YPos


# ── 字型搜尋 ──────────────────────────────────────────────────────────────────

FONT_CANDIDATES = {
    "regular": [
        # 同目錄 TTF（優先，使用者可自行放置）
        "NotoSansTC-Regular.ttf",
        # Windows 微軟正黑體
        r"C:\Windows\Fonts\msjh.ttc",
        r"C:\Windows\Fonts\msjhl.ttc",
        # Windows Noto（若已安裝）
        r"C:\Windows\Fonts\NotoSansTC-Regular.ttf",
        # Linux Noto CJK
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
        # macOS
        "/System/Library/Fonts/PingFang.ttc",
        "/Library/Fonts/NotoSansTC-Regular.ttf",
    ],
    "bold": [
        "NotoSansTC-Bold.ttf",
        r"C:\Windows\Fonts\msjhbd.ttc",
        r"C:\Windows\Fonts\NotoSansTC-Bold.ttf",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc",
        "/usr/share/fonts/truetype/noto/NotoSansCJK-Bold.ttc",
        "/usr/share/fonts/noto-cjk/NotoSansCJK-Bold.ttc",
        "/System/Library/Fonts/PingFang.ttc",
        "/Library/Fonts/NotoSansTC-Bold.ttf",
    ],
}

def find_font(style: str) -> str:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    for path in FONT_CANDIDATES[style]:
        full = path if os.path.isabs(path) else os.path.join(script_dir, path)
        if os.path.exists(full):
            return full
    raise FileNotFoundError(
        f"找不到中文字型（{style}）。\n"
        "解決方式（擇一）：\n"
        "  1. 將 NotoSansTC-Regular.ttf 與 NotoSansTC-Bold.ttf 放在程式同目錄\n"
        "     下載：https://fonts.google.com/noto/specimen/Noto+Sans+TC\n"
        "  2. Linux：sudo apt install fonts-noto-cjk\n"
        "  3. Windows：系統通常內建微軟正黑體，若仍找不到請確認路徑"
    )


# ── 色彩 ─────────────────────────────────────────────────────────────────────

C_PRIMARY   = (45,  55,  72)    # 深藍灰
C_ACCENT    = (74, 111, 212)    # 藍
C_SUCCESS   = (47, 133,  90)    # 綠
C_WARNING   = (192,  86,  33)   # 橘
C_DANGER    = (197,  48,  48)   # 紅
C_MUTED     = (113, 128, 150)   # 灰
C_TH_BG     = (235, 244, 255)   # 表頭淡藍
C_ROW_ALT   = (247, 250, 252)   # 交替列極淡灰
C_BORDER    = (203, 213, 224)   # 邊框
C_CODE_BG   = (240, 244, 248)   # 程式碼背景
C_DIVIDER   = (226, 232, 240)   # 分隔線
C_PAGE_BG   = (255, 255, 255)


# ── JSON 解析 ─────────────────────────────────────────────────────────────────

def load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def extract_licenses(component: dict) -> str:
    names = []
    for entry in component.get("licenses", []):
        lic = entry.get("license", {})
        names.append(lic.get("id") or lic.get("name") or "Unknown")
    return ", ".join(names) if names else "-"

def build_dep_map(dependencies: list) -> dict:
    return {d["ref"]: d.get("dependsOn", []) for d in dependencies}

def find_direct_deps(metadata_ref: str, dep_map: dict) -> list:
    direct = []
    for ref in dep_map.get(metadata_ref, []):
        direct.extend(dep_map.get(ref, []))
    return direct

def build_reverse_map(dep_map: dict) -> dict:
    rev = defaultdict(list)
    for ref, deps in dep_map.items():
        for d in deps:
            rev[d].append(ref)
    return rev

def build_tree_lines(ref: str, dep_map: dict, comp_map: dict,
                     prefix: str = "", visited: set = None) -> list:
    if visited is None:
        visited = set()
    lines = []
    children = dep_map.get(ref, [])
    for i, child in enumerate(children):
        is_last   = (i == len(children) - 1)
        connector = "\u2514\u2500\u2500 " if is_last else "\u251c\u2500\u2500 "
        ext       = "    "               if is_last else "\u2502   "
        c       = comp_map.get(child, {})
        name    = c.get("name", child)
        version = c.get("version", "")
        label   = f"{name}@{version}" if version else name
        suffix  = " (shared)" if child in visited else ""
        lines.append(f"{prefix}{connector}{label}{suffix}")
        if child not in visited:
            visited.add(child)
            lines.extend(build_tree_lines(child, dep_map, comp_map,
                                          prefix + ext, visited))
    return lines

LICENSE_RISK = {
    "low":    {"MIT","ISC","BSD-2-Clause","BSD-3-Clause","Apache-2.0","0BSD","Unlicense","CC0-1.0"},
    "medium": {"LGPL-2.0","LGPL-2.1","LGPL-3.0","MPL-2.0","CDDL-1.0"},
    "high":   {"GPL-2.0","GPL-3.0","AGPL-3.0","EUPL-1.1","EUPL-1.2"},
}
LICENSE_NOTES = {
    "MIT":          "最寬鬆，允許商業使用，需保留著作權聲明",
    "ISC":          "功能同 MIT，措辭更簡潔",
    "Apache-2.0":   "允許商業使用，含專利授權條款",
    "BSD-2-Clause": "寬鬆，無廣告條款",
    "BSD-3-Clause": "寬鬆，禁止以原作者名義背書",
    "LGPL-2.1":     "含 Copyleft，需動態連結或開放修改部分",
    "LGPL-3.0":     "同 LGPL-2.1，附 GPL-3.0 附加條款",
    "GPL-2.0":      "強 Copyleft，衍生作品須開源",
    "GPL-3.0":      "強 Copyleft，含反 Tivoization 條款",
    "AGPL-3.0":     "最嚴格，網路服務亦須開源",
}

def risk_info(lic: str) -> tuple:
    if lic in LICENSE_RISK["low"]:    return ("低", C_SUCCESS)
    if lic in LICENSE_RISK["medium"]: return ("中", C_WARNING)
    if lic in LICENSE_RISK["high"]:   return ("高", C_DANGER)
    return ("未知", C_WARNING)


# ── PDF 類別 ──────────────────────────────────────────────────────────────────

class SbomPDF(FPDF):
    def __init__(self, font_r: str, font_b: str):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.add_font("TC",  style="",  fname=font_r)
        self.add_font("TC",  style="B", fname=font_b)
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(20, 18, 20)
        self._total_pages = 0
        self._table_header_meta = None

    # 頁眉 / 頁尾
    def header(self):
        pass

    def footer(self):
        self.set_y(-13)
        self.set_font("TC", size=7.5)
        self.set_text_color(*C_MUTED)
        self.cell(0, 5, f"{self.page_no()} / {{nb}}", align="C")

    def _usable_bottom(self) -> float:
        return self.h - self.b_margin

    def ensure_space(self, needed_height: float) -> bool:
        if self.get_y() + needed_height > self._usable_bottom():
            self.add_page()
            return True
        return False

    # 工具方法
    def h_rule(self, color=C_DIVIDER, thickness=0.3, space_before=4, space_after=4):
        self.ensure_space(space_before + space_after + 2)
        self.ln(space_before)
        self.set_draw_color(*color)
        self.set_line_width(thickness)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.set_line_width(0.2)
        self.ln(space_after)

    def section_title(self, text: str):
        self.ensure_space(12)
        self.set_font("TC", style="B", size=13)
        self.set_text_color(*C_PRIMARY)
        self.ln(1)
        self.cell(0, 8, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def sub_title(self, text: str):
        self.ensure_space(10)
        self.set_font("TC", style="B", size=10)
        self.set_text_color(*C_ACCENT)
        self.ln(1)
        self.cell(0, 7, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def table_header(self, cols: list, widths: list):
        self._table_header_meta = (list(cols), list(widths))
        self.ensure_space(8)
        self.set_fill_color(*C_TH_BG)
        self.set_draw_color(*C_BORDER)
        self.set_text_color(*C_PRIMARY)
        self.set_font("TC", style="B", size=8)
        for text, w in zip(cols, widths):
            self.cell(w, 7, text, border=1, fill=True,
                      new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.ln()

    def table_row(self, cells: list, widths: list, alt: bool = False,
                  colors: list = None):
        """
        cells  : list of str
        widths : list of float (mm)
        colors : list of RGB tuple or None (per cell text color override)
        """
        self.set_fill_color(*(C_ROW_ALT if alt else C_PAGE_BG))
        self.set_draw_color(*C_BORDER)
        self.set_font("TC", size=8)

        row_colors = colors if colors else [None] * len(cells)

        # 計算行高（支援自動換行）
        line_height = 5.5
        cell_heights = []
        for text, w in zip(cells, widths):
            lines = self._count_lines(text, w - 4)
            cell_heights.append(lines * line_height + 3)
        row_h = max(cell_heights)

        if self.get_y() + row_h > self._usable_bottom():
            self.add_page()
            if self._table_header_meta:
                cols, header_widths = self._table_header_meta
                self.table_header(cols, header_widths)

        x0, y0 = self.get_x(), self.get_y()

        for i, (text, w) in enumerate(zip(cells, widths)):
            # 背景矩形
            self.set_xy(x0 + sum(widths[:i]), y0)
            self.rect(self.get_x(), self.get_y(), w, row_h, style="DF")
            # 文字
            tc = row_colors[i] if row_colors[i] else C_PRIMARY
            self.set_text_color(*tc)
            self.set_xy(x0 + sum(widths[:i]) + 2, y0 + 1.5)
            self.multi_cell(w - 4, line_height, text, border=0, fill=False)

        self.set_xy(x0, y0 + row_h)

    def _count_lines(self, text: str, w: float) -> int:
        """估算 multi_cell 會產生幾行。"""
        if not text:
            return 1
        self.set_font("TC", size=8)
        total_lines = 0
        paragraphs = text.splitlines() or [""]
        for para in paragraphs:
            if not para:
                total_lines += 1
                continue
            line_count = 1
            line_width = 0
            for ch in para:
                ch_w = self.get_string_width(ch)
                if line_width + ch_w <= w:
                    line_width += ch_w
                else:
                    line_count += 1
                    line_width = ch_w
            total_lines += line_count
        return max(total_lines, 1)

    def code_block(self, lines: list):
        """等寬文字區塊（依賴樹用）。"""
        self.set_fill_color(*C_CODE_BG)
        self.set_draw_color(*C_BORDER)
        self.set_font("TC", size=7.5)
        self.set_text_color(*C_PRIMARY)

        line_h = 5
        padding = 3
        block_w = self.w - self.l_margin - self.r_margin
        idx = 0
        while idx < len(lines):
            # Ensure at least one line can be rendered in current page.
            self.ensure_space(line_h + padding * 2)
            available_h = self._usable_bottom() - self.get_y()
            capacity = int((available_h - padding * 2) // line_h)
            capacity = max(capacity, 1)
            chunk = lines[idx:idx + capacity]
            block_h = len(chunk) * line_h + padding * 2

            x0, y0 = self.get_x(), self.get_y()
            self.rect(x0, y0, block_w, block_h, style="DF")

            self.set_xy(x0 + padding, y0 + padding)
            for line in chunk:
                self.cell(block_w - padding * 2, line_h, line,
                          new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                self.set_x(x0 + padding)

            idx += len(chunk)
            self.ln(2)


# ── PDF 建立 ──────────────────────────────────────────────────────────────────

def build_pdf(data: dict, output_path: str):
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # 解析資料
    meta           = data.get("metadata", {})
    bom_format     = data.get("bomFormat", "CycloneDX")
    spec_ver       = data.get("specVersion", "-")
    serial         = data.get("serialNumber", "-")
    scan_time      = meta.get("timestamp", "-")
    tools          = meta.get("tools", {}).get("components", [])
    tool_info      = "-"
    if tools:
        t = tools[0]
        tool_info = (f"{t.get('name','')} {t.get('version','')} "
                     f"({t.get('manufacturer',{}).get('name','')})")
    repo_name = "-"
    properties = meta.get("properties", [])
    if isinstance(properties, list):
        for prop in properties:
            if (
                isinstance(prop, dict)
                and prop.get("name") == "taitra:repo"
                and str(prop.get("value", "")).strip()
            ):
                repo_name = str(prop.get("value")).strip()
                break
    if repo_name == "-":
        component_name = meta.get("component", {}).get("name", "")
        if isinstance(component_name, str) and component_name.strip() not in {"", "."}:
            repo_name = component_name.strip()

    raw_components = data.get("components", [])
    lib_components = [c for c in raw_components if c.get("type") == "library"]
    comp_map       = {c["bom-ref"]: c for c in lib_components}
    dep_map        = build_dep_map(data.get("dependencies", []))
    metadata_ref   = meta.get("component", {}).get("bom-ref", "")
    direct_refs    = find_direct_deps(metadata_ref, dep_map)
    direct_set     = set(direct_refs)
    direct_comps   = [r for r in comp_map if r in direct_set]
    indirect_comps = [r for r in comp_map if r not in direct_set]
    rev_map        = build_reverse_map(dep_map)
    vulns          = data.get("vulnerabilities", [])

    lic_count = defaultdict(int)
    for c in lib_components:
        for l in extract_licenses(c).split(", "):
            lic_count[l] += 1
    lic_summary = "  ".join(f"{k} x{v}" for k, v in lic_count.items())

    # 建立 PDF
    font_r = find_font("regular")
    font_b = find_font("bold")
    print(f"[*] 使用字型：{font_r}")

    pdf = SbomPDF(font_r, font_b)
    pdf.alias_nb_pages()
    pdf.add_page()
    W = pdf.w - pdf.l_margin - pdf.r_margin

    # ── 封面區塊 ────────────────────────────────────────────────────────────
    pdf.set_font("TC", style="B", size=22)
    pdf.set_text_color(*C_PRIMARY)
    pdf.cell(0, 12, "SBOM \u5206\u6790\u5831\u544a",  # SBOM 分析報告
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("TC", size=8.5)
    pdf.set_text_color(*C_MUTED)
    pdf.cell(0, 6, f"程式碼儲存庫：{repo_name}",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, f"\u683c\u5f0f\uff1a{bom_format} {spec_ver}   |   \u6383\u63cf\u5de5\u5177\uff1a{tool_info}",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, f"\u6383\u63cf\u6642\u9593\uff1a{scan_time}   |   \u7522\u751f\u65e5\u671f\uff1a{now_str}",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, f"\u5e8f\u865f\uff1a{serial}",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # 藍色分隔線
    pdf.ln(3)
    pdf.set_draw_color(*C_ACCENT)
    pdf.set_line_width(1.2)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.set_line_width(0.2)
    pdf.ln(5)

    # ── 摘要 ────────────────────────────────────────────────────────────────
    pdf.section_title("摘要")
    vuln_color = C_SUCCESS if not vulns else C_DANGER
    vuln_text  = "0 \u7b46\uff08\u901a\u904e\uff09" if not vulns else f"{len(vulns)} \u7b46\uff08\u8acb\u7acb\u5373\u6aa2\u67e5\uff09"

    cols   = ["\u9805\u76ee", "\u6578\u5024"]           # 項目 / 數值
    widths = [W * 0.38, W * 0.62]
    pdf.table_header(cols, widths)
    rows = [
        ("\u5957\u4ef6\u7e3d\u6578",   f"{len(lib_components)} \u500b"),
        ("\u76f4\u63a5\u4f9d\u8cf4",   f"{len(direct_comps)} \u500b"),
        ("\u9593\u63a5\u4f9d\u8cf4",   f"{len(indirect_comps)} \u500b"),
        ("\u6388\u6b0a\u7a2e\u985e",   lic_summary),
        ("\u5df2\u77e5\u6f0f\u6d1e (CVE)", vuln_text),
    ]
    for i, (label, val) in enumerate(rows):
        vc = vuln_color if i == len(rows) - 1 else None
        pdf.table_row([label, val], widths, alt=(i % 2 == 1),
                      colors=[None, vc])

    pdf.h_rule()

    # ── 直接依賴 ────────────────────────────────────────────────────────────
    pdf.section_title("套件清單")
    pdf.sub_title("直接依賴（Direct Dependencies）")
    cols   = ["\u5957\u4ef6\u540d\u7a31", "\u7248\u672c", "\u6388\u6b0a"]
    widths = [W * 0.52, W * 0.18, W * 0.30]
    pdf.table_header(cols, widths)
    for i, ref in enumerate(direct_comps):
        c = comp_map[ref]
        g = c.get("group", "")
        n = c.get("name", ref)
        d = f"{g}/{n}" if g else n
        pdf.table_row([d, c.get("version","-"), extract_licenses(c)],
                      widths, alt=(i % 2 == 1),
                      colors=[C_ACCENT, None, None])

    pdf.ln(3)
    pdf.sub_title("間接依賴（Transitive Dependencies）")
    cols   = ["\u5957\u4ef6\u540d\u7a31", "\u7248\u672c", "\u6388\u6b0a", "\u88ab\u5f15\u5165\u4f86\u6e90"]
    widths = [W * 0.36, W * 0.14, W * 0.16, W * 0.34]
    pdf.table_header(cols, widths)
    for i, ref in enumerate(indirect_comps):
        c = comp_map.get(ref, {})
        g = c.get("group", "")
        n = c.get("name", ref)
        d = f"{g}/{n}" if g else n
        parents = [comp_map.get(pp, {}).get("name", pp)
                   for pp in rev_map.get(ref, []) if pp in comp_map]
        ps = "、".join(parents) if parents else "-"
        pdf.table_row([d, c.get("version","-"), extract_licenses(c), ps],
                      widths, alt=(i % 2 == 1),
                      colors=[C_ACCENT, None, None, C_MUTED])

    pdf.h_rule()

    # ── 依賴關係樹 ──────────────────────────────────────────────────────────
    pdf.section_title("依賴關係樹")
    tree_lines = ["package-lock.json"]
    visited_tree = set(direct_refs)
    for ref in direct_refs:
        c2   = comp_map.get(ref, {})
        name = c2.get("name", ref)
        ver  = c2.get("version", "")
        lbl  = f"{name}@{ver}" if ver else name
        is_last   = (ref == direct_refs[-1])
        connector = "\u2514\u2500\u2500 " if is_last else "\u251c\u2500\u2500 "
        ext       = "    "               if is_last else "\u2502   "
        tree_lines.append(f"{connector}{lbl}")
        sub = build_tree_lines(ref, dep_map, comp_map,
                               prefix=ext, visited=set(visited_tree))
        tree_lines.extend(sub)
        visited_tree.add(ref)

    pdf.code_block(tree_lines)
    pdf.h_rule()

    # ── 授權合規 ────────────────────────────────────────────────────────────
    pdf.section_title("授權合規分析")
    cols   = ["\u6388\u6b0a", "\u5957\u4ef6\u6578", "\u98a8\u96aa\u7b49\u7d1a", "\u8aaa\u660e"]
    widths = [W * 0.17, W * 0.11, W * 0.12, W * 0.60]
    pdf.table_header(cols, widths)
    for i, (lic, count) in enumerate(lic_count.items()):
        rl, rc = risk_info(lic)
        note   = LICENSE_NOTES.get(lic, "\u8acb\u4eba\u5de5\u78ba\u8a8d")
        pdf.table_row([lic, str(count), rl, note],
                      widths, alt=(i % 2 == 1),
                      colors=[C_ACCENT, None, rc, C_MUTED])

    pdf.h_rule()

    # ── 漏洞掃描 ────────────────────────────────────────────────────────────
    pdf.section_title("漏洞掃描結果")
    if not vulns:
        pdf.set_font("TC", style="B", size=9)
        pdf.set_text_color(*C_SUCCESS)
        pdf.cell(0, 7, "✓ 未發現任何已知安全漏洞（CVE：0 筆）",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("TC", size=8.5)
        pdf.set_text_color(*C_MUTED)
        pdf.multi_cell(0, 6,
            "建議定期重新掃描，新漏洞會持續被揭露。"
            "可整合 trivy 至 CI/CD pipeline，每次部署前自動執行 trivy fs .")
    else:
        pdf.set_font("TC", style="B", size=9)
        pdf.set_text_color(*C_DANGER)
        pdf.cell(0, 7, f"⚠ 發現 {len(vulns)} 筆漏洞，請儘速評估影響範圍。",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)
        cols   = ["CVE ID", "\u56b4\u91cd\u5ea6", "\u5f71\u97ff\u5957\u4ef6", "\u8aaa\u660e"]
        widths = [W * 0.22, W * 0.12, W * 0.28, W * 0.38]
        pdf.table_header(cols, widths)
        for i, v in enumerate(vulns):
            vid  = v.get("id", "-")
            sev  = v.get("ratings",[{}])[0].get("severity","-") if v.get("ratings") else "-"
            aff  = ", ".join(a.get("ref","") for a in v.get("affects",[]))
            desc = v.get("description","-")[:80]
            sc   = C_DANGER if sev in ("critical","high") else C_WARNING
            pdf.table_row([vid, sev, aff, desc],
                          widths, alt=(i % 2 == 1),
                          colors=[C_ACCENT, sc, C_MUTED, C_MUTED])

    pdf.h_rule()

    # ── 建議事項 ────────────────────────────────────────────────────────────
    pdf.section_title("建議事項")
    suggestions = [
        ("定期重新掃描",  "建議整合至 CI/CD pipeline，每次部署前自動執行 trivy fs ."),
        ("版本鎖定",      "已有 package-lock.json，正式部署請使用 npm ci 而非 npm install"),
        ("SBOM 存檔",    "將 SBOM 檔案納入版本控管，作為軟體供應鏈稽核憑證（符合 NTIA 最低要求）"),
        ("授權聲明",      "MIT 套件需在產品中保留著作權聲明（NOTICE 或 LICENSE 檔案）"),
    ]
    cols   = ["\u5efa\u8b70\u9805\u76ee", "\u8aaa\u660e"]
    widths = [W * 0.24, W * 0.76]
    pdf.table_header(cols, widths)
    for i, (title, desc) in enumerate(suggestions):
        pdf.table_row([title, desc], widths, alt=(i % 2 == 1),
                      colors=[None, C_MUTED])

    # ── 頁尾說明 ────────────────────────────────────────────────────────────
    pdf.ln(6)
    pdf.set_draw_color(*C_DIVIDER)
    pdf.set_line_width(0.3)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(3)
    pdf.set_font("TC", size=7.5)
    pdf.set_text_color(*C_MUTED)
    pdf.cell(0, 5,
        f"\u5831\u544a\u7522\u751f\u6642\u9593\uff1a{now_str}   |   "
        "\u7a0b\u5f0f\uff1asbom_to_pdf.py\uff08\u7d14 Python\uff0c\u7121\u9700 AI model\uff09",
        align="C")

    pdf.output(output_path)


# ── 主程式 ────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("用法：python sbom_to_pdf.py <input.json> [output.pdf]")
        sys.exit(1)

    input_path  = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) >= 3 else None
    if output_path is None:
        base        = os.path.splitext(input_path)[0]
        output_path = f"{base}_report.pdf"

    print(f"[*] 讀取：{input_path}")
    data = load_json(input_path)

    print("[*] 產生 PDF 中...")
    build_pdf(data, output_path)

    lib_count  = len([c for c in data.get("components",[]) if c.get("type")=="library"])
    vuln_count = len(data.get("vulnerabilities", []))
    print(f"[✓] PDF 已輸出：{output_path}")
    print(f"    套件數：{lib_count} 個")
    print(f"    漏洞數：{vuln_count} 筆")


if __name__ == "__main__":
    main()
