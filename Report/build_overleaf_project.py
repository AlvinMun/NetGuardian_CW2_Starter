from pathlib import Path
import re
import zipfile


SOURCE = Path(__file__).with_name("Report_Coursework_II.tex")
PROJECT = Path(__file__).with_name("Overleaf_Project")
ARCHIVE = Path(__file__).parents[1] / "Overleaf_NetGuardian.zip"


def write(path, content):
    destination = PROJECT / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content.strip() + "\n", encoding="utf-8")


source = SOURCE.read_text(encoding="utf-8")
cover_match = re.search(r"\\begin\{titlepage\}(.*?)\\end\{titlepage\}", source, re.S)
abstract_match = re.search(r"\\begin\{abstract\}(.*?)\\end\{abstract\}", source, re.S)
keywords_match = re.search(r"\\begin\{IEEEkeywords\}(.*?)\\end\{IEEEkeywords\}", source, re.S)
if not all((cover_match, abstract_match, keywords_match)):
    raise SystemExit("The source report is missing a title page, abstract, or keywords block.")

body_start = source.index(r"\section{Introduction}")
body_end = source.index(r"\begin{thebibliography}")
body = source[body_start:body_end]
markers = list(re.finditer(r"\\section(\*)?\{([^}]*)\}", body))
sections = {}
for index, marker in enumerate(markers):
    end = markers[index + 1].start() if index + 1 < len(markers) else len(body)
    title = marker.group(2)
    star = marker.group(1) or ""
    content = body[marker.end():end].strip()
    content = re.sub(r"\\clearpage\s*$", "", content).strip()
    section_text = "\\section{}{{{}}}\n\n{}".format(star, title, content)
    sections[title] = section_text

required = ["Introduction", "Related Work", "System Design", "Implementation",
            "Testing and Results", "Conclusion", "Acknowledgment"]
missing = [name for name in required if name not in sections]
if missing:
    raise SystemExit("Missing sections: " + ", ".join(missing))

system_design = sections["System Design"]
figure_pattern = re.compile(r"\\begin\{figure\}\[t\].*?\\end\{figure\}", re.S)
figures = {}

def separate_figure(match):
    block = match.group(0)
    if "fig:topology" in block:
        name = "topology"
    elif "fig:ids" in block:
        name = "ids_workflow"
    else:
        return block
    figures[name] = block
    return "\\input{figures/" + name + "}"

system_design = figure_pattern.sub(separate_figure, system_design)
if set(figures) != {"topology", "ids_workflow"}:
    raise SystemExit("Expected the topology and IDS workflow figures in the source report.")
sections["System Design"] = system_design

citation_keys = {
    "1": "openflow-intro", "2": "openflow-spec", "3": "mininet",
    "4": "ryu", "5": "opennetmon", "6": "fresco",
}
for name, content in list(sections.items()):
    content = content.replace("[1], [2]", r"\cite{openflow-intro,openflow-spec}")
    for number, key in citation_keys.items():
        content = re.sub(r"\[" + number + r"\]", r"\\cite{" + key + "}", content)
    sections[name] = content

cover = (r"""\onecolumn
\pagenumbering{gobble}
\begin{titlepage}
""" + cover_match.group(1).strip() + r"""
\end{titlepage}
\clearpage
\pagenumbering{arabic}
\setcounter{page}{1}
\twocolumn""")
write("cover.tex", cover)

abstract = (r"""\begin{abstract}
""" + abstract_match.group(1).strip() + r"""
\end{abstract}

\begin{IEEEkeywords}
""" + keywords_match.group(1).strip() + r"""
\end{IEEEkeywords}""")
write("sections/abstract.tex", abstract)

section_files = {
    "Introduction": "introduction.tex",
    "Related Work": "related_work.tex",
    "System Design": "system_design.tex",
    "Implementation": "implementation.tex",
    "Testing and Results": "testing_results.tex",
    "Conclusion": "conclusion.tex",
    "Acknowledgment": "acknowledgment.tex",
}
for title, filename in section_files.items():
    write("sections/" + filename, sections[title])
for name, content in figures.items():
    write("figures/" + name + ".tex", content)

write("main.tex", r"""\documentclass[conference]{IEEEtran}
\IEEEoverridecommandlockouts
\usepackage{graphicx}
\usepackage{booktabs}
\usepackage{array}
\usepackage{url}
\usepackage{xcolor}
\usepackage{tikz}
\usetikzlibrary{arrows.meta,positioning,shapes.geometric}
\setlength{\textfloatsep}{7pt plus 2pt minus 2pt}
\setlength{\floatsep}{6pt plus 2pt minus 2pt}
\setlength{\intextsep}{6pt plus 2pt minus 2pt}

\begin{document}
\input{cover}

\title{NetGuardian: Enterprise SDN Management}
\author{\IEEEauthorblockN{[Team name]}
\IEEEauthorblockA{CSI201 Introduction to Networking, AY2026/27 S1}}
\maketitle

\input{sections/abstract}
\input{sections/introduction}
\input{sections/related_work}
\input{sections/system_design}
\input{sections/implementation}
\input{sections/testing_results}
\input{sections/conclusion}
\input{sections/acknowledgment}

\clearpage
\bibliographystyle{IEEEtran}
\bibliography{references}
\end{document}""")

write("references.bib", r"""@article{openflow-intro,
  author  = {McKeown, Nick and Anderson, Tom and Balakrishnan, Hari and Parulkar, Guru and Peterson, Larry and Rexford, Jennifer and Shenker, Scott and Turner, Jonathan},
  title   = {OpenFlow: Enabling Innovation in Campus Networks},
  journal = {ACM SIGCOMM Computer Communication Review},
  volume  = {38},
  number  = {2},
  pages   = {69--74},
  year    = {2008},
  month   = apr
}

@techreport{openflow-spec,
  author      = {{Open Networking Foundation}},
  title       = {OpenFlow Switch Specification, Version 1.3.0},
  institution = {Open Networking Foundation},
  number      = {ONF TS-006},
  year        = {2012},
  month       = jun,
  url         = {https://opennetworking.org/wp-content/uploads/2014/10/openflow-spec-v1.3.0.pdf}
}

@inproceedings{mininet,
  author    = {Lantz, Bob and Heller, Brandon and McKeown, Nick},
  title     = {A Network in a Laptop: Rapid Prototyping for Software-Defined Networks},
  booktitle = {Proceedings of the 9th ACM SIGCOMM Workshop on Hot Topics in Networks},
  address   = {Monterey, CA, USA},
  year      = {2010}
}

@misc{ryu,
  author       = {{Ryu Project}},
  title        = {Ryu SDN Framework: OpenFlow 1.3 API Reference},
  howpublished = {\url{https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html}},
  note         = {Accessed 2026}
}

@inproceedings{opennetmon,
  author    = {van Adrichem, N. L. M. and Doerr, C. and Kuipers, F. A.},
  title     = {OpenNetMon: Network Monitoring in OpenFlow Software-Defined Networks},
  booktitle = {Proceedings of the IEEE/IFIP Network Operations and Management Symposium},
  address   = {Krakow, Poland},
  pages     = {1--8},
  year      = {2014},
  doi       = {10.1109/NOMS.2014.6838228}
}

@inproceedings{fresco,
  author    = {Shin, Seungwon and Porras, Philip and Yegneswaran, Vinod and Fong, Martin and Gu, Guofei and Tyson, Mabry},
  title     = {FRESCO: Modular Composable Security Services for Software-Defined Networks},
  booktitle = {Proceedings of the Network and Distributed System Security Symposium},
  address   = {San Diego, CA, USA},
  year      = {2013}
}""")

write("README.md", """# CSI201 Coursework II — NetGuardian (Overleaf project)

`main.tex` is the IEEE conference-format entry point. Overleaf should compile
`main.tex`; it loads the separate cover, abstract, sections, figures, and
BibTeX references listed below.

```text
main.tex
cover.tex
references.bib
sections/
  abstract.tex
  introduction.tex
  related_work.tex
  system_design.tex
  implementation.tex
  testing_results.tex
  conclusion.tex
  acknowledgment.tex
figures/
  topology.tex
  ids_workflow.tex
```

The two current diagrams are TikZ figures kept as separate files. Add actual
VM-generated monitoring graphs to `figures/` after testing and include them in
`sections/testing_results.tex`. Replace every bracketed placeholder with real
team details, software versions, evidence, and measurements before submission;
no VM results are invented in this project.
""")

PROJECT.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(ARCHIVE, "w", compression=zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(PROJECT.rglob("*")):
        if path.is_file():
            archive.write(path, path.relative_to(PROJECT).as_posix())
print("Created project files in {}".format(PROJECT))
print("Created import archive at {}".format(ARCHIVE))
