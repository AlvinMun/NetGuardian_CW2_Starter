# Report files

- `Report_Coursework_II.tex` is the IEEE double-column report draft. It includes
  the topology/policy design, implementation description, figures, references,
  and a five-run results table.
- `Report_Coursework_II_DRAFT.pdf` is a compiled review copy. It is visibly
  marked as a draft and contains placeholders for real VM results, software
  versions, team names/IDs, and contribution percentages.

After running the VM tests, replace every `[pending]` placeholder and the
draft language in the TeX source, check that the report has six body pages
excluding its cover, then compile twice with:

```bash
pdflatex -interaction=nonstopmode -halt-on-error -jobname=Report_Coursework_II Report_Coursework_II.tex
pdflatex -interaction=nonstopmode -halt-on-error -jobname=Report_Coursework_II Report_Coursework_II.tex
```

The final file name required by the brief is `Report_Coursework_II.pdf`. Keep
generated VM CSVs and logs under `Codes/data` and `Codes/Evidence`; include
selected real screenshots and result summaries in the report and video.
