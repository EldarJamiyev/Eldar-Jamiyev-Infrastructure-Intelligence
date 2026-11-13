---
name: scientific-agent-skills
description: "Turn AI agents into AI Scientists. Unified scientific agent skill library covering computational biology, chemistry, genomics, medicine, astrophysics, and 100+ scientific databases."
triggers:
  - "scientific agent"
  - "bioinformatics"
  - "computational chemistry"
  - "genomic analysis"
  - "scientific literature"
---

# Scientific Agent Skills

The primary Agent Skills standard for scientific research, drug discovery, genomics, and academic literature analysis.

## Key Disciplines & Tools

1. **Structural Biology & Protein Science:**
   - AlphaFold 2/3 prediction analysis (`fetch_structure.py`, `analyze_plddt.py`, `analyze_pae.py`).
   - PDB (Protein Data Bank), Foldseek structural search, and UniProt sequence analysis.
   - MSA (Multiple Sequence Alignment) with MMseqs2 and Clustal Omega.
2. **Cheminformatics & Drug Discovery:**
   - PubChem, ChEMBL, and Reactome database integrations.
   - Molecular docking, SMILES parsing, binding affinity profiling, and ADMET prediction.
3. **Genomics & Clinical Genetics:**
   - ClinVar, dbSNP, gnomAD, and Ensembl database queries.
   - Variant impact scoring and single variant consequence analysis.
4. **Literature Search & Research Synthesis:**
   - Automated arXiv, bioRxiv, Europe PMC, and OpenAlex query pipelines.
   - Citation matching and cross-database bibliographic resolution.
