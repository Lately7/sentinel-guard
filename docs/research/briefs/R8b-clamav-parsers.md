# R8b — ClamAV 1.5.4 file types and parsers, read from source

The current directory is a checkout of the ClamAV source at tag
`clamav-1.5.4`. Build on R8a (`docs/research/R8a-clamav-engine.md` in the
Sentinel repository) if it exists.

## Questions

1. **File-type recognition.** How `filetypes.c`/`filetypes_int.h` and the
   magic database decide a type; precedence between magic and extension
   (ClamAV ignores names?); what happens to unknown types; how embedded types
   (`CL_TYPE_*` found inside another file) trigger nested scans.
2. **Parser inventory.** One row per parser/unpacker: PE (including every
   supported packer: UPX, FSG, Petite, MEW, yC, WWPack, NsPack, Aspack,
   Upack, PeSpin…), ELF, Mach-O, ZIP, RAR (unrar), 7z, ARJ, CAB, CHM, ISO9660,
   UDF, DMG, XAR, TAR, GZIP/BZIP2/XZ/LZMA, MSI/OLE2 + VBA, OOXML, OneNote,
   PDF (streams, filters, JavaScript, encryption), RTF, HTML/JS normalization,
   SWF, HWP, mail/MIME/TNEF/uuencode, images (fuzzy hash), NSIS, InstallShield,
   autoit, Python bytecode if any, LNK if any. For each: source file, entry
   function, what it extracts and rescans, its limits, its known unsupported
   variants, and what result an unsupported or malformed input produces.
3. **Missing conditions.** For a Windows home PC in 2026, which common
   delivery formats or containers are NOT parsed or only partly parsed
   (examples to check: password-protected archives, encrypted Office/PDF,
   modern installers, MSIX/AppX, ISO/IMG/VHD(X), LNK, HTA, JScript/VBScript
   files without HTML, PowerShell scripts, .NET single-file bundles,
   Electron/ASAR, Python-packed executables, Go/Rust binaries, signed-binary
   sideloading). State what ClamAV does with each (raw-byte matching only?).
4. **Heuristics.** Every heuristic ClamAV can raise (`Heuristics.*`):
   trigger condition (`path:line`), config switch, false-positive risk, and
   whether it is evidence of malice or only of an unusual structure.

## Deliverable

Sections 1–4 with tables, then "Implications for Gate v2": which formats
Sentinel must parse itself or mark as "not inspected", and which ClamAV
outputs can be trusted as evidence of complete inspection.
