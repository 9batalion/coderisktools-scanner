# CodeRiskTools — Master TODO gaps audit

## Cel i zakres

Ten raport jest audytem względem dokładnie tego pliku:

```text
docs/VULNERABILITY-DATABASE-MASTER-TODO-HERMES.md
```

Audyt obejmuje:

- Stage V0–V16 z sekcji `# 31. Kolejność wdrażania`;
- kryteria MVP z sekcji `# 32`;
- kryteria pełnej wersji z sekcji `# 33`;
- warunki odmowy publikacji z sekcji `# 34`;
- obowiązki raportowania batchy z sekcji `# 35`;
- zakazy bezpieczeństwa z sekcji `# 36`;
- docelowy rezultat z sekcji `# 37`;
- szczegółowe wymagania źródłowe, parsery, matching, updatera, snapshotów, CLI, raportów i bezpieczeństwa w sekcjach 2–30.

Nie traktuję samego checkboxa jako dowodu. Status opiera się na kodzie, testach, CLI, dokumentacji, historii git i realnym execution output.

## Evidence baseline

Audyt wykonano na:

```text
HEAD: 4ae9dd7ffab961f730d4ec83fc5ff723b596d200
branch: origin/main
working tree: clean
```

Master TODO ma obecnie:

```text
checked: 110
unchecked: 1996
total: 2106
```

Liczba checkboxów nie jest sama w sobie miarą realizacji: część punktów nadrzędnych jest zaznaczona jako MVP/subset, a część szczegółowych punktów pozostaje niezaznaczona mimo istniejącej implementacji częściowej.

## Verification gates

Uruchomiono:

```text
pytest -q
828 passed, 1 skipped, 909 subtests passed

python3 -O -m pytest -q
828 passed, 1 skipped, 1 warning, 909 subtests passed

python3 -m compileall -q src tests
PASS

git diff --check
PASS
```

Pełny self-scan `src/` nie był GREEN:

```text
secret-scanner scan --dir src --recursive --format json --profile balanced
exit: 1
findings: 1
severity: medium
file: src/__main__.py
line: 352
rule: CRT-SEC-020 / GENERIC_CREDENTIAL
```

To wygląda na detekcję nazwy zmiennej `credential` użytej przy odczycie zmiennej środowiskowej, a nie ujawnioną wartość sekretu. Mimo to gate nie może być opisany jako GREEN bez jawnej decyzji: poprawka reguły, korekta kodu albo zatwierdzona baseline/false-positive evidence.

---

# Status per Stage

## Stage V0 — audyt i zamrożenie kontraktów

Master TODO: linie 2532–2546.

### Potwierdzone

- checkout i baseline były wykonane;
- pełny test suite istnieje i przechodzi;
- publiczne kontrakty `Finding`, `ScanResult`, fingerprintów, JSON/SARIF i exit policy mają testy;
- dodano testy ochrony istniejących kontraktów;
- nie rozpoczęto implementacji bazy przed kontraktami.

### Brak

- osobny ADR o oddzieleniu podatności od sekretów — Master TODO linia 2545 pozostaje niezaznaczona;
- w repo nie znaleziono osobnego pliku ADR; separacja jest obecnie chroniona kodem/testami/dokumentacją;
- pełny self-scan całego `src/` wymaga rozstrzygnięcia false positive z linii `src/__main__.py:352`.

### Warunek zamknięcia

Utworzyć ADR albo jawnie zmienić TODO na kontrakt dokumentacyjny oraz zamknąć/udokumentować self-scan finding.

## Stage V1 — kontrakty domenowe

Master TODO: linie 2548–2559.

### Potwierdzone

- modele podstawowe;
- enums;
- provenance;
- snapshot manifest MVP;
- fingerprinty źródła/advisory/component/occurrence/vulnerability/snapshot;
- testy stabilności;
- brak sieci i brak produkcyjnej bazy w tym etapie.

### Brak lub częściowo

- PURL jest reprezentowany, lecz pełna canonicalization pozostaje pending;
- brak kompletnego modelu docelowego z osobnymi encjami dla `AffectedRange`, `FixedVersion`, `UnaffectedVersion`, `VulnerabilityFinding`, `ComponentOccurrence`, `Remediation`, `LicenseRecord`, `AttributionRecord` i `DatabaseHealth`;
- snapshot manifest nie zawiera jeszcze całego docelowego zestawu pól: wersji buildera, wersji reguł korelacji/fingerprintów, pełnej listy źródeł, licencji, atrybucji i podpisu.

## Stage V2 — inventory MVP

Master TODO: linie 2561–2574.

### Potwierdzone

Istnieją parsery/testy dla:

- `package-lock.json`;
- `poetry.lock`;
- `uv.lock`;
- `requirements.txt`;
- `Cargo.lock`;
- `go.mod`/`go.sum`;
- `composer.lock`;
- komponentów i occurrence;
- unresolved dependencies;
- JSON inventory;
- limitów i złośliwych manifestów.

### Brak

Stage V2 jest MVP, nie pełnym inventory. Szczegółowy backlog nadal obejmuje m.in.:

- Pipfile/pdm/pylock;
- yarn classic/Berry;
- pnpm;
- Maven/POM/Gradle;
- NuGet;
- Gemfile.lock;
- Swift Package.resolved;
- Dart, Elixir, Haskell, R;
- Conan/vcpkg;
- pełny dependency graph;
- pełną direct/transitive semantykę dla każdego ekosystemu.

## Stage V3 — mini baza OSV

Master TODO: linie 2576–2587.

### Potwierdzone

- SQLite schema;
- fixture import;
- podstawowe indeksy;
- exact-version matching;
- OSV introduced/fixed/last_affected range MVP;
- fixed versions;
- withdrawn filtering;
- vulnerability occurrence fingerprint;
- explanation;
- brak automatycznego updatera sieciowego.

### Brak

- pełny comparator framework ekosystemów;
- jawny wynik `indeterminate` dla brakującej wersji — obecna ścieżka może zwrócić brak dopasowania;
- pełny status model `affected/fixed/not_affected/indeterminate`;
- vendor backport i distro-aware matching;
- pełna PURL/CPE/name/range hierarchia z sekcji 11.

## Stage V4 — pełny importer OSV

Master TODO: linie 2589–2598.

### Potwierdzone

- bounded supplied-record import;
- quality metrics;
- source snapshots;
- determinism w zakresie obecnych fixture/snapshot contracts.

### Brak

Master TODO pozostawia niezrealizowane:

- wszystkie ekosystemy;
- pełną lokalną bazę;
- pełny benchmark jakości/wydajności;
- pełny low-memory contract.

Dodatkowo brakuje dowodu production-grade streamingu globalnych feedów, a nie tylko bounded importu dostarczonych rekordów.

## Stage V5 — CVE i GHSA correlation

Master TODO: linie 2600–2608.

### Potwierdzone

- CVE List V5 import contract;
- GHSA import contract;
- alias index;
- merge decisions;
- konflikty;
- fingerprint stability po korelacji;
- merge/split tests.

### Brak lub częściowo

- pełny downloader/aktualizator publicznych feedów CVE/GHSA;
- pełny alias graph dla wszystkich źródeł;
- kompletna heurystyczna korelacja;
- pełny ręczny correction workflow;
- pełny produkcyjny merge/split audit report.

## Stage V6 — NVD enrichment

Master TODO: linie 2610–2618.

### Potwierdzone

- CVSS;
- CWE;
- CPE;
- references;
- wielokrotne metryki;
- preferowana metryka prezentacyjna;
- niezależność fingerprintu od CVSS.

### Brak lub częściowo

- pełny NVD feed/API downloader;
- pełna incremental revision history z realnego feedu;
- kompletna coverage report dla NVD;
- pełna walidacja wszystkich konfiguracji CPE w production data.

## Stage V7 — exploitation intelligence

Master TODO: linie 2620–2628.

### Potwierdzone

- CISA KEV;
- EPSS;
- CISA Vulnrichment;
- SSVC;
- ransomware signal;
- additive policy evaluator MVP;
- brak wpływu enrichment na fingerprint.

### Brak lub częściowo

- pełny downloader i historyczna agregacja feedów;
- pełny production source coverage report;
- pełny lifecycle rewizji enrichment;
- pełny audyt wartości ryzyka do źródła w każdym finalnym findingu;
- pełna separacja `missing`, `indeterminate`, `stale` i `not applicable` we wszystkich raportach.

## Stage V8 — bezpieczny updater

Master TODO: linie 2630–2642.

### Potwierdzone

- HTTPS fetch;
- allowlist;
- size/time/redirect limits;
- ETag/conditional fetch;
- staging;
- integrity;
- quality gates;
- atomic activation;
- rollback;
- snapshot manifest;
- retry/conditional boundary.

### Brak lub częściowo

- pełny multi-source cursor pipeline;
- kompletne archiwa ZIP/gzip/tar z archive-bomb protections jako osobny kontrakt;
- podpisy źródeł i podpis manifestu;
- pełne tombstones;
- pełny source-by-source incremental history;
- pełne `doctor`, `metrics`, `sources`, `export-manifest` CLI;
- air-gap bundle.

## Stage V9 — CLI i raporty

Master TODO: linie 2644–2655.

### Potwierdzone

- inventory/scan/vuln-db CLI MVP;
- JSON;
- SARIF;
- Markdown;
- HTML;
- CSV;
- database status;
- podstawowe stale/status warnings;
- podstawowa exit policy.

### Brak

Master TODO linia 2652 pozostaje pending:

- osobna pełna komenda `vuln explain`;
- kompletne `vuln lookup` i package-level lookup;
- pełny source/conflict/snapshot health view;
- pełna wersjonowana vulnerability JSON schema;
- pełna SARIF rule/evidence contract;
- pełny filtrowalny/self-contained HTML contract.

## Stage V10 — baseline, suppression i VEX

Master TODO: linie 2657–2667.

### Potwierdzone

- vulnerability baseline;
- delta;
- suppression;
- OpenVEX MVP;
- CycloneDX VEX MVP;
- `not_affected` i `under_investigation` w VEX/suppression boundary;
- data-change report.

### Brak

Master TODO linia 2662 pozostaje pending:

- pełny expiry lifecycle;
- owner/ticket/scope/expiry enforcement;
- expired/unused suppression report;
- pełny signed VEX provenance;
- pełny import/export VEX contract.

## Stage V11 — SBOM

Master TODO: linie 2669–2677.

### Potwierdzone częściowo

- CycloneDX JSON strict local inventory subset;
- SPDX JSON strict local package subset;
- Syft native JSON artifact subset.

### Brak — bieżący etap

Te cztery punkty muszą pozostać pending:

1. linia 2674 — OSV-Scanner import;
2. linia 2675 — Trivy import;
3. linia 2676 — Grype import;
4. linia 2677 — external evidence provenance.

Dodatkowo w szczegółowych sekcjach 6.1–6.3 brakuje:

- CycloneDX XML;
- bom-ref, CPE, SWID;
- hashes, licenses, dependency graph, scope, evidence, embedded vulnerabilities;
- SPDX tag-value/XML/SPDXID/relationships/checksums/licenses;
- Syft table low-confidence adapter;
- external tool version/name/source evidence contract;
- porównania external findings z lokalną bazą.

## Stage V12 — dystrybucje Linux

Master TODO: linie 2679–2689.

Wszystkie punkty są pending:

- Debian;
- Ubuntu;
- Red Hat;
- SUSE;
- Alpine;
- RPM comparator;
- Debian comparator;
- APK comparator;
- backport awareness.

Nie należy rozpoczynać V12 przed domknięciem V11, chyba że powstanie jawnie zatwierdzony wyjątek w batch decision.

## Stage V13 — pozostałe ekosystemy

Master TODO: linie 2691–2702.

Wszystkie punkty są pending:

- Maven;
- NuGet;
- Ruby;
- Swift;
- Dart;
- Elixir;
- Haskell;
- R;
- Conan;
- vcpkg.

Brakuje także właściwych comparatorów wersji i fixture corpus dla każdego ekosystemu.

## Stage V14 — CSAF vendor feeds

Master TODO: linie 2704–2713.

Wszystkie punkty są pending:

- generic CSAF importer;
- provider registry;
- provider health;
- product tree;
- remediations;
- vendor-specific status;
- licenses;
- quality gates.

Samo występowanie słowa CSAF w Master TODO/dokumentacji nie jest evidence implementacji.

## Stage V15 — pełny benchmark

Master TODO: linie 2715–2728.

Wszystkie punkty są pending:

- public fixtures;
- precision;
- recall;
- performance;
- memory;
- false-positive suite;
- false-negative suite;
- regression gates;
- porównanie z OSV-Scanner;
- porównanie z Trivy;
- porównanie z Grype;
- wyjaśnienie różnic bez kopiowania ich wyników.

Istnieją testy regresyjne i performance baseline, ale nie ma pełnego benchmarku jakości matching engine.

## Stage V16 — produkcyjny snapshot

Master TODO: linie 2730–2743.

Wszystkie punkty są pending:

- full build;
- reproducibility;
- licenses;
- attributions;
- signed manifest;
- air-gap bundle;
- release notes;
- database health report;
- source coverage report;
- known limitations;
- rollback test jako pełny release/disaster workflow;
- disaster recovery test.

Nie publikować production snapshotu przed zamknięciem tej sekcji.

---

# Kryteria MVP — sekcja 32

Master TODO: linie 2747–2771.

## Potwierdzone lub bardzo mocno poparte evidence

- osobne modele podatności;
- stabilne fingerprinty MVP;
- brak zmiany istniejącego secret `Finding` contract;
- Python, npm, Cargo i Go inventory;
- wersje z lockfile/manifest;
- lokalny OSV;
- brak sieci w scan path;
- brak uruchamiania kodu repozytorium;
- snapshot manifest;
- component/version/advisory evidence;
- match basis;
- confidence MVP;
- fixed version, jeżeli znana;
- vulnerability fingerprint;
- fingerprint niezależny od CVSS;
- JSON/SARIF reports;
- pełna regresja przechodzi.

## Nadal wymagające jawnego odznaczenia albo korekty

- Master TODO sekcja 32 pozostaje checkboxowo niezaktualizowana;
- trzeba dodać osobny acceptance evidence block do każdego kryterium;
- brak explicit `indeterminate` dla brakującej wersji;
- brak pełnego confidence hierarchy;
- pełne `Finding` output fields nie są jeszcze równoważne docelowemu vulnerability finding;
- self-scan całego `src/` ma obecnie niezamknięty medium finding;
- brak osobnego ADR z V0.

Wniosek: istnieje działający MVP subsystem, ale formalne kryteria MVP nie powinny być oznaczone jako całkowicie zamknięte bez osobnego acceptance pass.

---

# Kryteria pełnej wersji — sekcja 33

Master TODO: linie 2775–2818.

## Zrealizowane częściowo

Istnieją adaptery/kontrakty dla:

- OSV;
- CVE V5;
- NVD enrichment;
- GHSA import;
- CISA Vulnrichment;
- CISA KEV;
- EPSS;
- CWE/CPE;
- PURL subset;
- CycloneDX JSON subset;
- SPDX JSON subset;
- VEX MVP;
- baseline/suppression;
- full/conditional updater boundary;
- atomic activation;
- rollback;
- malicious input tests;
- fingerprint tests;
- no-network/no-execution tests.

## Braki blokujące pełną wersję

- główne bazy ekosystemowe;
- główne dystrybucje Linux;
- CSAF;
- pełny SBOM format coverage;
- air-gap;
- jawne licencje/attributions;
- quality/performance benchmark;
- measurable source coverage;
- full false-positive/false-negative suite;
- full reproducible production snapshots;
- provenance każdego finalnego wyniku;
- pełna explainability każdego merge advisory;
- pełny audyt suppression;
- formalne udokumentowanie każdej heurystyki blokującej build.

---

# Kryteria odmowy publikacji — sekcja 34

Master TODO: linie 2822–2842.

## Działają częściowo

Istnieją kontrakty dla:

- integrity check;
- manifest/database verification;
- hashes/content digests;
- quality status;
- snapshot staging;
- atomic promotion;
- rollback;
- source provenance;
- reconciliation/quality metrics.

## Brak lub niewystarczający dowód

- rejected CVE hard gate jako kompletna reguła dla wszystkich źródeł;
- gwałtowny spadek advisory/package z pełnym baseline porównaniem;
- kompletność source attribution;
- source license gate;
- reproducibility gate dla pełnych production snapshots;
- malicious archive test;
- pełny rollback disaster test;
- brak ręcznych, nieudokumentowanych poprawek;
- finalny `quality status=failed` publication blocker dla wszystkich ścieżek.

Nie wolno deklarować, że sekcja 34 jest całkowicie zamknięta tylko dlatego, że updater ma staging i rollback.

---

# Raportowanie batchy — sekcja 35

Master TODO: linie 2846–2891.

## Potwierdzone w obecnym workflow

- Observation/Fact/Delta/Risk/Decision są stosowane w komunikacji batchowej;
- wykonywane są testy i readback;
- PR/CI/merge są używane;
- scope batchy jest bounded;
- Stage V11 jest rozdzielony od sekcji matching #11.

## Braki procesowe

- każdy historyczny batch nie ma osobnego, trwałego raportu w repo;
- nie każdy batch ma zapis zmiany liczby testów, wydajności i rozmiaru bazy;
- brakuje jednolitego artefaktu provenance dla każdego batcha;
- obecny raport jest pierwszym osobnym audytem Master TODO.

---

# Zakazy — sekcja 36

Master TODO: linie 2895–2916.

## Potwierdzone przez obecny kod/testy

- brak zmiany sekretowego fingerprintu;
- oddzielny vulnerability contract;
- brak automatycznego update podczas scan;
- brak wykonywania repo code;
- brak package-manager execution;
- local/offline scan boundary;
- zachowanie provenance i konfliktów;
- CVSS/EPSS/KEV nie zmieniają fingerprintu;
- snapshot manifest przed aktywacją;
- poprzedni snapshot jest zachowywany;
- brak deklaracji 100% coverage.

## Niezamknięte albo wymagające dalszego audytu

- pełne ukrywanie braku wersji jako `indeterminate` — obecnie ryzyko semantyczne;
- vendor backport awareness;
- pełna ochrona przed name-only false matches;
- pełna licencyjna weryfikacja redystrybucji;
- formalne zakodowanie wszystkich zakazów jako contract tests;
- self-scan false positive gate opisany wyżej.

---

# Docelowy rezultat — sekcja 37

Master TODO: linie 2920–2963.

## Już dostępne częściowo

Dostępne są:

- lokalny scan;
- HTML/JSON/SARIF/Markdown/CSV;
- component/version/PURL/manifest path;
- advisory IDs i aliases w podstawowym zakresie;
- affected/fixed/explanation/confidence/fingerprint/snapshot;
- baseline/suppression/policy MVP;
- CVSS/CWE/KEV/EPSS/SSVC w zakresie obecnych danych.

## Braki przed spełnieniem rezultatu docelowego

- `vuln-db update --full` jako pełny production multi-source update;
- pełne ecosystem/distribution coverage;
- pełny CSAF;
- pełny SBOM adapter coverage;
- direct/transitive semantics dla wszystkich parserów;
- pełna affected range i remediation semantics;
- producent advisory i pełne source provenance;
- pełne explain match;
- audytowalny suppression lifecycle;
- konkretna rekomendacja naprawcza dla każdego findingu;
- signed reproducible snapshot;
- air-gap release;
- license/attribution report.

---

# Priorytet braków

## P0 — blokuje obecny Stage V11

1. OSV-Scanner JSON import.
2. Trivy JSON import.
3. Grype JSON import.
4. External evidence provenance.
5. Testy malformed/duplicate/unsupported/tool-version dla trzech adapterów.
6. Decyzja i zamknięcie self-scan finding `src/__main__.py:352`.

## P1 — blokuje formalne MVP

1. Osobny ADR V0.
2. Pełny confidence/match status contract.
3. Jawny `indeterminate` dla brakującej wersji.
4. PURL canonicalization.
5. Pełny vulnerability finding schema.
6. Domknięcie MVP criteria section 32 przez evidence matrix.

## P2 — blokuje pełną wersję

1. V12 dystrybucje Linux i comparatory.
2. V13 pozostałe ekosystemy.
3. V14 CSAF.
4. V15 benchmark precision/recall/FP/FN/performance/memory.
5. V16 signed reproducible production snapshot, licenses, attributions, air-gap i DR.

# Decision

Nie przechodzimy do V12.

Najbliższy bounded batch pozostaje:

```text
V11d — OSV-Scanner JSON import
```

Batch powinien zakończyć się:

- RED → GREEN;
- strict local import;
- tool name/version provenance;
- no-network/no-subprocess;
- malformed/duplicate/unsupported tests;
- full regression;
- compile;
- secret-safe scan z rozstrzygniętym obecnym findingiem;
- PR/CI/merge/readback;
- aktualizacją Master TODO dopiero po evidence.

Nie wolno oznaczyć Stage V11 jako ukończonego przed zamknięciem czterech punktów z linii 2674–2677.
