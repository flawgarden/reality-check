# reality-check
`reality-check` stands out as a tough SAST tools benchmark dataset, as it is based on real-world vulnerabilities that discovered and resolved in large-scale industry projects. This repository consists of three parts.

- The CVE database `cves_db.csv` presented in table format provides detailed information for each CVE, including the CVE identifier, CWE identifier, repository name, version, and links to source code archives. This thoroughness ensures a straightforward way to bootstrap the projects to benchmark SAST tools.

- The markup files used to locate affected source code locations are presented in two versions per CVE entry. The former corresponds to the vulnerable code, while the latter represents the fixed code. These files describe the vulnerable and fixed locations in terms of the relative path to the file in the source code project and the affected line region of a function or a class with its name, making them a valuable resource for researchers.

- And a bunch of scripts to download, build, and markup projects from the CVE database. The [SARIF-based format](https://github.com/flawgarden/bentoo/blob/main/docs/bentoo-sarif/format.md) is used as a markup format.


## Get started

Markup files are located in the `markup` subfolder. Each file is named semantically:
```sh
PROJECT-NAME_CVE-ID_VERSION-NAME.csv
```
For example, the name of `Openfire_CVE-2019-18393_Openfire-4.5.0.csv` file means the markup file related to the `Openfire` project, `CVE-2019-18393` vulnerability identifier and `Openfire-4.5.0` version. One line in the file describes one location in the project in the form:
```sh
relative/path/to/file:[startline,endline]:functionOrClassName
```
To bootstrap the benchmark data, execute the `scripts/bootstrap.sh` script in the root of the `reality-check` project root directory. It performs project collection according to the CVE table database in the `benchmark` subdirectory. It locates a `truth.sarif` file in each project root directory, marking vulnerable and safe source code locations regarding source code regions and CWE classes.


## Where are we now, and where are we going?

Currently, the CVE database consists of projects presented in the article [Comparison and Evaluation on Static Application Security Testing (SAST) Tools for Java](https://sites.google.com/view/java-sast-study/home?authuser=0) under the name `Java CVE Benchmark`. The `Java CVE Benchmark` comprises 165 CVEs, making it, according to the authors, the largest CVE benchmark for the Java language.

- The main goal of this project is to extend this CVE dataset to other languages such as **C#**, **Go**, and **Python**.
- For this purpose, we are to use a language-agnostic approach, as described in the article above. To do this, we will use the [CVEfixes](https://github.com/secureIT-project/CVEfixes) project database, which provides an unprecedentedly simple way to obtain almost all the necessary project markup data and subsequently have the markup reviewed by experts.
