#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const yauzl = require("yauzl");

const ROOT = process.argv[2];

if (!ROOT) {
  console.error("Usage: node epub-scanner.js <directory>");
  process.exit(1);
}

const suspiciousExtensions = [
  ".js",
  ".mjs",
  ".wasm",
  ".exe",
  ".dll",
  ".bat",
  ".cmd",
  ".ps1",
  ".sh",
  ".jar",
];

const textExtensions = [
  ".html",
  ".htm",
  ".xhtml",
  ".xml",
  ".svg",
  ".js",
  ".mjs",
  ".css",
  ".opf",
];

const suspiciousPatterns = [
  {
    name: "JavaScript execution",
    regex: /\beval\s*\(/gi,
    severity: "HIGH",
  },
  {
    name: "Dynamic Function constructor",
    regex: /\bnew\s+Function\s*\(/gi,
    severity: "HIGH",
  },
  {
    name: "Function constructor",
    regex: /\bFunction\s*\(/gi,
    severity: "HIGH",
  },
  {
    name: "Base64 decoding",
    regex: /\batob\s*\(/gi,
    severity: "MEDIUM",
  },
  {
    name: "Character-code obfuscation",
    regex: /\bString\.fromCharCode\s*\(/gi,
    severity: "MEDIUM",
  },
  {
    name: "Document write",
    regex: /\bdocument\.write\s*\(/gi,
    severity: "MEDIUM",
  },
  {
    name: "Dynamic HTML",
    regex: /\.innerHTML\s*=/gi,
    severity: "MEDIUM",
  },
  {
    name: "Iframe",
    regex: /<iframe\b/gi,
    severity: "MEDIUM",
  },
  {
    name: "Script tag",
    regex: /<script\b/gi,
    severity: "HIGH",
  },
  {
    name: "WebAssembly",
    regex: /\bWebAssembly\b/gi,
    severity: "HIGH",
  },
  {
    name: "Network request",
    regex: /\b(fetch|XMLHttpRequest)\s*\(/gi,
    severity: "MEDIUM",
  },
  {
    name: "WebSocket",
    regex: /\bWebSocket\s*\(/gi,
    severity: "MEDIUM",
  },
  {
    name: "Window navigation",
    regex: /\b(location\.href|window\.open)\b/gi,
    severity: "MEDIUM",
  },
];

const externalUrlRegex =
  /https?:\/\/[^\s"'<>]+/gi;

const obfuscationPatterns = [
  /\\x[0-9a-f]{2}/gi,
  /\\u[0-9a-f]{4}/gi,
  /[A-Za-z0-9+/]{100,}={0,2}/g,
];

const results = {
  scannedAt: new Date().toISOString(),
  directory: path.resolve(ROOT),
  total: 0,
  clean: 0,
  suspicious: 0,
  errors: 0,
  files: [],
};

function severityRank(severity) {
  return {
    NONE: 0,
    LOW: 1,
    MEDIUM: 2,
    HIGH: 3,
    CRITICAL: 4,
  }[severity] || 0;
}

function maxSeverity(current, next) {
  return severityRank(next) > severityRank(current)
    ? next
    : current;
}

function getLineNumber(text, index) {
  return text.slice(0, index).split("\n").length;
}

function inspectText(content, fileName) {
  const findings = [];

  for (const pattern of suspiciousPatterns) {
    pattern.regex.lastIndex = 0;

    let match;

    while ((match = pattern.regex.exec(content)) !== null) {
      findings.push({
        type: "pattern",
        name: pattern.name,
        severity: pattern.severity,
        line: getLineNumber(content, match.index),
        sample: content
          .slice(
            Math.max(0, match.index - 80),
            Math.min(content.length, match.index + 120)
          )
          .replace(/\s+/g, " ")
          .trim(),
      });

      // Avoid producing thousands of identical findings.
      if (findings.length >= 100) {
        break;
      }
    }
  }

  // External URLs
  const urls = content.match(externalUrlRegex) || [];

  const uniqueUrls = [...new Set(urls)];

  for (const url of uniqueUrls.slice(0, 50)) {
    findings.push({
      type: "external-url",
      name: "External URL",
      severity: "MEDIUM",
      value: url,
    });
  }

  // Obfuscation indicators
  for (const regex of obfuscationPatterns) {
    regex.lastIndex = 0;

    if (regex.test(content)) {
      findings.push({
        type: "obfuscation",
        name: "Possible obfuscation",
        severity: "MEDIUM",
      });
    }
  }

  return findings;
}

function scanEpub(epubPath) {
  return new Promise((resolve) => {
    const result = {
      file: epubPath,
      status: "CLEAN",
      risk: "NONE",
      size: fs.statSync(epubPath).size,
      entries: 0,
      suspiciousFiles: [],
      findings: [],
      errors: [],
    };

    yauzl.open(
      epubPath,
      {
        lazyEntries: true,
        autoClose: true,
      },
      (error, zipfile) => {
        if (error) {
          result.status = "ERROR";
          result.errors.push(error.message);
          results.errors++;
          resolve(result);
          return;
        }

        zipfile.readEntry();

        zipfile.on("entry", (entry) => {
          result.entries++;

          const fileName = entry.fileName;
          const lowerName = fileName.toLowerCase();

          // Ignore directories
          if (lowerName.endsWith("/")) {
            zipfile.readEntry();
            return;
          }

          const extension = path.extname(lowerName);

          // Suspicious executable-like files
          if (suspiciousExtensions.includes(extension)) {
            result.suspiciousFiles.push({
              file: fileName,
              reason: `Contains ${extension} file`,
            });

            if (extension === ".exe" || extension === ".dll") {
              result.risk = maxSeverity(result.risk, "CRITICAL");
            } else if (extension === ".wasm") {
              result.risk = maxSeverity(result.risk, "HIGH");
            } else if (
              extension === ".js" ||
              extension === ".mjs"
            ) {
              result.risk = maxSeverity(result.risk, "HIGH");
            } else {
              result.risk = maxSeverity(result.risk, "HIGH");
            }
          }

          // Inspect textual content
          if (textExtensions.includes(extension)) {
            zipfile.openReadStream(entry, (streamError, stream) => {
              if (streamError) {
                result.errors.push(
                  `${fileName}: ${streamError.message}`
                );
                zipfile.readEntry();
                return;
              }

              const chunks = [];

              stream.on("data", (chunk) => {
                // Prevent excessive memory usage on pathological files.
                if (Buffer.concat(chunks).length < 10 * 1024 * 1024) {
                  chunks.push(chunk);
                }
              });

              stream.on("end", () => {
                try {
                  const content = Buffer.concat(chunks).toString("utf8");

                  const findings = inspectText(
                    content,
                    fileName
                  );

                  if (findings.length > 0) {
                    result.findings.push({
                      file: fileName,
                      findings,
                    });

                    for (const finding of findings) {
                      result.risk = maxSeverity(
                        result.risk,
                        finding.severity
                      );
                    }
                  }
                } catch (e) {
                  result.errors.push(
                    `${fileName}: ${e.message}`
                  );
                }

                zipfile.readEntry();
              });
            });

            return;
          }

          zipfile.readEntry();
        });

        zipfile.on("end", () => {
          if (
            result.suspiciousFiles.length > 0 ||
            result.findings.length > 0
          ) {
            result.status = "SUSPICIOUS";
            results.suspicious++;
          } else {
            results.clean++;
          }

          resolve(result);
        });

        zipfile.on("error", (zipError) => {
          result.status = "ERROR";
          result.errors.push(zipError.message);
          results.errors++;
        });
      }
    );
  });
}

function findEpubs(directory) {
  const found = [];

  function walk(currentDirectory) {
    let entries;

    try {
      entries = fs.readdirSync(currentDirectory, {
        withFileTypes: true,
      });
    } catch (error) {
      console.error(
        `Cannot read directory: ${currentDirectory}`
      );
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(
        currentDirectory,
        entry.name
      );

      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (
        entry.isFile() &&
        entry.name.toLowerCase().endsWith(".epub")
      ) {
        found.push(fullPath);
      }
    }
  }

  walk(directory);

  return found;
}

function printResult(result) {
  const relative = path.relative(
    path.resolve(ROOT),
    result.file
  );

  let icon = "✅";

  if (result.status === "ERROR") {
    icon = "❌";
  } else if (result.status === "SUSPICIOUS") {
    icon = result.risk === "CRITICAL"
      ? "🚨"
      : "⚠️";
  }

  console.log(
    `${icon} ${relative} — ${result.risk}`
  );

  if (result.suspiciousFiles.length > 0) {
    for (const file of result.suspiciousFiles) {
      console.log(
        `   └─ ${file.file}: ${file.reason}`
      );
    }
  }

  for (const group of result.findings) {
    for (const finding of group.findings.slice(0, 20)) {
      console.log(
        `   └─ ${group.file}: ${finding.severity} — ${finding.name}` +
        (finding.line
          ? ` (line ${finding.line})`
          : "")
      );

      if (finding.value) {
        console.log(`      ${finding.value}`);
      }
    }
  }

  if (result.errors.length > 0) {
    for (const error of result.errors) {
      console.log(`   └─ ERROR: ${error}`);
    }
  }
}

async function main() {
  const absoluteRoot = path.resolve(ROOT);

  if (!fs.existsSync(absoluteRoot)) {
    console.error(
      `Directory does not exist: ${absoluteRoot}`
    );
    process.exit(1);
  }

  console.log("EPUB Security Scanner");
  console.log("=====================");
  console.log(`Directory: ${absoluteRoot}`);
  console.log("");

  const epubs = findEpubs(absoluteRoot);

  if (epubs.length === 0) {
    console.log("No EPUB files found.");
    return;
  }

  console.log(`Found ${epubs.length} EPUB files.`);
  console.log("");

  for (let i = 0; i < epubs.length; i++) {
    console.log(
      `[${i + 1}/${epubs.length}] Scanning...`
    );

    const result = await scanEpub(epubs[i]);

    results.files.push(result);

    printResult(result);
  }

  const reportPath = path.join(
    process.cwd(),
    "epub-security-report.json"
  );

  fs.writeFileSync(
    reportPath,
    JSON.stringify(results, null, 2),
    "utf8"
  );

  console.log("");
  console.log("=====================");
  console.log("SCAN COMPLETE");
  console.log("=====================");
  console.log(`Total:       ${results.total || epubs.length}`);
  console.log(`Clean:       ${results.clean}`);
  console.log(`Suspicious:  ${results.suspicious}`);
  console.log(`Errors:      ${results.errors}`);
  console.log("");
  console.log(`Report: ${reportPath}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
