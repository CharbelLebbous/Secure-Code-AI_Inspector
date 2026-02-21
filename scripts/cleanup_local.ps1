$ErrorActionPreference = "Continue"

Write-Host "Cleaning local temporary folders and legacy screenshots..."

$dirs = @(
    ".pytest_cache",
    ".pytest_tmp",
    ".pytest_work",
    ".tmp_dedupe_check",
    ".tmp_manual_compare",
    ".tmp_manual_compare2",
    ".tmp_manual_compare3",
    ".tmp_manual_compare_dup",
    ".tmp_pdf_ocr",
    ".tmp_pytest",
    ".tmp_pytest_safe",
    ".tmp_service_check",
    ".tmp_v7_check",
    "__pycache__",
    "archive/course_materials/.tmp_ocr",
    "archive/course_materials/.tmp_ocr_text"
)

foreach ($d in $dirs) {
    if (Test-Path $d) {
        try {
            Remove-Item -Recurse -Force $d -ErrorAction Stop
            Write-Host "Removed $d"
        } catch {
            Write-Host "Failed to remove $d : $($_.Exception.Message)"
        }
    }
}

$legacyScreens = @(
    "docs/Screenshot (546).png",
    "docs/Screenshot (547).png",
    "docs/Screenshot (548).png",
    "docs/Screenshot (550).png",
    "docs/Screenshot (551).png"
)

foreach ($s in $legacyScreens) {
    if (Test-Path $s) {
        try {
            Remove-Item -Force $s -ErrorAction Stop
            Write-Host "Removed $s"
        } catch {
            Write-Host "Failed to remove $s : $($_.Exception.Message)"
        }
    }
}

$legacyFiles = @(
    "archive/course_materials/CBRS503_Project_extracted.txt",
    "archive/course_materials/CBRS503 Project.txt",
    "archive/course_materials/-.png"
)

foreach ($f in $legacyFiles) {
    if (Test-Path $f) {
        try {
            Remove-Item -Force $f -ErrorAction Stop
            Write-Host "Removed $f"
        } catch {
            Write-Host "Failed to remove $f : $($_.Exception.Message)"
        }
    }
}

Write-Host "Cleanup done."
