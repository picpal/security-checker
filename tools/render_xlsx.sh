#!/bin/sh
# macOS 전용: xlsx 를 Numbers 로 PDF 내보내기 → pdftoppm 으로 시트별 PNG. 사용: tools/render_xlsx.sh <xlsx> <out-dir>
# 산출물 검증용(레이아웃을 사람이/LLM 이 눈으로 확인). 의존: Numbers.app, pdftoppm(brew install poppler).
set -e
X=$(cd "$(dirname "$1")" && pwd)/$(basename "$1"); R="$2"; rm -rf "$R"; mkdir -p "$R"
osascript <<APPLESCRIPT
tell application "Numbers"
  set d to open POSIX file "$X"
  delay 1
  export d to POSIX file "$R/report.pdf" as PDF
  close d saving no
end tell
APPLESCRIPT
pdftoppm -r 70 -png "$R/report.pdf" "$R/page" && ls "$R"
