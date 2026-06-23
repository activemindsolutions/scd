'use strict';
/**
 * terminal-links.js
 * OSC 8 hyperlinks — clickable text in terminals that support it. Single source for
 * OSC 8 across the CLI (previously duplicated in output-terminal.js / scan.js / report.js).
 *
 * Only emitted in terminals known to support OSC 8; everywhere else the plain display
 * text is returned, never a raw escape sequence. CMD/Ctrl+click follows the URI via the
 * OS handler — for source files that opens the file in the user's default editor.
 */

const path = require('path');

const SUPPORTS_OSC8 = (() => {
  // Never emit hyperlink escapes to a non-TTY (a pipe, a redirect to a file, a CI log) —
  // the raw OSC 8 sequences would corrupt that output. Links are an interactive nicety only.
  if (!process.stdout.isTTY) return false;
  const prog  = process.env.TERM_PROGRAM  ?? '';
  const emul  = process.env.TERM_EMULATOR ?? '';
  const vte   = process.env.VTE_VERSION   ?? '';
  const color = process.env.COLORTERM     ?? '';
  return (
    prog === 'iTerm.app'          ||  // iTerm2
    prog === 'vscode'             ||  // VS Code integrated terminal
    prog === 'WarpTerminal'       ||  // Warp
    prog === 'ghostty'            ||  // Ghostty
    emul === 'JetBrains-JediTerm' ||  // JetBrains IDEs (IntelliJ, WebStorm, …)
    (color === 'truecolor' && vte !== '') // VTE-based: GNOME Terminal, Tilix, …
  );
})();

const ESC = '\x1b';

// Wrap display text in an OSC 8 hyperlink to `uri`. Plain text when unsupported.
function hyperlink(uri, display) {
  if (!SUPPORTS_OSC8) return display;
  return `${ESC}]8;;${uri}${ESC}\\${display}${ESC}]8;;${ESC}\\`;
}

// Link display text to a source file. macOS cannot open 'file.js:12', so the line
// number never enters the URI — it stays in the display text only.
function fileLink(relativePath, lineNum = null, displayText = null) {
  const display = displayText ?? (lineNum ? `${relativePath}:${lineNum}` : relativePath);
  const abs = path.resolve(process.cwd(), relativePath);
  return hyperlink(`file://${abs}`, display);
}

// Link display text to a source file given an already-resolved absolute path.
function sourceLink(absPath, display) {
  return hyperlink(`file://${absPath}`, display);
}

module.exports = { SUPPORTS_OSC8, hyperlink, fileLink, sourceLink };
