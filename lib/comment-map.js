/**
 * comment-map.js
 * Builds a map of comment lines for a file before rules are applied.
 *
 * Returns a CommentMap object that classifies each line as:
 *   CODE    — no comment content on this line
 *   COMMENT — entire line is a comment (line comment or inside a block comment)
 *   MIXED   — line contains both code and an inline comment
 *
 * Usage:
 *   const map = buildCommentMap(content, 'js');
 *   map.isComment(lineNumber)   // true if line is COMMENT
 *   map.isMixed(lineNumber)     // true if line is MIXED
 *   map.lineType(lineNumber)    // 'CODE' | 'COMMENT' | 'MIXED'
 *
 * Design notes:
 * - Content is never modified — no side-effects on matchIndex or line-offsets.
 * - Block comments tracked via range state machine, not regex on each line.
 * - Inline comment detection is optional (disabled by default per config).
 * - Unsupported extensions return an empty map (all lines → CODE).
 * - Multi-line string literals (Python triple-quotes) treated as comments
 *   when used as docstrings (file/function level), not when assigned to a
 *   variable (those are data, not comments).
 *
 * Future: this module is designed to become a first-class scan step in the
 * proposed 6-step execution model. It produces structured line metadata that
 * can feed both the code scanner (skip COMMENT lines) and a dedicated comment
 * scanner (analyse COMMENT lines with separate rules or AI).
 */

'use strict';

// ── Line type constants ────────────────────────────────────────────────────
const LINE_TYPE = {
  CODE:    'CODE',
  COMMENT: 'COMMENT',
  MIXED:   'MIXED',
};

// ── Language comment syntax ────────────────────────────────────────────────
// Each entry defines:
//   lineStart   {string[]}  Prefixes that make an entire line a comment (trimmed)
//   blockOpen   {string}    Block comment open marker
//   blockClose  {string}    Block comment close marker
//   inlineStart {string[]}  Markers that begin an inline (end-of-line) comment
//
// Notes:
// - YAML and Shell have no block comments. # is both line and inline.
// - Python triple-quote strings are handled separately via TRIPLE_QUOTE_EXTS.
// - SQL uses -- for line comments and /* */ for block comments.
// - XML/HTML comments are <!-- --> and can span multiple lines.

const SYNTAX = {
  // JavaScript / TypeScript / C# / Java — C-style comments
  js:  { lineStart: ['//'], blockOpen: '/*', blockClose: '*/', inlineStart: ['//'] },
  mjs: { lineStart: ['//'], blockOpen: '/*', blockClose: '*/', inlineStart: ['//'] },
  cjs: { lineStart: ['//'], blockOpen: '/*', blockClose: '*/', inlineStart: ['//'] },
  ts:  { lineStart: ['//'], blockOpen: '/*', blockClose: '*/', inlineStart: ['//'] },
  jsx: { lineStart: ['//'], blockOpen: '/*', blockClose: '*/', inlineStart: ['//'] },
  tsx: { lineStart: ['//'], blockOpen: '/*', blockClose: '*/', inlineStart: ['//'] },
  cs:  { lineStart: ['//'], blockOpen: '/*', blockClose: '*/', inlineStart: ['//'] },
  go:  { lineStart: ['//'], blockOpen: '/*', blockClose: '*/', inlineStart: ['//'] },
  java: { lineStart: ['//'], blockOpen: '/*', blockClose: '*/', inlineStart: ['//'] },
  kt:  { lineStart: ['//'], blockOpen: '/*', blockClose: '*/', inlineStart: ['//'] },
  rs:  { lineStart: ['//'], blockOpen: '/*', blockClose: '*/', inlineStart: ['//'] },

  // PHP — supports both // and # as line comments, plus /* */
  php: { lineStart: ['//', '#'], blockOpen: '/*', blockClose: '*/', inlineStart: ['//', '#'] },

  // Python — # for line/inline; triple-quoted strings handled separately
  py:  { lineStart: ['#'], blockOpen: null, blockClose: null, inlineStart: ['#'] },

  // Shell / Bash / PowerShell
  sh:   { lineStart: ['#'], blockOpen: null, blockClose: null, inlineStart: ['#'] },
  bash: { lineStart: ['#'], blockOpen: null, blockClose: null, inlineStart: ['#'] },
  ps1:  { lineStart: ['#'], blockOpen: '<#', blockClose: '#>', inlineStart: ['#'] },

  // Ruby
  rb:  { lineStart: ['#'], blockOpen: '=begin', blockClose: '=end', inlineStart: ['#'] },

  // YAML — # only, no block comments
  yml:  { lineStart: ['#'], blockOpen: null, blockClose: null, inlineStart: ['#'] },
  yaml: { lineStart: ['#'], blockOpen: null, blockClose: null, inlineStart: ['#'] },

  // SQL
  sql:  { lineStart: ['--'], blockOpen: '/*', blockClose: '*/', inlineStart: ['--'] },

  // INI / CFG / properties — ; and # as line comments
  ini:        { lineStart: [';', '#'], blockOpen: null, blockClose: null, inlineStart: [';', '#'] },
  cfg:        { lineStart: [';', '#'], blockOpen: null, blockClose: null, inlineStart: [';', '#'] },
  conf:       { lineStart: [';', '#'], blockOpen: null, blockClose: null, inlineStart: [';', '#'] },
  properties: { lineStart: ['#', '!'], blockOpen: null, blockClose: null, inlineStart: [] },

  // XML / HTML — <!-- --> block comments only
  xml:  { lineStart: [], blockOpen: '<!--', blockClose: '-->', inlineStart: [] },
  html: { lineStart: [], blockOpen: '<!--', blockClose: '-->', inlineStart: [] },

  // ASP.NET / Web.config — same comment syntax as XML/HTML
  aspx:   { lineStart: [], blockOpen: '<!--', blockClose: '-->', inlineStart: [] },
  ascx:   { lineStart: [], blockOpen: '<!--', blockClose: '-->', inlineStart: [] },
  master: { lineStart: [], blockOpen: '<!--', blockClose: '-->', inlineStart: [] },
  config: { lineStart: [], blockOpen: '<!--', blockClose: '-->', inlineStart: [] },

  // Markdown — # headings are not executable, treat as comment-like.
  // Findings in Markdown headings/paragraphs are almost never actionable.
  md:  { lineStart: ['#'], blockOpen: null, blockClose: null, inlineStart: [] },

  // Backup/original files — inherit C-style // as default since most backed-up
  // source files are JS/TS/C#. Findings in backup files are rarely actionable.
  bak:  { lineStart: ['//'], blockOpen: '/*', blockClose: '*/', inlineStart: ['//'] },
  old:  { lineStart: ['//'], blockOpen: '/*', blockClose: '*/', inlineStart: ['//'] },
  orig: { lineStart: ['//'], blockOpen: '/*', blockClose: '*/', inlineStart: ['//'] },

  // Batch / Windows CMD — REM and ::
  bat:  { lineStart: ['rem ', 'rem\t', '::'], blockOpen: null, blockClose: null, inlineStart: [] },
  cmd:  { lineStart: ['rem ', 'rem\t', '::'], blockOpen: null, blockClose: null, inlineStart: [] },
};

// Extensions where triple-quoted strings act as docstrings/comments
// when at the start of a file, class, or function.
// We treat any triple-quoted string that starts on a line with no preceding code
// as a COMMENT block for the purposes of FP suppression.
const TRIPLE_QUOTE_EXTS = new Set(['py']);

// ── CommentMap ────────────────────────────────────────────────────────────

class CommentMap {
  /**
   * @param {Map<number, string>} lineTypes  Map of 1-based lineNumber → LINE_TYPE
   */
  constructor(lineTypes) {
    this._types = lineTypes;
  }

  /** Returns true if the line is entirely a comment (or inside a block comment). */
  isComment(lineNumber) {
    return this._types.get(lineNumber) === LINE_TYPE.COMMENT;
  }

  /** Returns true if the line has both code and an inline comment. */
  isMixed(lineNumber) {
    return this._types.get(lineNumber) === LINE_TYPE.MIXED;
  }

  /** Returns 'CODE' | 'COMMENT' | 'MIXED'. Defaults to 'CODE' for unknown lines. */
  lineType(lineNumber) {
    return this._types.get(lineNumber) || LINE_TYPE.CODE;
  }

  /** Total number of lines classified as COMMENT. */
  get commentCount() {
    let n = 0;
    for (const t of this._types.values()) if (t === LINE_TYPE.COMMENT) n++;
    return n;
  }

  /** Total number of lines classified as MIXED. */
  get mixedCount() {
    let n = 0;
    for (const t of this._types.values()) if (t === LINE_TYPE.MIXED) n++;
    return n;
  }
}

// ── Empty map (for unsupported extensions) ─────────────────────────────────
const EMPTY_MAP = new CommentMap(new Map());

// ── Builder ────────────────────────────────────────────────────────────────

/**
 * Build a CommentMap for the given file content and extension.
 *
 * @param {string} content         Full file content
 * @param {string} ext             File extension (lowercase, without dot)
 * @param {object} [opts]
 * @param {boolean} [opts.inline]  Classify MIXED lines (inline comments). Default: false.
 * @returns {CommentMap}
 */
function buildCommentMap(content, ext, opts = {}) {
  const syntax = SYNTAX[ext];
  if (!syntax) return EMPTY_MAP;

  const { inline = false } = opts;
  const lines    = content.split('\n');
  const lineTypes = new Map();

  // State for block comment tracking
  let inBlock = false;

  // State for Python triple-quote docstring tracking
  let inTriple     = false;
  let tripleMarker = null;  // '"""' or "'''"

  for (let i = 0; i < lines.length; i++) {
    const lineNum  = i + 1;           // 1-based
    const raw      = lines[i];
    const trimmed  = raw.trimStart();

    // ── Python triple-quote docstrings ───────────────────────────────────
    if (TRIPLE_QUOTE_EXTS.has(ext)) {
      if (inTriple) {
        // Inside a triple-quoted string — classify as COMMENT
        lineTypes.set(lineNum, LINE_TYPE.COMMENT);
        // Check if this line closes the triple quote
        const closeIdx = raw.indexOf(tripleMarker);
        if (closeIdx !== -1) {
          inTriple     = false;
          tripleMarker = null;
          // Line that closes the triple-quote is still COMMENT —
          // closing marker is part of the docstring
        }
        continue;
      }

      // Check if this line opens a triple-quoted string that acts as a docstring.
      // We treat it as a docstring (COMMENT) when the line starts with the marker
      // (possibly with leading whitespace) with no preceding code.
      const tripleOpen = trimmed.startsWith('"""') ? '"""'
                       : trimmed.startsWith("'''") ? "'''"
                       : null;

      if (tripleOpen) {
        // Check if the triple-quote closes on the same line (single-line docstring)
        const rest = trimmed.slice(3);
        const closeIdx = rest.indexOf(tripleOpen);
        if (closeIdx !== -1) {
          // Same-line triple-quote: classify as COMMENT
          lineTypes.set(lineNum, LINE_TYPE.COMMENT);
        } else {
          // Multi-line triple-quote opens here
          inTriple     = true;
          tripleMarker = tripleOpen;
          lineTypes.set(lineNum, LINE_TYPE.COMMENT);
        }
        continue;
      }
    }

    // ── Block comment state ──────────────────────────────────────────────
    if (syntax.blockOpen && syntax.blockClose) {
      if (inBlock) {
        lineTypes.set(lineNum, LINE_TYPE.COMMENT);
        // Check if the block closes on this line
        const closeIdx = raw.indexOf(syntax.blockClose);
        if (closeIdx !== -1) {
          inBlock = false;
          // If there is non-whitespace content after the close marker,
          // this line transitions back to CODE after the close — but since
          // the close marker itself is comment content, treat the whole line
          // as COMMENT for simplicity. The code after */ is rare and low-risk.
        }
        continue;
      }

      // Check if a block comment opens on this line
      const openIdx = raw.indexOf(syntax.blockOpen);
      if (openIdx !== -1) {
        // Verify no code precedes the block open on this line
        const before = raw.slice(0, openIdx).trim();

        // Check if the block also closes on this same line
        const afterOpen   = raw.slice(openIdx + syntax.blockOpen.length);
        const closeOnSame = afterOpen.indexOf(syntax.blockClose);

        if (before.length === 0) {
          // Block open starts the line — it's a COMMENT line
          if (closeOnSame !== -1) {
            // Opens and closes on same line — single-line block comment
            lineTypes.set(lineNum, LINE_TYPE.COMMENT);
          } else {
            // Block opens but doesn't close — mark as COMMENT, enter block state
            inBlock = true;
            lineTypes.set(lineNum, LINE_TYPE.COMMENT);
          }
        } else {
          // Code precedes the block open — MIXED line, block may continue
          if (closeOnSame === -1) {
            inBlock = true;
          }
          if (inline) {
            lineTypes.set(lineNum, LINE_TYPE.MIXED);
          }
          // If inline is off, this stays CODE — block tracking still applies
        }
        continue;
      }
    }

    // ── Line comment check ───────────────────────────────────────────────
    if (syntax.lineStart.length > 0) {
      // Batch files: 'rem' is case-insensitive
      const checkStr = ext === 'bat' || ext === 'cmd'
        ? trimmed.toLowerCase()
        : trimmed;

      const isLineComment = syntax.lineStart.some(prefix => checkStr.startsWith(prefix));
      if (isLineComment) {
        // ── Magic comment exception ────────────────────────────────────
        // JS/TS "magic comments" begin with //# or //@ and are runtime-
        // significant directives, not documentation:
        //   //# sourceMappingURL=file.js.map  (source maps — browser reads this)
        //   //@ sourceURL=file.js             (older source map syntax)
        //   //# sourceURL=...                 (eval source naming)
        // TypeScript compiler directives (// @ts-ignore etc.) are handled
        // separately: they start with "// @" (space before @) and are
        // intentionally classified as CODE per design decision 2026-05-15.
        if ((ext === 'js' || ext === 'ts' || ext === 'mjs' || ext === 'cjs' ||
             ext === 'jsx' || ext === 'tsx') &&
            (trimmed.startsWith('//#') || trimmed.startsWith('//@'))) {
          // Magic comment — treat as CODE, fall through
        } else {
          lineTypes.set(lineNum, LINE_TYPE.COMMENT);
          continue;
        }
      }
    }

    // ── Inline comment check (optional) ──────────────────────────────────
    if (inline && syntax.inlineStart.length > 0) {
      // Detect inline comment: look for the marker outside of string literals.
      // Full string-aware parsing is expensive; we use a heuristic:
      // find the first inline marker occurrence and check if it's likely
      // inside a string by counting unescaped quotes before it.
      const inlineMarker = findInlineCommentMarker(raw, syntax.inlineStart);
      if (inlineMarker !== -1) {
        lineTypes.set(lineNum, LINE_TYPE.MIXED);
        continue;
      }
    }

    // ── Default: CODE ─────────────────────────────────────────────────────
    // Don't set lineTypes for CODE lines — isComment() defaults to CODE.
    // This keeps the Map small (only COMMENT and MIXED lines stored).
  }

  return new CommentMap(lineTypes);
}

// ── Inline comment heuristic ──────────────────────────────────────────────

/**
 * Find the character index of an inline comment marker in a line,
 * using a simple heuristic to skip markers inside string literals.
 *
 * Returns -1 if no inline comment marker found outside a string.
 *
 * Heuristic: track whether we're inside a string by counting unescaped
 * quote characters. Not perfect for complex cases (nested quotes, template
 * literals) but sufficient for the common cases we care about.
 *
 * @param {string}   line     Raw line content
 * @param {string[]} markers  List of inline comment marker strings
 * @returns {number}          Index of marker, or -1
 */
function findInlineCommentMarker(line, markers) {
  let inString   = false;
  let stringChar = null;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];

    // Toggle string state on unescaped quote characters
    if (!inString && (ch === '"' || ch === "'" || ch === '`')) {
      inString   = true;
      stringChar = ch;
      continue;
    }
    if (inString && ch === stringChar && line[i - 1] !== '\\') {
      inString   = false;
      stringChar = null;
      continue;
    }

    // Skip characters inside strings
    if (inString) continue;

    // Check each marker at current position
    for (const marker of markers) {
      if (line.startsWith(marker, i)) {
        return i;
      }
    }
  }

  return -1;
}

module.exports = { buildCommentMap, CommentMap, LINE_TYPE };
