import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import {
  loadScanState,
  saveScanState,
  getFileState,
  updateFileState,
  deleteScanState,
  getStateFilePath,
  type ScanState,
  type FileState,
} from "../src/state";

/**
 * Tests for the incremental scan state module.
 *
 * We override $HOME to point at a temp directory so that
 * loadScanState / saveScanState / deleteScanState operate
 * on an isolated file without touching the real user config.
 */
describe("state module", () => {
  let tmpDir: string;
  let originalHome: string | undefined;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "shhh-state-test-"));
    originalHome = process.env.HOME;
    process.env.HOME = tmpDir;
  });

  afterEach(() => {
    if (originalHome !== undefined) {
      process.env.HOME = originalHome;
    } else {
      delete process.env.HOME;
    }
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // -----------------------------------------------------------------------
  // loadScanState
  // -----------------------------------------------------------------------
  describe("loadScanState", () => {
    it("should return a fresh empty state when no state file exists", () => {
      const state = loadScanState();
      expect(state).toHaveProperty("lastScan");
      expect(state).toHaveProperty("files");
      expect(typeof state.lastScan).toBe("string");
      expect(Object.keys(state.files).length).toBe(0);
    });

    it("should return a fresh empty state when the state file contains invalid JSON", () => {
      const stateDir = path.join(tmpDir, ".config", "shhh");
      fs.mkdirSync(stateDir, { recursive: true });
      fs.writeFileSync(path.join(stateDir, "scan-state.json"), "NOT VALID JSON", "utf-8");

      const state = loadScanState();
      expect(Object.keys(state.files).length).toBe(0);
      expect(typeof state.lastScan).toBe("string");
    });

    it("should return a fresh empty state when the state file has wrong shape", () => {
      const stateDir = path.join(tmpDir, ".config", "shhh");
      fs.mkdirSync(stateDir, { recursive: true });
      // Missing required fields
      fs.writeFileSync(
        path.join(stateDir, "scan-state.json"),
        JSON.stringify({ something: "else" }),
        "utf-8",
      );

      const state = loadScanState();
      expect(Object.keys(state.files).length).toBe(0);
    });

    it("should load a previously saved state from disk", () => {
      const saved: ScanState = {
        lastScan: "2025-01-15T10:00:00.000Z",
        files: {
          "/home/user/.claude/session.jsonl": {
            lastScannedByte: 1024,
            lastModified: "2025-01-15T09:30:00.000Z",
            findingsCount: 3,
          },
        },
      };

      const stateDir = path.join(tmpDir, ".config", "shhh");
      fs.mkdirSync(stateDir, { recursive: true });
      fs.writeFileSync(
        path.join(stateDir, "scan-state.json"),
        JSON.stringify(saved, null, 2),
        "utf-8",
      );

      const loaded = loadScanState();
      expect(loaded.lastScan).toBe("2025-01-15T10:00:00.000Z");
      expect(Object.keys(loaded.files)).toHaveLength(1);
      expect(loaded.files["/home/user/.claude/session.jsonl"]).toEqual({
        lastScannedByte: 1024,
        lastModified: "2025-01-15T09:30:00.000Z",
        findingsCount: 3,
      });
    });
  });

  // -----------------------------------------------------------------------
  // saveScanState
  // -----------------------------------------------------------------------
  describe("saveScanState", () => {
    it("should create the config directory and persist state to disk", () => {
      const state: ScanState = {
        lastScan: "2025-06-01T12:00:00.000Z",
        files: {
          "/tmp/test.jsonl": {
            lastScannedByte: 500,
            lastModified: "2025-06-01T11:00:00.000Z",
            findingsCount: 1,
          },
        },
      };

      saveScanState(state);

      const stateFile = path.join(tmpDir, ".config", "shhh", "scan-state.json");
      expect(fs.existsSync(stateFile)).toBe(true);

      const raw = fs.readFileSync(stateFile, "utf-8");
      const parsed = JSON.parse(raw);
      expect(parsed.lastScan).toBe("2025-06-01T12:00:00.000Z");
      expect(parsed.files["/tmp/test.jsonl"].lastScannedByte).toBe(500);
    });

    it("should overwrite an existing state file on second save", () => {
      const state1: ScanState = {
        lastScan: "2025-01-01T00:00:00.000Z",
        files: {},
      };
      saveScanState(state1);

      const state2: ScanState = {
        lastScan: "2025-02-01T00:00:00.000Z",
        files: {
          "/a/b.json": {
            lastScannedByte: 100,
            lastModified: "2025-02-01T00:00:00.000Z",
            findingsCount: 0,
          },
        },
      };
      saveScanState(state2);

      const loaded = loadScanState();
      expect(loaded.lastScan).toBe("2025-02-01T00:00:00.000Z");
      expect(Object.keys(loaded.files)).toHaveLength(1);
    });
  });

  // -----------------------------------------------------------------------
  // getFileState
  // -----------------------------------------------------------------------
  describe("getFileState", () => {
    it("should return null when the file has no prior state", () => {
      const state: ScanState = { lastScan: new Date().toISOString(), files: {} };
      expect(getFileState(state, "/nonexistent/path.json")).toBeNull();
    });

    it("should return the FileState for a tracked file", () => {
      const fileState: FileState = {
        lastScannedByte: 2048,
        lastModified: "2025-03-10T08:00:00.000Z",
        findingsCount: 5,
      };
      const state: ScanState = {
        lastScan: "2025-03-10T09:00:00.000Z",
        files: { "/home/user/.claude/log.jsonl": fileState },
      };

      const result = getFileState(state, "/home/user/.claude/log.jsonl");
      expect(result).toEqual(fileState);
    });
  });

  // -----------------------------------------------------------------------
  // updateFileState
  // -----------------------------------------------------------------------
  describe("updateFileState", () => {
    it("should add a new file entry to the state", () => {
      const state: ScanState = { lastScan: new Date().toISOString(), files: {} };
      updateFileState(state, "/tmp/new-file.jsonl", 4096, 2);

      const entry = state.files["/tmp/new-file.jsonl"];
      expect(entry).toBeDefined();
      expect(entry.lastScannedByte).toBe(4096);
      expect(entry.findingsCount).toBe(2);
      expect(typeof entry.lastModified).toBe("string");
      // lastModified should be a valid ISO date
      expect(new Date(entry.lastModified).toISOString()).toBe(entry.lastModified);
    });

    it("should overwrite an existing file entry", () => {
      const state: ScanState = {
        lastScan: new Date().toISOString(),
        files: {
          "/tmp/existing.jsonl": {
            lastScannedByte: 100,
            lastModified: "2025-01-01T00:00:00.000Z",
            findingsCount: 1,
          },
        },
      };

      updateFileState(state, "/tmp/existing.jsonl", 500, 3);

      const entry = state.files["/tmp/existing.jsonl"];
      expect(entry.lastScannedByte).toBe(500);
      expect(entry.findingsCount).toBe(3);
      // lastModified should be updated
      expect(entry.lastModified).not.toBe("2025-01-01T00:00:00.000Z");
    });
  });

  // -----------------------------------------------------------------------
  // deleteScanState
  // -----------------------------------------------------------------------
  describe("deleteScanState", () => {
    it("should return false when there is no state file to delete", () => {
      expect(deleteScanState()).toBe(false);
    });

    it("should delete the state file and return true", () => {
      // First create a state file
      saveScanState({ lastScan: new Date().toISOString(), files: {} });

      const stateFile = path.join(tmpDir, ".config", "shhh", "scan-state.json");
      expect(fs.existsSync(stateFile)).toBe(true);

      const result = deleteScanState();
      expect(result).toBe(true);
      expect(fs.existsSync(stateFile)).toBe(false);
    });

    it("should allow loadScanState to return empty state after deletion", () => {
      saveScanState({
        lastScan: "2025-01-01T00:00:00.000Z",
        files: { "/x": { lastScannedByte: 1, lastModified: "2025-01-01T00:00:00.000Z", findingsCount: 0 } },
      });

      deleteScanState();
      const state = loadScanState();
      expect(Object.keys(state.files)).toHaveLength(0);
    });
  });

  // -----------------------------------------------------------------------
  // Round-trip: save -> load -> getFileState
  // -----------------------------------------------------------------------
  describe("round-trip integration", () => {
    it("should survive a full save-load-query cycle", () => {
      const state: ScanState = { lastScan: new Date().toISOString(), files: {} };
      updateFileState(state, "/a/b/c.jsonl", 9999, 7);
      updateFileState(state, "/d/e/f.json", 42, 0);
      saveScanState(state);

      const loaded = loadScanState();
      expect(getFileState(loaded, "/a/b/c.jsonl")).toEqual(
        expect.objectContaining({ lastScannedByte: 9999, findingsCount: 7 }),
      );
      expect(getFileState(loaded, "/d/e/f.json")).toEqual(
        expect.objectContaining({ lastScannedByte: 42, findingsCount: 0 }),
      );
      expect(getFileState(loaded, "/nonexistent")).toBeNull();
    });
  });

  // -----------------------------------------------------------------------
  // getStateFilePath
  // -----------------------------------------------------------------------
  describe("getStateFilePath", () => {
    it("should return a path ending with scan-state.json inside .config/shhh", () => {
      const p = getStateFilePath();
      expect(p.endsWith("scan-state.json")).toBe(true);
      expect(p).toContain(".config");
      expect(p).toContain("shhh");
    });
  });

  // -----------------------------------------------------------------------
  // BUG-011: updateFileState records file mtime correctly
  // Previously updateFileState always used new Date() instead of the
  // file's actual mtime, causing incremental scans to never skip files.
  // -----------------------------------------------------------------------
  describe("updateFileState records file mtime (BUG-011)", () => {
    it("should record the provided mtime instead of current wall-clock time", () => {
      const state: ScanState = { lastScan: new Date().toISOString(), files: {} };
      const fakeMtime = new Date("2024-06-15T10:30:00.000Z");
      updateFileState(state, "/tmp/file.jsonl", 1024, 0, fakeMtime);

      const entry = state.files["/tmp/file.jsonl"];
      expect(entry.lastModified).toBe("2024-06-15T10:30:00.000Z");
    });

    it("should fall back to current time when mtime is not provided", () => {
      const state: ScanState = { lastScan: new Date().toISOString(), files: {} };
      const before = new Date().toISOString();
      updateFileState(state, "/tmp/file.jsonl", 1024, 0);
      const after = new Date().toISOString();

      const entry = state.files["/tmp/file.jsonl"];
      // The recorded time should be between before and after
      expect(entry.lastModified >= before).toBe(true);
      expect(entry.lastModified <= after).toBe(true);
    });

    it("should store linesScanned when provided", () => {
      const state: ScanState = { lastScan: new Date().toISOString(), files: {} };
      const mtime = new Date("2024-06-15T10:30:00.000Z");
      updateFileState(state, "/tmp/file.jsonl", 2048, 3, mtime, 150);

      const entry = state.files["/tmp/file.jsonl"];
      expect(entry.linesScanned).toBe(150);
    });

    it("should default linesScanned to 0 when not provided", () => {
      const state: ScanState = { lastScan: new Date().toISOString(), files: {} };
      updateFileState(state, "/tmp/file.jsonl", 2048, 3);

      const entry = state.files["/tmp/file.jsonl"];
      expect(entry.linesScanned).toBe(0);
    });
  });

  // -----------------------------------------------------------------------
  // BUG-012: loadScanState rejects arrays in files field
  // Previously typeof [] === "object" passed validation, allowing a
  // corrupted state file with an array in the files field.
  // -----------------------------------------------------------------------
  describe("loadScanState rejects arrays in files field (BUG-012)", () => {
    it("should return empty state when files is an array", () => {
      const stateDir = path.join(tmpDir, ".config", "shhh");
      fs.mkdirSync(stateDir, { recursive: true });
      fs.writeFileSync(
        path.join(stateDir, "scan-state.json"),
        JSON.stringify({ lastScan: "2025-01-01T00:00:00.000Z", files: [] }),
        "utf-8",
      );

      const state = loadScanState();
      expect(Object.keys(state.files)).toHaveLength(0);
      // Should be a plain object, not an array
      expect(Array.isArray(state.files)).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // BUG-013: loadScanState handles truncated/empty state file
  // -----------------------------------------------------------------------
  describe("loadScanState handles truncated state file (BUG-013)", () => {
    it("should return empty state for a zero-byte file", () => {
      const stateDir = path.join(tmpDir, ".config", "shhh");
      fs.mkdirSync(stateDir, { recursive: true });
      fs.writeFileSync(path.join(stateDir, "scan-state.json"), "", "utf-8");

      const state = loadScanState();
      expect(Object.keys(state.files)).toHaveLength(0);
      expect(typeof state.lastScan).toBe("string");
    });

    it("should return empty state for a truncated JSON fragment", () => {
      const stateDir = path.join(tmpDir, ".config", "shhh");
      fs.mkdirSync(stateDir, { recursive: true });
      fs.writeFileSync(
        path.join(stateDir, "scan-state.json"),
        '{"lastScan":"2025-01-',
        "utf-8",
      );

      const state = loadScanState();
      expect(Object.keys(state.files)).toHaveLength(0);
    });
  });
});
