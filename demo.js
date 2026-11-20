/* SHA-256 และ HMAC แบบทำงานทันที (ระบบหลังบ้านเรียกแบบไม่รอ) ใช้เฉพาะโหมดตัวอย่าง */
var DemoSHA = (function () {
  var K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
  function sha256(bytes) {
    var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var m = Array.prototype.slice.call(bytes), bits = m.length * 8;
    m.push(0x80);
    while (m.length % 64 !== 56) m.push(0);
    var hi = Math.floor(bits / 0x100000000), lo = bits >>> 0;
    m.push((hi >>> 24) & 255, (hi >>> 16) & 255, (hi >>> 8) & 255, hi & 255, (lo >>> 24) & 255, (lo >>> 16) & 255, (lo >>> 8) & 255, lo & 255);
    var W = new Array(64);
    for (var i = 0; i < m.length; i += 64) {
      var t;
      for (t = 0; t < 16; t++) W[t] = (m[i + 4 * t] << 24) | (m[i + 4 * t + 1] << 16) | (m[i + 4 * t + 2] << 8) | m[i + 4 * t + 3];
      for (t = 16; t < 64; t++) {
        var x = W[t - 15], y = W[t - 2];
        var s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        var s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        W[t] = (W[t - 16] + s0 + W[t - 7] + s1) | 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (t = 0; t < 64; t++) {
        var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        var t1 = (h + S1 + ((e & f) ^ (~e & g)) + K[t] + W[t]) | 0;
        var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        var t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }
    var out = [];
    H.forEach(function (v) { out.push((v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255); });
    return out;
  }
  function hmac(key, msg) {
    if (key.length > 64) key = sha256(key);
    var k = Array.prototype.slice.call(key);
    while (k.length < 64) k.push(0);
    var o = k.map(function (b) { return b ^ 0x5c; }), ip = k.map(function (b) { return b ^ 0x36; });
    return sha256(o.concat(sha256(ip.concat(Array.prototype.slice.call(msg)))));
  }
  function utf8(s) { return Array.prototype.slice.call(new TextEncoder().encode(String(s))); }
  return { sha256: sha256, hmac: hmac, utf8: utf8 };
})();

/* ===== สมุดสุขภาพ โหมดตัวอย่าง =====
 * จำลอง Google Sheet และ Google Drive ไว้ในเครื่อง แล้วรันระบบหลังบ้านตัวจริง (Code.gs) ในเบราว์เซอร์
 * ข้อมูลทั้งหมดอยู่ในเครื่องนี้เท่านั้น ไม่ส่งไปไหน ใช้สาธิตและทดลองก่อนเชื่อมระบบจริง */
(function () {
  'use strict';
  var STORE = 'healthbook.demo.data', FSTORE = 'healthbook.demo.files', VERSION = 14;
  var sheets = {}, props = {}, files = {}, folders = {}, nId = 0;

  /* ---------- ชีต ---------- */
  function cellVal(v) {
    if (v instanceof Date) return v.toISOString();
    return (typeof v === 'string' && v.charAt(0) === "'") ? v.slice(1) : v;
  }
  function makeSheet(name, cells, hidden) {
    cells = cells || [];
    var sh = {
      name: name, cells: cells, hidden: !!hidden,
      getName: function () { return sh.name; },
      setName: function (n) { delete sheets[sh.name]; sh.name = n; sheets[n] = sh; return sh; },
      getLastRow: function () { for (var r = cells.length - 1; r >= 0; r--) if (cells[r] && cells[r].some(function (v) { return v !== '' && v !== null && v !== undefined; })) return r + 1; return 0; },
      getLastColumn: function () { return cells.reduce(function (m, r) { return Math.max(m, r ? r.length : 0); }, 0); },
      getRange: function (r, c, nr, nc) {
        nr = nr || 1; nc = nc || 1;
        var rg = {
          getValues: function () {
            var o = [];
            for (var i = 0; i < nr; i++) { var row = []; for (var j = 0; j < nc; j++) { var v = (cells[r - 1 + i] || [])[c - 1 + j]; row.push(v === undefined || v === null ? '' : v); } o.push(row); }
            return o;
          },
          setValues: function (vals) { vals.forEach(function (row, i) { row.forEach(function (v, j) { cells[r - 1 + i] = cells[r - 1 + i] || []; cells[r - 1 + i][c - 1 + j] = cellVal(v); }); }); return rg; },
          setValue: function (v) { cells[r - 1] = cells[r - 1] || []; cells[r - 1][c - 1] = cellVal(v); return rg; },
          getValue: function () { var v = (cells[r - 1] || [])[c - 1]; return v === undefined || v === null ? '' : v; },
          getRow: function () { return r; }, getColumn: function () { return c; }, getNumRows: function () { return nr; }, getNumColumns: function () { return nc; },
          getSheet: function () { return sh; },
          createTextFinder: function (text) {
            var tf = {
              entire: false, matchEntireCell: function (b) { tf.entire = b; return tf; },
              _all: function () {
                var out = [];
                for (var i = 0; i < nr; i++) for (var j = 0; j < nc; j++) {
                  var v = (cells[r - 1 + i] || [])[c - 1 + j]; v = String(v === undefined || v === null ? '' : v);
                  if (tf.entire ? v === String(text) : v.indexOf(String(text)) >= 0) out.push(sh.getRange(r + i, c + j));
                }
                return out;
              },
              findNext: function () { return tf._all()[0] || null; }, findAll: function () { return tf._all(); }
            };
            return tf;
          },
          sort: function (o) {
            var col = (typeof o === 'object' ? o.column : o) - c, asc = typeof o === 'object' ? o.ascending !== false : true, rows = [];
            for (var i = 0; i < nr; i++) rows.push((cells[r - 1 + i] || []).slice());
            var key = function (x) { var v = x[col]; return v === undefined || v === '' || v === null ? null : String(v); };
            rows.sort(function (a, b) { var ka = key(a), kb = key(b); if (ka === kb) return 0; if (ka === null) return 1; if (kb === null) return -1; return (ka < kb ? -1 : 1) * (asc ? 1 : -1); });
            rows.forEach(function (row, i) { cells[r - 1 + i] = row; });
            return rg;
          }
        };
        ['setNumberFormat', 'setDataValidation', 'setNote', 'setFontWeight', 'setBackground', 'setWrap', 'setVerticalAlignment', 'setFontSize', 'setBorder', 'setHorizontalAlignment', 'setFontColor'].forEach(function (k) { rg[k] = function () { return rg; }; });
        return rg;
      },
      appendRow: function (row) { cells[sh.getLastRow()] = row.map(cellVal); },
      hideSheet: function () { sh.hidden = true; }, isSheetHidden: function () { return sh.hidden; },
      setFrozenRows: function () {}, setColumnWidth: function () {}, setColumnWidths: function () {}, setRowHeights: function () {},
      deleteRow: function (r) { cells.splice(r - 1, 1); }, clear: function () { cells.length = 0; }, clearContents: function () { cells.length = 0; },
      autoResizeColumns: function () {}, setTabColor: function () {}
    };
    return sh;
  }
  var ss = {
    getSheetByName: function (n) { return sheets[n] || null; },
    insertSheet: function (n) { return (sheets[n] = makeSheet(n)); },
    getSheets: function () { return Object.keys(sheets).map(function (k) { return sheets[k]; }); },
    deleteSheet: function (s) { delete sheets[s.name]; },
    setSpreadsheetTimeZone: function () {}, getSpreadsheetTimeZone: function () { return 'Asia/Bangkok'; }, toast: function () {}, getUrl: function () { return ''; }
  };
  var builder = function () { var b = { requireValueInList: function () { return b; }, setAllowInvalid: function () { return b; }, build: function () { return {}; } }; return b; };

  /* ---------- เครื่องมือ ---------- */
  function toSigned(arr) { var o = new Int8Array(arr.length); for (var i = 0; i < arr.length; i++) o[i] = arr[i] > 127 ? arr[i] - 256 : arr[i]; return o; }
  function b64(bytes) {
    var s = '', CH = 0x8000;
    for (var i = 0; i < bytes.length; i += CH) {
      var part = Array.prototype.slice.call(bytes, i, i + CH).map(function (x) { return (x + 256) % 256; });
      s += String.fromCharCode.apply(null, part);
    }
    return btoa(s);
  }
  function unb64(s) {
    var bin = atob(String(s).replace(/\s/g, '')), o = new Int8Array(bin.length);
    for (var i = 0; i < bin.length; i++) { var c = bin.charCodeAt(i); o[i] = c > 127 ? c - 256 : c; }
    return o;
  }
  function fmt(d, tz, f) {
    var t = new Date(d.getTime() + 7 * 3600e3), p = function (n) { return ('0' + n).slice(-2); };
    var map = { yyyy: t.getUTCFullYear(), MM: p(t.getUTCMonth() + 1), dd: p(t.getUTCDate()), HH: p(t.getUTCHours()), mm: p(t.getUTCMinutes()), ss: p(t.getUTCSeconds()) };
    return f.replace(/yyyy|MM|dd|HH|mm|ss/g, function (k) { return map[k]; });
  }
  function uuid() {
    if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) { var r = Math.random() * 16 | 0; return (c === 'x' ? r : (r & 3 | 8)).toString(16); });
  }
  var Utilities = {
    formatDate: fmt,
    computeDigest: function (alg, text) { return toSigned(DemoSHA.sha256(DemoSHA.utf8(text))); },
    computeHmacSha256Signature: function (text, key) { return toSigned(DemoSHA.hmac(DemoSHA.utf8(key), DemoSHA.utf8(text))); },
    getUuid: uuid,
    base64Encode: b64, base64Decode: unb64,
    base64EncodeWebSafe: function (s) { return b64(DemoSHA.utf8(s)).replace(/\+/g, '-').replace(/\//g, '_'); },
    newBlob: function (bytes, mime, name) { return { bytes: bytes, mime: mime, name: name, setName: function (n) { this.name = n; return this; }, getBytes: function () { return bytes; }, getContentType: function () { return mime; } }; },
    DigestAlgorithm: { SHA_256: 'sha256' }, Charset: { UTF_8: 'utf8' }
  };
  var PropertiesService = { getScriptProperties: function () { return { getProperty: function (k) { return props.hasOwnProperty(k) ? props[k] : null; }, setProperty: function (k, v) { props[k] = String(v); }, deleteProperty: function (k) { delete props[k]; } }; } };
  var LockService = { getScriptLock: function () { return { waitLock: function () {}, tryLock: function () { return true; }, releaseLock: function () {} }; } };
  function fileObj(f) {
    var isImg = /^image\//.test(f.mime);
    return {
      getId: function () { return f.id; }, getName: function () { return f.name; },
      getUrl: function () { return 'https://drive.google.com/file/d/' + f.id + '/view'; },
      setTrashed: function (b) { f.trashed = !!b; }, isTrashed: function () { return f.trashed; },
      getThumbnail: function () { return isImg && f.bytes ? { getBytes: function () { return f.bytes; }, getContentType: function () { return f.mime; } } : null; },
      getBlob: function () { return { getBytes: function () { return f.bytes || new Int8Array(0); }, getContentType: function () { return f.mime; } }; },
      getDateCreated: function () { return new Date(f.at || Date.now()); }
    };
  }
  function folderObj(id) {
    var fo = folders[id];
    return {
      getId: function () { return id; }, getName: function () { return fo.name; }, isTrashed: function () { return false; },
      getUrl: function () { return 'https://drive.google.com/drive/folders/' + id; },
      createFile: function (blob) {
        var fid = 'DEMO' + (++nId) + Math.random().toString(36).slice(2, 8);
        files[fid] = { id: fid, name: blob.name, mime: blob.mime, bytes: blob.bytes, trashed: false, at: Date.now(), folder: id };
        return fileObj(files[fid]);
      },
      getFiles: function () {
        var list = Object.keys(files).filter(function (k) { return files[k].folder === id && !files[k].trashed; }), i = 0;
        return { hasNext: function () { return i < list.length; }, next: function () { return fileObj(files[list[i++]]); } };
      }
    };
  }
  var DriveApp = {
    createFolder: function (name) { var id = 'DFOLDER' + (++nId); folders[id] = { name: name }; return folderObj(id); },
    getFolderById: function (id) { if (!folders[id]) throw new Error('no folder'); return folderObj(id); },
    getFileById: function (id) { if (!files[id]) throw new Error('no file'); return fileObj(files[id]); }
  };
  var ContentService = { createTextOutput: function (s) { return { body: s, setMimeType: function () { return this; } }; }, MimeType: { JSON: 'json' } };
  var CacheService = { getScriptCache: function () { return { get: function () { return null; }, put: function () {}, remove: function () {} }; } };
  var ScriptApp = { getProjectTriggers: function () { return []; } };
  /* ค่าฝุ่นตัวอย่าง (โหมดตัวอย่างต่อ Air4Thai ไม่ได้) */
  var UrlFetchApp = { fetch: function () {
    var t = new Date(), d = t.getFullYear() + '-' + ('0' + (t.getMonth() + 1)).slice(-2) + '-' + ('0' + t.getDate()).slice(-2);
    var body = { stations: [{ stationID: 'demo', nameTH: 'เขตปทุมวัน (ข้อมูลตัวอย่าง)', lat: '13.7465', long: '100.5182', AQILast: { date: d, time: ('0' + t.getHours()).slice(-2) + ':00', PM25: { value: (44 + Math.random() * 20).toFixed(1) } } }] };
    return { getResponseCode: function () { return 200; }, getContentText: function () { return JSON.stringify(body); } };
  } };
  var Session = { getActiveUser: function () { return { getEmail: function () { return ''; } }; }, getEffectiveUser: function () { return { getEmail: function () { return ''; } }; } };
  var SpreadsheetApp = { getActive: function () { return ss; }, getActiveSpreadsheet: function () { return ss; }, newDataValidation: builder };

  /* ---------- ระบบหลังบ้านตัวจริง (Code.gs) ---------- */
  var GS = (function (SpreadsheetApp, Utilities, PropertiesService, LockService, DriveApp, ContentService, CacheService, ScriptApp, Session, UrlFetchApp) {
/**
 * สมุดสุขภาพ (พัฒนาจากฟิตเควส): ระบบเก็บบันทึกการขยับที่บ้าน (Google Apps Script + Google Sheets)
 * ใช้คู่กับหน้าเว็บ index.html ที่วางบนเว็บแยกต่างหาก แบบโปรแกรมกระโดดเชือก
 *
 * วิธีติดตั้งโดยย่อ
 *   1) เปิด Google Sheet ใหม่ > ส่วนขยาย > Apps Script > วางโค้ดนี้ทั้งหมด > บันทึก
 *   2) เปิดชีตใหม่ กดเมนู สมุดสุขภาพ > 1) ตั้งค่าครั้งแรก
 *   3) ใส่วันเริ่มโปรแกรม (วันจันทร์) ในแท็บตั้งค่า
 *   4) การทำให้ใช้งานได้ > การทำให้ใช้งานได้รายการใหม่ > เว็บแอป
 *      ดำเนินการในฐานะ: ฉัน / ผู้ที่มีสิทธิ์เข้าถึง: ทุกคน
 *   5) กดเมนู สมุดสุขภาพ > ให้ระบบทำงานเองทุกชั่วโมง (สร้างอันดับ + แคชให้แอปเปิดเร็วตลอดปี)
 *
 * ห้ามกด "เรียงข้อมูล" ในแท็บบันทึกและภารกิจที่ทำ (ใช้ "มุมมองตัวกรอง" แทน) ถ้าเผลอเรียง ระบบเรียงกลับให้ทุกชั่วโมง
 *
 * นักเรียนสมัครเองด้วยเลขประจำตัว ชื่อ-สกุล ชั้น ป.1–ป.6 ห้อง เลขที่ และ PIN 4–6 หลัก
 * ครูรีเซ็ต PIN ได้โดยลบช่อง PIN ในแท็บนักเรียน แล้วให้นักเรียนกด สมัครครั้งแรก อีกครั้ง
 * @OnlyCurrentDoc
 */
var APP_VERSION = 2;
var APP_NAME = 'สมุดสุขภาพ';

/* ===== สมุดสุขภาพ: กติกากลาง (ใช้ร่วมกันทั้งฝั่ง Apps Script และหน้าเว็บโหมดเดโม) ===== */
var FQ = (function () {
  'use strict';

  var ACTIVITIES = [
    { id: 'run', label: 'วิ่งหรือเดินเร็ว', icon: '🏃', out: true },
    { id: 'bike', label: 'ปั่นจักรยาน', icon: '🚲', out: true },
    { id: 'rope', label: 'กระโดดเชือก', icon: '🦘' },
    { id: 'dance', label: 'เต้น', icon: '💃' },
    { id: 'sport', label: 'เล่นกีฬา', icon: '⚽', out: true },
    { id: 'play', label: 'เล่นกลางแจ้ง', icon: '🌳', out: true },
    { id: 'quest', label: 'ท่าเควสที่ครูสอน', icon: '🐾' },
    { id: 'stretch', label: 'ยืดเหยียด', icon: '🧘' },
    { id: 'homequest', label: 'เควสบ้านสัปดาห์นี้', icon: '⭐' },
    { id: 'other', label: 'อื่น ๆ', icon: '✨' }
  ];

  var FEELINGS = [
    { id: 'fun', label: 'สนุก', icon: '😄' },
    { id: 'ok', label: 'เฉย ๆ', icon: '😐' },
    { id: 'notfun', label: 'ไม่สนุก', icon: '🙁' }
  ];

  var DEFAULTS = {
    schoolName: '',
    minMinutesForStar: 15,
    starCapPerWeek: 2,
    backfillDays: 2,
    maxMinutesPerLog: 60,
    maxMinutesPerDay: 120,
    maxLogsPerDay: 6,
    programStart: '',
    programWeeks: 8,
    /* แต้มและระดับ ออกแบบให้เด็กที่ทำสม่ำเสมอถึงระดับ 10 เมื่อทำครบ ~150 วัน (ครูแก้ได้ในแท็บตั้งค่า) */
    xpPerMinute: 1,
    xpMinuteCap: 60,
    xpPerStar: 20,
    xpMissionDiff: [10, 15, 20],
    diffUnlock: [4, 7],
    xpPhotoBonus: 10,      /* โบนัสรูปแบบเก่า: ยังนับให้แถวเก่าที่เคยส่งรูป และแถว สาธิตในคาบ */
    xpMissionVideo: 30,    /* เควสบ้านประจำสัปดาห์ (กดทำแล้ว) */
    /* คลิปในการ์ดภารกิจและเควสบ้าน: ดูครบ clipSeconds วินาที หรือจนจบคลิปที่สั้นกว่า ได้ xpClip */
    xpClip: 10,
    clipSeconds: 180,
    /* โหมดฝุ่น PM2.5: ดึงค่าจาก Air4Thai สถานีใกล้โรงเรียนทุกชั่วโมง ถึงระดับ dustFrom (4 = ส้ม) = วันฝุ่น */
    dustOn: true,
    dustFrom: 4,
    dustLat: 13.746,
    dustLng: 100.518,
    dustStation: '',
    xpDust: 10,
    xpStreak3: 15,
    xpStreak7: 50,
    streakRest: 1,
    dayBadges: [{ days: 30, xp: 100 }, { days: 60, xp: 200 }, { days: 90, xp: 300 }, { days: 120, xp: 400 }, { days: 150, xp: 500 }],
    levelXp: [0, 200, 700, 1500, 3000, 4500, 6500, 9000, 11500, 14000],
    legendStep: 2000,
    /* ระยะเก็บไฟล์รูปและวิดีโอหลักฐานแบบเก่า (ก่อนเปลี่ยนเป็นคลิป) */
    proofOn: true,
    photoKeepDays: 30,
    videoKeepDays: 14,
    /* เป้าสัปดาห์ปรับตามตัวเด็ก: ถึงเป้า → สัปดาห์ต่อไป +10% / ไม่ถึง → ใช้เป้าเดิม (ไม่เกิน 420 นาทีตาม WHO) */
    weekGoalStart: 60,
    weekGoalStep: 10,
    weekGoalMax: 420,
    xpWeekGoal: 20,
    /* อันดับ: ลีกตามภาค และห้องแข่งห้อง (นับ % เพื่อนในห้องที่ขยับสัปดาห์นี้) */
    roomMinMembers: 5,
    leagueSize: 10,
    /* คำถามสุขภาพวันละข้อ และอีเวนต์เทศกาล */
    xpQuizRight: 5,
    xpQuizWrong: 1,
    xpEvent: 50,
    /* โหมดครู */
    missingDays: 7,
    sidLen: 4,
    termNow: '',
    /* 6B-26: ทั้งโรงเรียนเดินทางด้วยก้าว (นาทีรวม × ก้าวต่อนาที × 0.5 เมตร) */
    stepsPerMin: 100
  };

  /* ฉายา 10 ระดับ: นักกีฬา → พลังธาตุ → อวกาศ → ตำนาน */
  var LEVELS = [
    { lv: 1, icon: '🌱', title: 'นักกีฬาฝึกหัด', arc: 1 },
    { lv: 2, icon: '👟', title: 'ดาวรุ่งพุ่งแรง', arc: 1 },
    { lv: 3, icon: '🧢', title: 'กัปตันทีม', arc: 1 },
    { lv: 4, icon: '💨', title: 'นักกีฬาพลังลม', arc: 2 },
    { lv: 5, icon: '🔥', title: 'ฮีโร่พลังไฟ', arc: 2 },
    { lv: 6, icon: '⚡', title: 'ฮีโร่สายฟ้า', arc: 2 },
    { lv: 7, icon: '🚀', title: 'ฮีโร่ทะยานฟ้า', arc: 3 },
    { lv: 8, icon: '🌙', title: 'ผู้พิชิตดวงจันทร์', arc: 3 },
    { lv: 9, icon: '🌌', title: 'ผู้พิทักษ์กาแล็กซี', arc: 3 },
    { lv: 10, icon: '🏆', title: 'แชมป์ตำนานแห่งจักรวาล', arc: 4 }
  ];
  var ARCS = { 1: '🏟️ ภาค 1 สนามกีฬา', 2: '⚡ ภาค 2 ปลุกพลังธาตุ', 3: '🚀 ภาค 3 ทะยานสู่อวกาศ', 4: '👑 ตำนาน' };

  var BADGE_ICONS = ['🥉', '🥈', '🥇', '💎', '👑'];
  var DIFF_STARS = ['', '⭐', '⭐⭐', '⭐⭐⭐'];

  var MISSION_TYPES = [
    { id: 'move', label: 'ภารกิจขยับ', sheet: 'ขยับ', icon: '🏃' },
    { id: 'habit', label: 'ภารกิจสุขนิสัย', sheet: 'สุขนิสัย', icon: '💧' }
  ];

  /* ภารกิจตั้งต้น: ทำในบ้านได้ ไม่ต้องใช้อุปกรณ์ ไม่มีเรื่องลดอาหารหรือน้ำหนัก
   * steps = ขั้น 1–4 จากง่ายไปยาก: ป.1–3 ใช้ขั้น 1–3 และ ป.4–6 ใช้ขั้น 2–4 ตามความยาก ⭐ / ⭐⭐ / ⭐⭐⭐
   * clip = คลิปตั้งต้น (YouTube ภาษาไทย ส่วนใหญ่จาก Thai PBS Kids / Thai PBS / ALTV) ครูเปลี่ยนได้ในแท็บภารกิจประจำวัน */
  var DEFAULT_MISSIONS = [
    { type: 'move', steps: ['กระโดดตบ 10 ครั้ง ทำ 2 รอบ', 'กระโดดตบ 15 ครั้ง ทำ 2 รอบ', 'กระโดดตบ 20 ครั้ง ทำ 3 รอบ', 'กระโดดตบ 30 ครั้ง ทำ 3 รอบ'], clip: 'https://www.youtube.com/watch?v=lfz9euKMUVM' },
    { type: 'move', steps: ['ยืนขาเดียวนับ 1–10 สลับขา (ยืนใกล้ผนัง)', 'ยืนขาเดียวนับ 1–20 สลับขา', 'ยืนขาเดียวนับ 1–30 สลับขา ทำ 2 รอบ', 'ยืนขาเดียวกางแขนเป็นเครื่องบิน นับ 1–30 สลับขา ทำ 2 รอบ'], clip: 'https://www.youtube.com/watch?v=2glgs3rH5wI' },
    { type: 'move', steps: ['ย่อเข่าเหมือนนั่งเก้าอี้ 10 ครั้ง', 'ย่อเข่าเหมือนนั่งเก้าอี้ 15 ครั้ง ทำ 2 รอบ', 'สควอต 20 ครั้ง ทำ 2 รอบ', 'สควอต 20 ครั้ง ทำ 3 รอบ'], clip: 'https://www.youtube.com/watch?v=0rRNgN8AIZE' },
    { type: 'move', steps: ['เดินหมี 5 ก้าว ไป–กลับ', 'เดินหมี 10 ก้าว ไป–กลับ', 'เดินหมี 10 ก้าว ไป–กลับ 2 รอบ', 'เดินหมี 15 ก้าว ไป–กลับ 3 รอบ'], clip: 'https://www.youtube.com/watch?v=7piw3N1ktBM' },
    { type: 'move', steps: ['กระโดดสองขาไปข้างหน้า 10 ครั้ง', 'กระโดดสองขาไปหน้า–ถอยหลัง 15 ครั้ง', 'กระโดดขาเดียว 10 ครั้ง สลับขา', 'กระโดดขาเดียว 15 ครั้ง สลับขา ทำ 2 รอบ'], clip: 'https://www.youtube.com/watch?v=KE5obR2OCI8' },
    { type: 'move', steps: ['วิ่งอยู่กับที่ 1 นาที', 'วิ่งอยู่กับที่ 2 นาที', 'วิ่งยกเข่าสูงอยู่กับที่ 1 นาที ทำ 2 รอบ', 'วิ่งยกเข่าสูงอยู่กับที่ 1 นาที ทำ 3 รอบ'], clip: 'https://www.youtube.com/watch?v=yOH447sHsc0' },
    { type: 'move', steps: ['ท่ากระดานวางเข่า ค้างนับ 1–10', 'ท่ากระดาน ค้างนับ 1–15', 'ท่ากระดาน ค้าง 30 วินาที', 'ท่ากระดาน ค้าง 30 วินาที ทำ 2 รอบ'], clip: 'https://www.youtube.com/watch?v=KioEA8eVoBw' },
    { type: 'move', steps: ['โยนรับลูกบอลหรือก้อนกระดาษ 10 ครั้ง', 'โยนรับลูกบอลหรือก้อนกระดาษ 20 ครั้ง', 'โยนลูกบอลกระทบผนังแล้วรับ 20 ครั้ง', 'โยนลูกบอลกระทบผนังแล้วรับ 30 ครั้ง สลับมือ'], clip: 'https://www.youtube.com/watch?v=Kzqf_fDE7oE' },
    { type: 'move', steps: ['เต้นตามเพลงที่ชอบ 1 เพลง', 'เต้นตามเพลงที่ชอบ 2 เพลง', 'เต้นตามเพลงที่ชอบ 2 เพลงไม่หยุด', 'เต้นตามเพลงที่ชอบ 3 เพลงไม่หยุด'], clip: 'https://www.youtube.com/watch?v=zPAafZ7ZTh0' },
    { type: 'move', steps: ['ก้มแตะปลายเท้า ค้างนับ 1–10 ทำ 2 ครั้ง', 'ก้มแตะปลายเท้า ค้างนับ 1–10 ทำ 3 ครั้ง', 'ยืดเหยียด 4 ท่า ท่าละนับ 1–15', 'ยืดเหยียด 5 ท่า ท่าละนับ 1–20'], clip: 'https://www.youtube.com/watch?v=-dr9oKW1oHw' },
    { type: 'move', steps: ['เดินเขย่งปลายเท้า 10 ก้าว', 'เดินเขย่งปลายเท้า 20 ก้าว', 'เดินเขย่ง 30 ก้าว แล้วเดินด้วยส้นเท้า 30 ก้าว', 'เดินเขย่ง 40 ก้าว แล้วเดินด้วยส้นเท้า 40 ก้าว'], clip: 'https://www.youtube.com/watch?v=2kCHSgkaWkg' },
    { type: 'move', steps: ['กระโดดข้ามเส้นซ้าย–ขวา 10 ครั้ง', 'กระโดดข้ามเส้นซ้าย–ขวา 20 ครั้ง', 'กระโดดข้ามเส้นซ้าย–ขวา 30 ครั้ง', 'กระโดดข้ามเส้นซ้าย–ขวา 30 ครั้ง ทำ 2 รอบ'], clip: 'https://www.youtube.com/watch?v=liBGuFPdKdM' },
    { type: 'move', steps: ['เดินปู 5 ก้าว ไป–กลับ', 'เดินปู 10 ก้าว ไป–กลับ', 'เดินปู 10 ก้าว ไป–กลับ 2 รอบ', 'เดินปู 15 ก้าว ไป–กลับ 3 รอบ'], clip: 'https://www.youtube.com/watch?v=i6zJqgrGq-k' },
    { type: 'move', outdoor: true, steps: ['เดินเร็วกับผู้ใหญ่ 5 นาที', 'เดินเร็วกับผู้ใหญ่ 10 นาที', 'เดินเร็วสลับวิ่งเบา ๆ กับผู้ใหญ่ 10 นาที', 'เดินเร็วสลับวิ่งเบา ๆ กับผู้ใหญ่ 15 นาที'], clip: 'https://www.youtube.com/watch?v=kGaU9AkTYMM' },
    { type: 'habit', steps: ['ดื่มน้ำเปล่า 4 แก้ว', 'ดื่มน้ำเปล่า 6 แก้ว', 'ดื่มน้ำเปล่า 8 แก้ว', 'ดื่มน้ำเปล่า 8 แก้ว และไม่ดื่มน้ำหวานทั้งวัน'], clip: '' },
    { type: 'habit', steps: ['แปรงฟันก่อนนอน', 'แปรงฟันก่อนนอน 2 นาที', 'แปรงฟันเช้าและก่อนนอน ครั้งละ 2 นาที', 'แปรงฟันเช้าและก่อนนอน 2 นาที แล้วไม่กินอะไรหลังแปรงก่อนนอน'], clip: 'https://www.youtube.com/watch?v=g9LkRL68-z0' },
    { type: 'habit', steps: ['เข้านอนก่อน 3 ทุ่มครึ่ง', 'เข้านอนก่อน 3 ทุ่ม', 'เข้านอนก่อน 3 ทุ่ม และเลิกเล่นจอก่อนนอน 30 นาที', 'เข้านอนก่อน 3 ทุ่ม และเลิกเล่นจอก่อนนอน 1 ชั่วโมง'], clip: 'https://www.youtube.com/watch?v=zoKjq1mkPZo' },
    { type: 'habit', steps: ['ลองกินผัก 3 คำ', 'กินผักในมื้อเย็น', 'กินผัก 2 มื้อในวันนี้', 'กินผักทุกมื้อในวันนี้'], clip: '' },
    { type: 'habit', steps: ['กินผลไม้ 1 อย่าง', 'กินผลไม้แทนขนม 1 ครั้ง', 'กินผลไม้ 2 อย่างในวันนี้', 'กินผลไม้แทนขนมทั้งวัน'], clip: 'https://www.youtube.com/watch?v=zS8EhYxPKg4' },
    { type: 'habit', steps: ['ล้างมือด้วยสบู่ก่อนกินข้าว', 'ล้างมือด้วยสบู่ก่อนกินข้าวทุกมื้อ', 'ล้างมือ 7 ขั้นตอนก่อนกินข้าวทุกมื้อ', 'ล้างมือ 7 ขั้นตอนก่อนกินข้าวและหลังเข้าห้องน้ำทุกครั้ง'], clip: 'https://www.youtube.com/watch?v=5Ta3dmQLBdI' },
    { type: 'habit', steps: ['เก็บของเล่นของตัวเอง', 'ช่วยงานบ้าน 1 อย่าง', 'ช่วยงานบ้าน 2 อย่าง เช่น กวาดบ้าน เก็บของ', 'ช่วยงานบ้าน 3 อย่าง เช่น กวาดบ้าน ล้างจาน พับผ้า'], clip: 'https://www.youtube.com/watch?v=YDZEM7wCu2I' },
    { type: 'habit', steps: ['กินอาหารเช้า', 'กินอาหารเช้าก่อนไปโรงเรียน', 'กินอาหารเช้าให้ครบ มีข้าว ไข่ หรือนม', 'กินอาหารเช้าให้ครบ มีข้าว ไข่หรือนม และผักหรือผลไม้'], clip: 'https://www.youtube.com/watch?v=F4800Eo9P18' },
    { type: 'habit', steps: ['เล่นนอกจอ 20 นาที', 'เล่นนอกจอ 30 นาที', 'วันนี้เล่นจอไม่เกิน 2 ชั่วโมง', 'วันนี้เล่นจอไม่เกิน 1 ชั่วโมง'], clip: 'https://www.youtube.com/watch?v=ul8ltPiY9ec' },
    { type: 'habit', steps: ['อาบน้ำเอง', 'อาบน้ำแต่งตัวเอง', 'อาบน้ำ สระผม แต่งตัวเอง', 'อาบน้ำ สระผม แล้วเก็บเสื้อผ้าใส่ตะกร้าเอง'], clip: 'https://www.youtube.com/watch?v=bxxOKENClXQ' },
    { type: 'habit', steps: ['บอกขอบคุณคนในบ้าน 1 คน', 'บอกขอบคุณคนในบ้าน 2 คน', 'ชมหรือขอบคุณคนในบ้าน 2 คน พร้อมบอกเหตุผล', 'เขียนการ์ดขอบคุณคนในบ้าน 1 ใบ'], clip: 'https://www.youtube.com/watch?v=NVCnbLbIi5A' },
    { type: 'habit', steps: ['หายใจช้า ๆ ลึก ๆ 3 ครั้งก่อนนอน', 'หายใจช้า ๆ ลึก ๆ 5 ครั้งก่อนนอน', 'นั่งหายใจช้า ๆ 2 นาที', 'นั่งหายใจช้า ๆ 3 นาที แล้วนึกถึงเรื่องดี ๆ วันนี้ 1 เรื่อง'], clip: 'https://www.youtube.com/watch?v=3VL8tQ818QM' },
    { type: 'habit', steps: ['จัดกระเป๋านักเรียนโดยมีผู้ใหญ่ช่วย', 'จัดกระเป๋านักเรียนเอง', 'จัดตารางสอนและเตรียมชุดพละเอง', 'จัดตารางสอน เตรียมชุด และทำการบ้านเสร็จก่อน 2 ทุ่ม'], clip: 'https://www.youtube.com/watch?v=VVbU0XZdgk8' },
    { type: 'habit', steps: ['นั่งหลังตรงตอนทำการบ้าน', 'นั่งหลังตรงตอนทำการบ้านและตอนกินข้าว', 'ลุกเดินยืดเส้นทุก 30 นาทีตอนทำการบ้านหรือดูจอ', 'ลุกเดินยืดเส้นทุก 30 นาที และพักสายตามองไกล 20 วินาที'], clip: 'https://www.youtube.com/watch?v=6R034x_o1ig' }
  ];

  var MINUTE_CHOICES = [10, 15, 20, 30, 45, 60];
  var TH_MONTHS = ['ม.ค.', 'ก.พ.', 'มี.ค.', 'เม.ย.', 'พ.ค.', 'มิ.ย.', 'ก.ค.', 'ส.ค.', 'ก.ย.', 'ต.ค.', 'พ.ย.', 'ธ.ค.'];
  var TH_DAYS = ['จ', 'อ', 'พ', 'พฤ', 'ศ', 'ส', 'อา'];
  var TH_DAYS_FULL = ['จันทร์', 'อังคาร', 'พุธ', 'พฤหัสบดี', 'ศุกร์', 'เสาร์', 'อาทิตย์'];

  function pad2(n) { return (n < 10 ? '0' : '') + n; }

  function isDate(v) { return Object.prototype.toString.call(v) === '[object Date]'; }

  /* แปลงวันที่เป็นคีย์ yyyy-mm-dd: รับ yyyy-mm-dd, d/m/yyyy (ปี พ.ศ. ก็ได้) หรือ Date */
  function toKey(v) {
    if (v === null || v === undefined || v === '') return '';
    var y, mo, d, m;
    if (isDate(v)) {
      if (isNaN(v.getTime())) return '';
      y = v.getFullYear(); mo = v.getMonth() + 1; d = v.getDate();
    } else {
      var s = String(v).trim();
      m = s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})(?:$|[T\s])/);
      if (m) { y = +m[1]; mo = +m[2]; d = +m[3]; } else {
        m = s.match(/^(\d{1,2})[\/.\-](\d{1,2})[\/.\-](\d{4})$/);
        if (!m) return '';
        d = +m[1]; mo = +m[2]; y = +m[3];
      }
    }
    if (y > 2400) y -= 543;
    if (mo < 1 || mo > 12 || d < 1 || d > 31) return '';
    var chk = new Date(Date.UTC(y, mo - 1, d));
    if (chk.getUTCMonth() !== mo - 1) return '';
    return y + '-' + pad2(mo) + '-' + pad2(d);
  }

  function dayNum(key) {
    var p = key.split('-');
    return Math.round(Date.UTC(+p[0], +p[1] - 1, +p[2]) / 86400000);
  }
  function fromDayNum(n) {
    var dt = new Date(n * 86400000);
    return dt.getUTCFullYear() + '-' + pad2(dt.getUTCMonth() + 1) + '-' + pad2(dt.getUTCDate());
  }
  function addDays(key, n) { return fromDayNum(dayNum(key) + n); }
  /* 0 = จันทร์ ... 6 = อาทิตย์ */
  function weekdayIdx(key) { return (new Date(dayNum(key) * 86400000).getUTCDay() + 6) % 7; }
  function thaiDate(key) {
    if (!key) return '';
    var p = key.split('-');
    return (+p[2]) + ' ' + TH_MONTHS[+p[1] - 1];
  }
  function dayLetter(key) { return TH_DAYS[weekdayIdx(key)]; }
  function dayName(key) { return TH_DAYS_FULL[weekdayIdx(key)]; }

  /* สัปดาห์ที่ของวันนั้นในโปรแกรม: 0 = ก่อนเริ่มหรือยังไม่ตั้งวันเริ่ม */
  function weekOf(key, startKey) {
    if (!key || !startKey) return 0;
    var diff = dayNum(key) - dayNum(startKey);
    if (diff < 0) return 0;
    return Math.floor(diff / 7) + 1;
  }

  function allowedDates(todayKey, backfill) {
    var out = [];
    for (var i = 0; i <= backfill; i++) out.push(addDays(todayKey, -i));
    return out;
  }

  function find(list, v) {
    var s = String(v === undefined || v === null ? '' : v).trim();
    for (var i = 0; i < list.length; i++) {
      if (list[i].id === s || list[i].label === s) return list[i];
    }
    return null;
  }
  function findActivity(v) { return find(ACTIVITIES, v); }
  function findFeeling(v) { return find(FEELINGS, v); }

  function yes(v) {
    if (v === true) return true;
    var s = String(v === undefined || v === null ? '' : v).trim().toLowerCase();
    return s === 'ใช่' || s === 'true' || s === 'yes' || s === '1';
  }

  function intOr(v, def, lo, hi) {
    var n = Number(v);
    if (v === '' || v === null || v === undefined || !isFinite(n)) return def;
    n = Math.round(n);
    if (n < lo) n = lo;
    if (n > hi) n = hi;
    return n;
  }

  /* เกณฑ์ระดับ: 10 ตัวเลข เริ่มที่ 0 และเพิ่มขึ้นเรื่อย ๆ ถ้าครูใส่ผิดรูป ใช้ค่าตั้งต้น */
  function levelList(v) {
    var a = Array.isArray(v) ? v : String(v === undefined || v === null ? '' : v).split(/[^\d]+/).filter(function (x) { return x !== ''; });
    a = a.map(function (x) { return parseInt(x, 10); });
    var ok = a.length === LEVELS.length && a[0] === 0;
    for (var i = 1; ok && i < a.length; i++) if (!(a[i] > a[i - 1])) ok = false;
    return ok ? a : DEFAULTS.levelXp.slice();
  }

  /* ตัวเลขหลายตัวคั่นด้วยจุลภาค เช่น 10,15,20 ถ้าผิดรูปใช้ค่าตั้งต้น */
  function numList(v, def, lo, hi, rising) {
    var a = Array.isArray(v) ? v : String(v === undefined || v === null ? '' : v).split(/[^\d]+/).filter(function (x) { return x !== ''; });
    a = a.map(function (x) { return parseInt(x, 10); });
    var ok = a.length === def.length;
    for (var i = 0; ok && i < a.length; i++) {
      if (!(a[i] >= lo && a[i] <= hi) || (rising && i > 0 && !(a[i] > a[i - 1]))) ok = false;
    }
    return ok ? a : def.slice();
  }
  /* เหรียญวันสะสม รูปแบบ วัน:แต้ม เช่น 30:100,60:200 */
  function badgeList(v) {
    if (Array.isArray(v)) return v;
    var out = [], bad = false;
    String(v === undefined || v === null ? '' : v).split(/[,\n]+/).forEach(function (p) {
      p = p.trim();
      if (!p) return;
      var m = /^(\d+)\s*[:=]\s*(\d+)$/.exec(p);
      if (!m) { bad = true; return; }
      out.push({ days: +m[1], xp: +m[2] });
    });
    out.sort(function (a, b) { return a.days - b.days; });
    for (var i = 0; i < out.length; i++) if (!(out[i].days >= 1) || (i && out[i].days === out[i - 1].days)) bad = true;
    return bad || !out.length ? DEFAULTS.dayBadges.slice() : out;
  }

  /* ระดับเริ่มโหมดฝุ่น: เหลือง/ส้ม/แดง หรือ 3/4/5 */
  function dustFromOf(v) {
    var t = String(v === undefined || v === null ? '' : v).trim();
    if (/เหลือง/.test(t)) return 3;
    if (/ส้ม/.test(t)) return 4;
    if (/แดง/.test(t)) return 5;
    var n = parseInt(t, 10);
    return n >= 3 && n <= 5 ? n : DEFAULTS.dustFrom;
  }
  /* พิกัดโรงเรียน "ละติจูด,ลองจิจูด" (คัดลอกจาก Google Maps ได้) ผิดรูปแบบ = ค่าเริ่มต้น */
  function placeOf(v) {
    var m = String(v || '').match(/(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)/);
    if (m) {
      var la = parseFloat(m[1]), ln = parseFloat(m[2]);
      if (la >= 5 && la <= 21 && ln >= 97 && ln <= 106) return [la, ln];
    }
    return [DEFAULTS.dustLat, DEFAULTS.dustLng];
  }

  function normSettings(raw) {
    raw = raw || {};
    var s = {
      schoolName: String(raw.schoolName === undefined ? DEFAULTS.schoolName : raw.schoolName).trim(),
      minMinutesForStar: intOr(raw.minMinutesForStar, DEFAULTS.minMinutesForStar, 1, 240),
      starCapPerWeek: intOr(raw.starCapPerWeek, DEFAULTS.starCapPerWeek, 0, 7),
      backfillDays: intOr(raw.backfillDays, DEFAULTS.backfillDays, 0, 7),
      maxMinutesPerLog: intOr(raw.maxMinutesPerLog, DEFAULTS.maxMinutesPerLog, 5, 240),
      maxMinutesPerDay: intOr(raw.maxMinutesPerDay, DEFAULTS.maxMinutesPerDay, 5, 480),
      maxLogsPerDay: intOr(raw.maxLogsPerDay, DEFAULTS.maxLogsPerDay, 1, 20),
      /* วันเริ่มโปรแกรมและจำนวนสัปดาห์ ใช้วันเดียวทั้งโรงเรียน */
      programStart: toKey(raw.programStart) || DEFAULTS.programStart,
      programWeeks: intOr(raw.programWeeks, DEFAULTS.programWeeks, 1, 12),
      xpPerMinute: intOr(raw.xpPerMinute, DEFAULTS.xpPerMinute, 0, 10),
      xpMinuteCap: intOr(raw.xpMinuteCap, DEFAULTS.xpMinuteCap, 0, 480),
      xpPerStar: intOr(raw.xpPerStar, DEFAULTS.xpPerStar, 0, 1000),
      xpMissionDiff: numList(raw.xpMissionDiff, DEFAULTS.xpMissionDiff, 0, 1000, false),
      diffUnlock: numList(raw.diffUnlock, DEFAULTS.diffUnlock, 1, 10, true),
      xpPhotoBonus: intOr(raw.xpPhotoBonus, DEFAULTS.xpPhotoBonus, 0, 1000),
      xpMissionVideo: intOr(raw.xpMissionVideo, DEFAULTS.xpMissionVideo, 0, 1000),
      xpClip: intOr(raw.xpClip, DEFAULTS.xpClip, 0, 1000),
      clipSeconds: intOr(raw.clipSeconds, DEFAULTS.clipSeconds, 10, 3600),
      dustOn: (raw.dustOn === undefined || raw.dustOn === null || String(raw.dustOn).trim() === '') ? DEFAULTS.dustOn : (yes(raw.dustOn) || /^เปิด/.test(String(raw.dustOn).trim())),
      dustFrom: dustFromOf(raw.dustFrom),
      dustLat: placeOf(raw.dustPlace)[0],
      dustLng: placeOf(raw.dustPlace)[1],
      dustStation: String(raw.dustStation || '').trim().replace(/[^A-Za-z0-9_-]/g, '').slice(0, 20),
      xpDust: intOr(raw.xpDust, DEFAULTS.xpDust, 0, 1000),
      xpStreak3: intOr(raw.xpStreak3, DEFAULTS.xpStreak3, 0, 1000),
      xpStreak7: intOr(raw.xpStreak7, DEFAULTS.xpStreak7, 0, 1000),
      streakRest: intOr(raw.streakRest, DEFAULTS.streakRest, 0, 3),
      dayBadges: badgeList(raw.dayBadges),
      levelXp: levelList(raw.levelXp),
      legendStep: intOr(raw.legendStep, DEFAULTS.legendStep, 10, 100000),
      proofOn: (raw.proofOn === undefined || raw.proofOn === null || String(raw.proofOn).trim() === '') ? DEFAULTS.proofOn : yes(raw.proofOn),
      photoKeepDays: intOr(raw.photoKeepDays, DEFAULTS.photoKeepDays, 1, 365),
      videoKeepDays: intOr(raw.videoKeepDays, DEFAULTS.videoKeepDays, 1, 365),
      weekGoalStart: intOr(raw.weekGoalStart, DEFAULTS.weekGoalStart, 5, 3000),
      weekGoalStep: intOr(raw.weekGoalStep, DEFAULTS.weekGoalStep, 0, 100),
      weekGoalMax: intOr(raw.weekGoalMax, DEFAULTS.weekGoalMax, 5, 3000),
      xpWeekGoal: intOr(raw.xpWeekGoal, DEFAULTS.xpWeekGoal, 0, 1000),
      roomMinMembers: intOr(raw.roomMinMembers, DEFAULTS.roomMinMembers, 1, 100),
      leagueSize: intOr(raw.leagueSize, DEFAULTS.leagueSize, 3, 50),
      xpQuizRight: intOr(raw.xpQuizRight, DEFAULTS.xpQuizRight, 0, 1000),
      xpQuizWrong: intOr(raw.xpQuizWrong, DEFAULTS.xpQuizWrong, 0, 1000),
      xpEvent: intOr(raw.xpEvent, DEFAULTS.xpEvent, 0, 5000),
      missingDays: intOr(raw.missingDays, DEFAULTS.missingDays, 2, 60),
      sidLen: intOr(raw.sidLen, DEFAULTS.sidLen, 0, 10),
      termNow: /^[12]\/\d{4}$/.test(String(raw.termNow || '').trim()) ? String(raw.termNow).trim() : DEFAULTS.termNow,
      stepsPerMin: intOr(raw.stepsPerMin, DEFAULTS.stepsPerMin, 50, 200)
    };
    if (s.maxMinutesPerDay < s.maxMinutesPerLog) s.maxMinutesPerDay = s.maxMinutesPerLog;
    if (s.weekGoalMax < s.weekGoalStart) s.weekGoalMax = s.weekGoalStart;
    s.minuteChoices = MINUTE_CHOICES.filter(function (m) { return m <= s.maxMinutesPerLog; });
    return s;
  }

  /* ไม่มีผู้ปกครองรับรองแล้ว: นับทุกรายการ ยกเว้นที่ครูใส่ว่า ไม่นับ */
  function isCounted(log) { return !log.excluded; }

  /* รวมนาทีรายวัน: counted = นาทีที่นับดาวได้ (ไม่เกินนาทีสูงสุดต่อวัน) */
  function dayTotals(logs, settings) {
    var map = {};
    for (var i = 0; i < logs.length; i++) {
      var l = logs[i];
      if (!isCounted(l) || !l.date) continue;
      var t = map[l.date] || (map[l.date] = { counted: 0, all: 0, count: 0 });
      var m = Number(l.minutes) || 0;
      t.all += m;
      t.count += 1;
      t.counted += m;
    }
    for (var k in map) {
      if (map.hasOwnProperty(k) && map[k].counted > settings.maxMinutesPerDay) map[k].counted = settings.maxMinutesPerDay;
    }
    return map;
  }

  function weekSummary(totals, weekStart, no, inProgram, settings) {
    var days = [], qualified = 0, counted = 0;
    for (var i = 0; i < 7; i++) {
      var k = addDays(weekStart, i);
      var t = totals[k] || { counted: 0 };
      var q = t.counted >= settings.minMinutesForStar;
      if (q) qualified++;
      counted += t.counted;
      days.push({ date: k, letter: dayLetter(k), counted: t.counted, qualified: q });
    }
    return {
      no: no, start: weekStart, end: addDays(weekStart, 6), inProgram: inProgram, days: days,
      qualifiedDays: qualified, stars: inProgram ? Math.min(qualified, settings.starCapPerWeek) : 0,
      minutesCounted: counted
    };
  }

  /* สรุปของนักเรียน 1 คน: logs = บันทึกของคนนั้น, klass = {start, weeks} */
  function summarize(logs, klass, settings, todayKey) {
    var totals = dayTotals(logs, settings);
    var start = klass.start || '';
    var weeks = klass.weeks || 8;
    var history = [], totalStars = 0, programMinutes = 0;
    if (start) {
      for (var w = 1; w <= weeks; w++) {
        var ws = weekSummary(totals, addDays(start, (w - 1) * 7), w, true, settings);
        history.push({ no: w, start: ws.start, end: ws.end, stars: ws.stars, minutes: ws.minutesCounted, qualifiedDays: ws.qualifiedDays });
        totalStars += ws.stars;
        programMinutes += ws.minutesCounted;
      }
    }
    var cw = weekOf(todayKey, start);
    var phase = !start ? 'nostart' : (cw === 0 ? 'before' : (cw > weeks ? 'after' : 'during'));
    var current = phase === 'during'
      ? weekSummary(totals, addDays(start, (cw - 1) * 7), cw, true, settings)
      : weekSummary(totals, addDays(todayKey, -weekdayIdx(todayKey)), cw, false, settings);
    for (var i = 0; i < current.days.length; i++) {
      current.days[i].isToday = current.days[i].date === todayKey;
      current.days[i].isFuture = current.days[i].date > todayKey;
    }
    return {
      phase: phase, currentWeek: cw, weeks: weeks, start: start, current: current,
      history: history, totalStars: totalStars, programMinutes: programMinutes
    };
  }

  /* ---------- แต้ม ระดับ ไฟต่อเนื่อง ----------
   * แต้มนับตั้งแต่วันเริ่มโปรแกรม ไม่มีวันจบ (ดาวบ้านนับแค่ช่วงโปรแกรมเหมือนเดิม) */
  function levelInfo(xp, s) {
    var th = s.levelXp, i = 0;
    for (var k = 0; k < th.length; k++) if (xp >= th[k]) i = k;
    var L = LEVELS[i], last = th[th.length - 1];
    var legend = 0, from = th[i], to = i + 1 < th.length ? th[i + 1] : 0;
    if (i === th.length - 1) {
      legend = Math.floor((xp - last) / s.legendStep);
      from = last + legend * s.legendStep;
      to = from + s.legendStep;
    }
    return { lv: L.lv, icon: L.icon, title: L.title, arc: L.arc, arcName: ARCS[L.arc], legend: legend, xp: xp, from: from, to: to };
  }

  function levelUp(a, b, s) {
    if (b.lv > a.lv || b.legend > a.legend) {
      var da = unlockedDiff(a.lv, s), db = unlockedDiff(b.lv, s);
      return {
        lv: b.lv, icon: b.icon, title: b.title, arc: b.arc, arcName: b.arcName, legend: b.legend,
        newArc: b.arc > a.arc, newLegend: b.legend > a.legend, newDiff: db > da ? db : 0
      };
    }
    return null;
  }
  /* เหรียญวันสะสมที่ได้เพิ่มระหว่างก่อน–หลัง */
  function badgeGained(a, b) { return b.badges.length > a.badges.length ? b.badges[b.badges.length - 1] : null; }

  /* ความยากที่ปลดล็อกแล้วตามระดับ: ⭐ ตั้งแต่แรก ⭐⭐ ที่ระดับ diffUnlock[0] ⭐⭐⭐ ที่ระดับ diffUnlock[1] */
  function unlockedDiff(lv, s) { return lv >= s.diffUnlock[1] ? 3 : (lv >= s.diffUnlock[0] ? 2 : 1); }

  /* แต้มของภารกิจ 1 รายการ: แต้มตามความยาก (+ โบนัสรูปของแถวเก่าที่เคยส่งรูป หรือ สาธิตในคาบ)
   * ครูใส่ ไม่ผ่าน = ไม่ได้โบนัสรูป, ไม่นับ = 0, เควสบ้านได้แต้มเควสบ้าน */
  function missionPoints(m, s) {
    if (m.check === 'ไม่นับ') return 0;
    var pass = m.check !== 'ไม่ผ่าน';
    if (m.type === 'quest') return pass ? s.xpMissionVideo : 0;
    var d = m.diff >= 1 && m.diff <= 3 ? m.diff : 1;
    var pts = s.xpMissionDiff[d - 1];
    if (pass && (m.proof === 'รูป' || m.proof === 'วิดีโอ' || m.proof === 'สาธิตในคาบ')) pts += s.xpPhotoBonus;
    return pts;
  }

  /* เป้าสัปดาห์: นับเป็นสัปดาห์ละ 7 วันจากวันเริ่มโปรแกรม ไม่มีวันจบ
   * สัปดาห์แรก = weekGoalStart ถึงเป้า → สัปดาห์ต่อไปเพิ่ม weekGoalStep% / ไม่ถึง → ใช้เป้าเดิม
   * ไม่เกิน weekGoalMax ปัดขึ้นทีละ 5 นาที  totals = dayTotals ของเด็กคนนี้ */
  function ceil5(n) { return Math.ceil(n / 5 - 1e-9) * 5; }
  function weekGoals(totals, start, today, s) {
    var out = [];
    if (!start || !today || today < start) return out;
    var goal = Math.min(s.weekGoalStart, s.weekGoalMax), step = s.weekGoalStep / 100;
    for (var ws = start, guard = 0; ws <= today && guard < 800; ws = addDays(ws, 7), guard++) {
      var sum = 0, reached = '';
      for (var i = 0; i < 7; i++) {
        var d = addDays(ws, i);
        if (d > today) break;
        sum += totals[d] ? totals[d].counted : 0;
        if (!reached && sum >= goal) reached = d;
      }
      out.push({ start: ws, end: addDays(ws, 6), goal: goal, minutes: sum, reached: reached });
      if (reached) goal = Math.min(s.weekGoalMax, Math.max(goal, ceil5(goal * (1 + step))));
    }
    return out;
  }

  /* สมุดแต้ม: แต้มแต่ละวันจากนาที ดาวบ้าน ภารกิจ และโบนัสไฟต่อเนื่อง
   * o = { logs, done (ของเด็กคนนี้), start, weeks, settings, today } */
  function xpLedger(o) {
    var s = o.settings, start = o.start, today = o.today, weeks = o.weeks || 8;
    var by = {}, parts = { minutes: 0, stars: 0, missions: 0, streak: 0, badges: 0, goal: 0, quiz: 0, event: 0, clip: 0, dust: 0 };
    var streak = { current: 0, best: 0, today: false }, badges = [], active = 0;
    function give(d, k, v) { if (!v) return; by[d] = (by[d] || 0) + v; parts[k] += v; }
    if (!start || today < start) return { total: 0, parts: parts, byDate: by, streak: streak, activeDays: 0, badges: badges, goals: [], totals: {}, eventsDone: [], clipCount: 0, dustCount: 0 };
    var totals = dayTotals(o.logs, s), qual = {};
    Object.keys(totals).sort().forEach(function (d) {
      if (d < start || d > today) return;
      var c = totals[d].counted;
      give(d, 'minutes', Math.min(c, s.xpMinuteCap) * s.xpPerMinute);
      /* เหรียญวันสะสม: นับวันที่บันทึกการขยับรวมทั้งหมด ไฟขาดหรือปิดเทอมก็ไม่หาย */
      if (c > 0) {
        active++;
        s.dayBadges.forEach(function (b, i) {
          if (active === b.days) {
            give(d, 'badges', b.xp);
            badges.push({ days: b.days, xp: b.xp, icon: BADGE_ICONS[i] || '🏅', date: d });
          }
        });
      }
      var w = weekOf(d, start);
      if (c >= s.minMinutesForStar && w >= 1 && w <= weeks) {
        qual[w] = (qual[w] || 0) + 1;
        if (qual[w] <= s.starCapPerWeek) give(d, 'stars', s.xpPerStar);
      }
    });
    (o.done || []).forEach(function (m) {
      if (m.date >= start && m.date <= today) give(m.date, 'missions', missionPoints(m, s));
    });
    /* ถึงเป้าสัปดาห์: ได้แต้มในวันที่นาทีรวมถึงเป้า */
    var goals = weekGoals(totals, start, today, s);
    goals.forEach(function (g) { if (g.reached) give(g.reached, 'goal', s.xpWeekGoal); });
    /* คำถามสุขภาพ: ถูก / ผิด ได้แต้มไม่เท่ากัน ครูใส่ ไม่นับ = 0 */
    (o.extra || []).forEach(function (x) {
      if (x.kind !== 'quiz' || x.check === 'ไม่นับ' || !x.date || x.date < start || x.date > today) return;
      give(x.date, 'quiz', x.ok ? s.xpQuizRight : s.xpQuizWrong);
    });
    /* ดูคลิปครบ: ภารกิจละ 1 ครั้งต่อวัน เควสบ้านสัปดาห์ละ 1 ครั้ง ครูใส่ ไม่นับ = 0 */
    var clipSeen = {}, clipCount = 0;
    (o.extra || []).forEach(function (x) {
      if (x.kind !== 'clip' || x.check === 'ไม่นับ' || !x.date || x.date < start || x.date > today) return;
      var key = x.ref === 'quest' ? 'q' + addDays(x.date, -weekdayIdx(x.date)) : x.ref + x.date;
      if (clipSeen[key]) return;
      clipSeen[key] = 1;
      clipCount++;
      give(x.date, 'clip', s.xpClip);
    });
    /* ภารกิจนักสู้ฝุ่น: วันละ 1 ครั้ง เฉพาะวันฝุ่นเยอะ ครูใส่ ไม่นับ = 0 */
    var dustSeen = {}, dustCount = 0;
    (o.extra || []).forEach(function (x) {
      if (x.kind !== 'dust' || x.check === 'ไม่นับ' || !x.date || x.date < start || x.date > today || dustSeen[x.date]) return;
      dustSeen[x.date] = 1;
      dustCount++;
      give(x.date, 'dust', s.xpDust);
    });
    /* อีเวนต์: ทำครบทุกภารกิจ ได้แต้มในวันที่ครบ + สติกเกอร์รุ่นพิเศษ */
    var eventsDone = [];
    (o.events || []).forEach(function (ev) {
      if (!ev.start || ev.start > today) return;
      var p = eventProgress(ev, o.logs, o.done, o.extra, s, today, totals);
      if (p.complete && p.at >= start) {
        give(p.at, 'event', s.xpEvent);
        eventsDone.push({ id: ev.id, name: ev.name, sticker: ev.sticker, date: p.at });
      }
    });
    /* ไฟต่อเนื่อง: วันที่มีบันทึกการขยับ นับตาม "วันที่ทำ" พักได้ streakRest วันต่อสัปดาห์ (จันทร์–อาทิตย์) */
    var cur = 0, best = 0, rest = 0;
    for (var d = start, guard = 0; d <= today && guard < 4000; d = addDays(d, 1), guard++) {
      if (weekdayIdx(d) === 0) rest = 0;
      if (totals[d] && totals[d].counted > 0) {
        cur++;
        if (cur > best) best = cur;
        if (cur === 3) give(d, 'streak', s.xpStreak3);
        if (cur % 7 === 0) give(d, 'streak', s.xpStreak7);
      } else if (d === today) {
        /* วันนี้ยังไม่จบ ไฟยังไม่ดับ */
      } else if (rest < s.streakRest) {
        rest++;
      } else {
        cur = 0;
      }
    }
    streak = { current: cur, best: best, today: !!(totals[today] && totals[today].counted > 0) };
    return {
      total: parts.minutes + parts.stars + parts.missions + parts.streak + parts.badges + parts.goal + parts.quiz + parts.event + parts.clip + parts.dust,
      parts: parts, byDate: by, streak: streak, activeDays: active, badges: badges, goals: goals, totals: totals, eventsDone: eventsDone,
      clipCount: clipCount, dustCount: dustCount
    };
  }

  /* ---------- สติกเกอร์ 20 แบบ: ปลดล็อกเองจากข้อมูล ไม่ต้องเก็บแยก ----------
   * f = ชื่อข้อมูลที่ใช้นับ (ดู stickerFacts) need = ต้องถึงเท่าไร */
  var STICKERS = [
    { id: 'first', icon: '🐣', name: 'ก้าวแรก', how: 'บันทึกการขยับครั้งแรก', f: 'activeDays', need: 1 },
    { id: 'fire3', icon: '🔥', name: 'ไฟลุก', how: 'ไฟต่อเนื่อง 3 วัน', f: 'bestStreak', need: 3 },
    { id: 'fire7', icon: '🌋', name: 'ไฟไม่ดับ', how: 'ไฟต่อเนื่อง 7 วัน', f: 'bestStreak', need: 7 },
    { id: 'fire30', icon: '☄️', name: 'ไฟนิรันดร์', how: 'ไฟต่อเนื่อง 30 วัน', f: 'bestStreak', need: 30 },
    { id: 'mission1', icon: '🎯', name: 'ภารกิจแรก', how: 'ทำภารกิจประจำวันครั้งแรก', f: 'missions', need: 1 },
    { id: 'combo7', icon: '🧩', name: 'คอมโบ', how: 'ทำภารกิจครบ 2 อย่างในวันเดียว 7 วัน', f: 'comboDays', need: 7 },
    { id: 'hard1', icon: '⭐', name: 'กล้าท้าทาย', how: 'ทำภารกิจ ⭐⭐⭐ ครั้งแรก', f: 'hard', need: 1 },
    { id: 'photo10', icon: '🎬', name: 'นักดูคลิป', how: 'ดูคลิปภารกิจครบ 10 คลิป', f: 'photos', need: 10 },
    { id: 'video4', icon: '🏡', name: 'ฮีโร่ประจำบ้าน', how: 'ทำเควสบ้านครบ 4 สัปดาห์', f: 'videos', need: 4 },
    { id: 'water7', icon: '💧', name: 'นักดื่มน้ำตัวจริง', how: 'ทำภารกิจดื่มน้ำ 7 ครั้ง', f: 'tag_water', need: 7 },
    { id: 'sleep5', icon: '🌙', name: 'นอนเร็ว', how: 'ทำภารกิจเข้านอน 5 ครั้ง', f: 'tag_sleep', need: 5 },
    { id: 'teeth5', icon: '🦷', name: 'ฟันสวย', how: 'ทำภารกิจแปรงฟัน 5 ครั้ง', f: 'tag_teeth', need: 5 },
    { id: 'veg5', icon: '🥦', name: 'ฮีโร่ผักผลไม้', how: 'ทำภารกิจผักหรือผลไม้ 5 ครั้ง', f: 'tag_veg', need: 5 },
    { id: 'rope10', icon: '🦘', name: 'จิงโจ้', how: 'บันทึกกระโดดเชือก 10 ครั้ง', f: 'act_rope', need: 10 },
    { id: 'rainbow', icon: '🌈', name: 'สายรุ้ง', how: 'ลองครบ 8 กิจกรรม', f: 'kinds', need: 8 },
    { id: 'goal4', icon: '🏁', name: 'ถึงเป้า', how: 'ถึงเป้าสัปดาห์ 4 ครั้ง', f: 'goals', need: 4 },
    { id: 'weekend4', icon: '🌞', name: 'สุดสัปดาห์ไม่หยุด', how: 'ขยับทั้งเสาร์และอาทิตย์ 4 สัปดาห์', f: 'weekends', need: 4 },
    { id: 'min1000', icon: '⏱️', name: 'พันนาที', how: 'ขยับรวม 1,000 นาที', f: 'minutes', need: 1000 },
    { id: 'arc2', icon: '⚡', name: 'ปลุกพลังธาตุ', how: 'ถึงภาค 2 (ระดับ 4)', f: 'level', need: 4 },
    { id: 'arc3', icon: '🚀', name: 'ทะยานสู่อวกาศ', how: 'ถึงภาค 3 (ระดับ 7)', f: 'level', need: 7 },
    { id: 'dust3', icon: '😷', name: 'นักสู้ฝุ่น', how: 'ทำภารกิจนักสู้ฝุ่นในวันฝุ่นเยอะ 3 วัน', f: 'dust', need: 3 }
  ];
  var CORE_ACTS = ['run', 'bike', 'rope', 'dance', 'sport', 'play', 'quest', 'stretch'];

  /* ป้ายของภารกิจสุขนิสัย ใช้นับสติกเกอร์ (ดูจากข้อความภารกิจ ครูแก้ข้อความได้ ถ้ายังมีคำเหล่านี้ก็นับ) */
  function tagOf(text) {
    var t = String(text || '');
    if (/ดื่มน้ำ/.test(t)) return 'water';
    if (/แปรงฟัน/.test(t)) return 'teeth';
    if (/เข้านอน/.test(t)) return 'sleep';
    if (/ผัก|ผลไม้/.test(t)) return 'veg';
    return '';
  }

  /* ตัวเลขที่ใช้นับสติกเกอร์ นับตั้งแต่วันเริ่มโปรแกรมเหมือนแต้ม  L = xpLedger, lv = levelInfo */
  function stickerFacts(logs, done, L, lv, start, today) {
    var f = { activeDays: L.activeDays, bestStreak: L.streak.best, missions: 0, comboDays: 0, hard: 0, photos: 0, videos: 0,
      tag_water: 0, tag_sleep: 0, tag_teeth: 0, tag_veg: 0, act_rope: 0, kinds: 0, goals: 0, weekends: 0, minutes: 0, level: lv.lv, dust: L.dustCount || 0 };
    if (!start || today < start) return f;
    var kinds = {}, byDay = {};
    (logs || []).forEach(function (l) {
      if (l.excluded || !l.date || l.date < start || l.date > today) return;
      var a = findActivity(l.activity), id = a ? a.id : '';
      if (id === 'rope') f.act_rope++;
      if (CORE_ACTS.indexOf(id) >= 0) kinds[id] = 1;
    });
    f.kinds = Object.keys(kinds).length;
    (done || []).forEach(function (m) {
      if (m.check === 'ไม่นับ' || !m.date || m.date < start || m.date > today) return;
      var ok = m.check !== 'ไม่ผ่าน';
      if (m.type === 'quest') { if (ok) f.videos++; return; }
      f.missions++;
      if (m.diff === 3) f.hard++;
      if (ok && m.proof === 'รูป') f.photos++;
      var tag = m.tag || tagOf(m.text);
      if (tag) f['tag_' + tag]++;
      var d = byDay[m.date] || (byDay[m.date] = {});
      d[m.type] = 1;
    });
    Object.keys(byDay).forEach(function (d) { if (byDay[d].move && byDay[d].habit) f.comboDays++; });
    /* นักดูคลิป: นับคลิปที่ดูครบ รวมรูปที่เคยส่งแบบเก่า (สติกเกอร์ที่ได้แล้วไม่หาย) */
    f.photos += L.clipCount || 0;
    var T = L.totals || {};
    Object.keys(T).forEach(function (d) {
      if (d < start || d > today) return;
      f.minutes += T[d].counted;
      if (weekdayIdx(d) === 5 && T[d].counted > 0 && T[addDays(d, 1)] && T[addDays(d, 1)].counted > 0 && addDays(d, 1) <= today) f.weekends++;
    });
    (L.goals || []).forEach(function (g) { if (g.reached) f.goals++; });
    return f;
  }
  function stickersOf(f) {
    return STICKERS.map(function (k) {
      var have = Math.min(f[k.f] || 0, k.need);
      return { id: k.id, icon: k.icon, name: k.name, how: k.how, got: (f[k.f] || 0) >= k.need, have: have, need: k.need };
    });
  }
  /* สติกเกอร์ที่ได้ใหม่ระหว่างก่อน–หลัง */
  function stickersGained(a, b) {
    var had = {};
    (a.stickers || []).forEach(function (x) { if (x.got) had[x.id] = 1; });
    return (b.stickers || []).filter(function (x) { return x.got && !had[x.id]; })
      .map(function (x) { return { id: x.id, icon: x.icon, name: x.name, how: x.how }; });
  }

  /* แต้มรวม แต้มสัปดาห์นี้ (จันทร์–วันนี้) และระดับ */
  function xpStatus(logsMine, doneMine, klass, s, today, more) {
    more = more || {};
    var L = xpLedger({ logs: logsMine, done: doneMine, extra: more.extra, events: more.events, start: klass.start, weeks: klass.weeks, settings: s, today: today });
    var ws = addDays(today, -weekdayIdx(today)), week = 0;
    Object.keys(L.byDate).forEach(function (d) { if (d >= ws && d <= today) week += L.byDate[d]; });
    var lv = levelInfo(L.total, s), next = null;
    for (var i = 0; i < s.dayBadges.length; i++) {
      if (s.dayBadges[i].days > L.activeDays) { next = { days: s.dayBadges[i].days, xp: s.dayBadges[i].xp, icon: BADGE_ICONS[i] || '🏅' }; break; }
    }
    var maxDiff = unlockedDiff(lv.lv, s);
    var g = L.goals.length ? L.goals[L.goals.length - 1] : null;
    var stickers = stickersOf(stickerFacts(logsMine, doneMine, L, lv, klass.start, today));
    return {
      started: !!klass.start && today >= klass.start, total: L.total, week: week,
      parts: L.parts, streak: L.streak, level: lv, activeDays: L.activeDays, badges: L.badges, nextBadge: next,
      maxDiff: maxDiff, nextUnlock: maxDiff < 3 ? { diff: maxDiff + 1, lv: s.diffUnlock[maxDiff - 1] } : null,
      weekGoal: g ? { goal: g.goal, minutes: g.minutes, reached: !!g.reached, xp: s.xpWeekGoal, start: g.start, end: g.end } : null,
      stickers: stickers, stickerCount: stickers.filter(function (x) { return x.got; }).length,
      eventStickers: L.eventsDone
    };
  }
  /* อีเวนต์ที่ทำครบใหม่ระหว่างก่อน–หลัง */
  function eventGained(a, b) {
    var had = {};
    (a.eventStickers || []).forEach(function (x) { had[x.id] = 1; });
    return (b.eventStickers || []).filter(function (x) { return !had[x.id]; });
  }

  /* ---------- ภารกิจประจำวัน ---------- */
  function missionsOf(done, student) {
    var out = [];
    for (var i = 0; i < (done || []).length; i++) if (done[i].code === student.code) out.push(done[i]);
    return out;
  }
  function findDone(doneMine, date, type) {
    for (var i = 0; i < doneMine.length; i++) if (doneMine[i].date === date && doneMine[i].type === type) return doneMine[i];
    return null;
  }
  /* ภารกิจของวันนั้น: ทั้งโรงเรียนได้ภารกิจเดียวกัน หมุนตามวัน
   * ความยาก diff 1–3 → ขั้น: ป.1–3 ใช้ขั้น 1–3, ป.4–6 ใช้ขั้น 2–4 (ขั้นว่างใช้ขั้นใกล้ที่สุดแทน) */
  function missionFor(date, type, pool, grade, diff) {
    var list = (pool || []).filter(function (m) {
      return m.type === type && m.active !== false && (m.steps || []).some(function (x) { return !!x; });
    });
    if (!list.length || !date) return null;
    var n = list.length, at = ((dayNum(date) + (type === 'habit' ? 5 : 0)) % n + n) % n, m = list[at];
    /* วันฝุ่น (pool.dustDay = วันนี้): ภารกิจกลางแจ้งเลื่อนไปใช้ภารกิจในบ้านอันถัดไป */
    if (pool && pool.dustDay === date && m.outdoor) {
      for (var j = 1; j < n; j++) { var x = list[(at + j) % n]; if (!x.outdoor) { m = x; break; } }
    }
    var d = diff >= 1 && diff <= 3 ? diff : 1;
    var step = Math.min(4, d + (grade >= 4 ? 1 : 0)), text = '';
    for (var k = step; k >= 1 && !text; k--) text = m.steps[k - 1] || '';
    for (var j = step + 1; j <= 4 && !text; j++) text = m.steps[j - 1] || '';
    return { type: type, text: text, diff: d, clip: m.clip || '' };
  }

  /* เควสบ้านของสัปดาห์นี้: นับสัปดาห์จากวันเริ่มโปรแกรม จบรายการแล้ววนกลับไปเริ่มใหม่ ไม่มีวันจบ */
  function questOf(quests, klass, today) {
    var w = weekOf(today, klass.start);
    var keys = Object.keys(quests || {}).map(Number).filter(function (n) { return n >= 1; }).sort(function (a, b) { return a - b; });
    if (!w || !keys.length) return null;
    var q = quests[keys[(w - 1) % keys.length]] || {};
    var text = klass.grade && klass.grade <= 3 ? (q.low || q.high) : (q.high || q.low);
    return text ? { week: w, text: text, clip: q.clip || '' } : null;
  }
  /* ดูคลิปครบแล้วหรือยัง: ภารกิจดูจากวันของภารกิจ เควสบ้านดูทั้งสัปดาห์นี้ */
  function clipDone(exMine, kind, date, today) {
    var ws = addDays(today, -weekdayIdx(today));
    for (var i = 0; i < (exMine || []).length; i++) {
      var x = exMine[i];
      if (x.kind !== 'clip' || x.ref !== kind) continue;
      if (kind === 'quest' ? (x.date >= ws && x.date <= today) : x.date === date) return x;
    }
    return null;
  }
  function questDoneThisWeek(doneMine, today) {
    var ws = addDays(today, -weekdayIdx(today));
    for (var i = 0; i < doneMine.length; i++) {
      if (doneMine[i].type === 'quest' && doneMine[i].date >= ws && doneMine[i].date <= today) return doneMine[i];
    }
    return null;
  }

  function fail(msg, code) { return { ok: false, error: msg, code: code || 'INVALID' }; }

  /* ตรวจรายการที่เด็กส่งมา ctx = {todayKey, settings, studentLogs} */
  function validateEntry(entry, ctx) {
    var s = ctx.settings;
    if (!entry || typeof entry !== 'object') return fail('ข้อมูลไม่ครบ ลองใหม่อีกครั้ง');
    var date = toKey(entry.date);
    if (!date || allowedDates(ctx.todayKey, s.backfillDays).indexOf(date) < 0) {
      return fail(s.backfillDays > 0 ? 'บันทึกได้เฉพาะวันนี้และย้อนหลังไม่เกิน ' + s.backfillDays + ' วัน' : 'บันทึกได้เฉพาะวันนี้');
    }
    var act = findActivity(entry.activity);
    if (!act) return fail('เลือกกิจกรรมก่อนนะ');
    var minutes = Number(entry.minutes);
    if (!isFinite(minutes) || Math.floor(minutes) !== minutes || minutes < 5 || minutes > s.maxMinutesPerLog) {
      return fail('เลือกเวลา 5–' + s.maxMinutesPerLog + ' นาที');
    }
    var feel = findFeeling(entry.feeling);
    if (!feel) return fail('เลือกว่าสนุกไหมก่อนนะ');
    var same = [];
    for (var i = 0; i < ctx.studentLogs.length; i++) {
      var l = ctx.studentLogs[i];
      if (l.date === date && !l.excluded) same.push(l);
    }
    if (same.length >= s.maxLogsPerDay) return fail('วันนั้นบันทึกครบ ' + s.maxLogsPerDay + ' ครั้งแล้ว', 'DAY_FULL');
    var used = 0;
    for (var j = 0; j < same.length; j++) used += Number(same[j].minutes) || 0;
    if (used + minutes > s.maxMinutesPerDay) {
      var left = s.maxMinutesPerDay - used;
      return fail(left >= 5 ? 'วันนั้นบันทึกได้อีกไม่เกิน ' + left + ' นาที' : 'วันนั้นบันทึกครบ ' + s.maxMinutesPerDay + ' นาทีแล้ว พักบ้างนะ', 'DAY_FULL');
    }
    return { ok: true, value: { date: date, activity: act, minutes: minutes, feeling: feel } };
  }

  /* นาทีที่ใช้ไปแล้วของแต่ละวันที่บันทึกได้ (ไว้บอกเด็กว่าเหลือเท่าไร) */
  function dayUsage(logs, dates) {
    var out = {};
    for (var i = 0; i < dates.length; i++) out[dates[i]] = { minutes: 0, count: 0 };
    for (var j = 0; j < logs.length; j++) {
      var l = logs[j];
      if (!l.excluded && out[l.date]) { out[l.date].minutes += Number(l.minutes) || 0; out[l.date].count += 1; }
    }
    return out;
  }

  /* บันทึกของนักเรียนคนนี้: ดูจากเลขประจำตัวอย่างเดียว ครูแก้ห้องให้ภายหลังบันทึกเดิมก็ไม่หาย */
  function mineOf(logs, klass, student) {
    var out = [];
    for (var i = 0; i < logs.length; i++) {
      if (logs[i].code === student.code) out.push(logs[i]);
    }
    return out;
  }
  function newestFirst(a, b) {
    if (a.date !== b.date) return a.date < b.date ? 1 : -1;
    return (b.row || 0) - (a.row || 0);
  }
  /* เด็กลบรายการของตัวเองได้เฉพาะวันที่ยังบันทึกได้ (okDates = วันนี้และย้อนหลังตามที่ตั้งไว้)
   * รายการที่ครูใส่ว่า ไม่นับ หรือครูบันทึกจากกระดาษ ลบเองไม่ได้ */
  function canDelete(l, okDates) {
    return !!l.id && !l.excluded && l.channel !== 'กระดาษ' && (okDates || []).indexOf(l.date) >= 0;
  }

  /* ---------- กิจกรรมเสริม: คำถามสุขภาพวันละข้อ และอีเวนต์เทศกาล ----------
   * extra = [{ date, code, kind: quiz|event, ref, answer, ok, check }] */
  function extrasOf(extra, student) {
    var out = [];
    for (var i = 0; i < (extra || []).length; i++) if (extra[i].code === student.code) out.push(extra[i]);
    return out;
  }

  /* ภารกิจอีเวนต์นับจาก: นาทีรวม / วันที่ขยับ / ภารกิจประจำวัน (ครั้ง) / ตอบคำถาม (ข้อ) / กดทำเอง */
  var EVENT_KINDS = [
    { id: 'minutes', label: 'นาทีรวม' }, { id: 'days', label: 'วันที่ขยับ' }, { id: 'missions', label: 'ภารกิจประจำวัน' },
    { id: 'quiz', label: 'ตอบคำถาม' }, { id: 'check', label: 'กดทำเอง' }
  ];
  function eventKind(v) { var k = find(EVENT_KINDS, v); return k ? k.id : ''; }

  /* ความคืบหน้าของอีเวนต์ 1 งาน นับเฉพาะในช่วงเริ่ม–จบ  ev = { id, start, end, tasks: [{ text, kind, need }] } */
  function eventProgress(ev, logs, done, extra, s, today, totals) {
    var end = ev.end < today ? ev.end : today;
    totals = totals || dayTotals(logs || [], s);
    var per = { minutes: {}, days: {}, missions: {}, quiz: {} };
    Object.keys(totals).forEach(function (d) {
      if (totals[d].counted > 0) { per.minutes[d] = totals[d].counted; per.days[d] = 1; }
    });
    (done || []).forEach(function (m) {
      if (m.type !== 'quest' && m.check !== 'ไม่นับ' && m.date) per.missions[m.date] = (per.missions[m.date] || 0) + 1;
    });
    (extra || []).forEach(function (x) {
      if (x.kind === 'quiz' && x.check !== 'ไม่นับ' && x.date) per.quiz[x.date] = (per.quiz[x.date] || 0) + 1;
    });
    var tasks = (ev.tasks || []).map(function (t, i) {
      var have = 0, at = '';
      if (t.kind === 'check') {
        (extra || []).forEach(function (x) {
          if (x.kind === 'event' && x.ref === ev.id + '#' + (t.n || i + 1) && x.check !== 'ไม่นับ' && x.date >= ev.start && x.date <= end && (!at || x.date < at)) at = x.date;
        });
        have = at ? 1 : 0;
      } else {
        var map = per[t.kind] || {};
        for (var d = ev.start, g = 0; d <= end && g < 400; d = addDays(d, 1), g++) {
          have += map[d] || 0;
          if (!at && have >= t.need) at = d;
        }
      }
      return { i: t.n || i + 1, text: t.text, kind: t.kind, need: t.need, have: Math.min(have, t.need), done: !!at, at: at };
    });
    var complete = tasks.length > 0 && tasks.every(function (t) { return t.done; });
    var at = '';
    if (complete) tasks.forEach(function (t) { if (t.at > at) at = t.at; });
    return { tasks: tasks, complete: complete, at: at };
  }

  /* อีเวนต์ที่โชว์ในแอป: กำลังจัด / อีก 14 วันจะเริ่ม / จบไม่เกิน 3 วัน */
  function eventsView(events, logs, done, extra, s, today) {
    var out = [];
    (events || []).forEach(function (ev) {
      if (!ev.start || !ev.end) return;
      var state = today < ev.start ? (dayNum(ev.start) - dayNum(today) <= 14 ? 'soon' : '')
        : today > ev.end ? (dayNum(today) - dayNum(ev.end) <= 3 ? 'ended' : '') : 'active';
      if (!state) return;
      var p = state === 'soon' ? { complete: false, tasks: (ev.tasks || []).map(function (t, i) {
        return { i: t.n || i + 1, text: t.text, kind: t.kind, need: t.need, have: 0, done: false, at: '' };
      }) } : eventProgress(ev, logs, done, extra, s, today);
      out.push({
        id: ev.id, name: ev.name, invite: ev.invite || '', start: ev.start, end: ev.end, state: state,
        daysLeft: state === 'active' ? dayNum(ev.end) - dayNum(today) : state === 'soon' ? dayNum(ev.start) - dayNum(today) : 0,
        tasks: p.tasks.map(function (t) {
          return { i: t.i, text: t.text, kind: t.kind, need: t.need, have: t.have, done: t.done, canCheck: state === 'active' && t.kind === 'check' && !t.done };
        }),
        complete: p.complete, sticker: ev.sticker || '', xp: s.xpEvent
      });
    });
    return out;
  }

  /* คำถามของวันนั้น: ทั้งช่วงชั้นได้ข้อเดียวกัน หมุนตามวัน ครบแล้ววนกลับ
   * list = [{ level: low|high|all, q, choices: [4], answer: 0–3, why, ref, active }] */
  function quizFor(date, grade, list) {
    var lv = grade && grade >= 4 ? 'high' : 'low';
    var pool = (list || []).filter(function (q) {
      return q.active !== false && (q.level === lv || q.level === 'all') && q.q && q.answer >= 0 && !!(q.choices || [])[q.answer] &&
        q.choices.filter(function (c) { return !!c; }).length >= 2;
    });
    if (!pool.length || !date) return null;
    var n = pool.length;
    return pool[((dayNum(date) + (lv === 'high' ? 17 : 0)) % n + n) % n];
  }
  function quizToday(ex, today) {
    for (var i = 0; i < ex.length; i++) if (ex[i].kind === 'quiz' && ex[i].date === today) return ex[i];
    return null;
  }
  /* ที่ส่งให้หน้าเว็บ: เฉลยกับคำอธิบายส่งหลังตอบแล้วเท่านั้น */
  function quizView(q, rec, s) {
    if (!q) return null;
    var v = {
      q: q.q, answered: !!rec, points: { right: s.xpQuizRight, wrong: s.xpQuizWrong },
      choices: q.choices.map(function (c, i) { return { i: i, text: c }; }).filter(function (c) { return !!c.text; })
    };
    if (rec) { v.chosen = rec.answer; v.correct = !!rec.ok; v.answer = q.answer; v.why = q.why || ''; }
    return v;
  }

  /* จับเวลาจากข้อความภารกิจ: "30 วินาที" / "นับ 1–10" / "2 นาที" และ "ทำ 3 รอบ" (ไม่มีเวลา = ใช้นาฬิกาจับเวลาเปล่า) */
  function timerOf(text) {
    var t = String(text || ''), m, sec = 0;
    if ((m = /(\d+)\s*วินาที/.exec(t))) sec = +m[1];
    else if ((m = /นับ\s*1\s*[–\-]\s*(\d+)/.exec(t))) sec = +m[1];
    else if ((m = /(\d+)\s*นาที/.exec(t))) sec = +m[1] * 60;
    var r = /ทำ\s*(\d+)\s*รอบ/.exec(t);
    return { sec: Math.min(sec, 1800), rounds: r ? Math.min(+r[1], 10) : 1 };
  }

  /* ---------- โปรไฟล์และการ์ดนักกีฬา ----------
   * เด็กเลือกจากรายการเท่านั้น (ยกเว้นชื่อเล่น) ชุดน้องขยับและสีพื้นปลดล็อกตามระดับ */
  var PROFILE = {
    sports: [
      { id: 'football', icon: '⚽', label: 'ฟุตบอล' }, { id: 'futsal', icon: '🥅', label: 'ฟุตซอล' }, { id: 'basketball', icon: '🏀', label: 'บาสเกตบอล' },
      { id: 'volleyball', icon: '🏐', label: 'วอลเลย์บอล' }, { id: 'badminton', icon: '🏸', label: 'แบดมินตัน' }, { id: 'pingpong', icon: '🏓', label: 'ปิงปอง' },
      { id: 'takraw', icon: '🦶', label: 'ตะกร้อ' }, { id: 'swim', icon: '🏊', label: 'ว่ายน้ำ' }, { id: 'run', icon: '🏃', label: 'วิ่ง' },
      { id: 'bike', icon: '🚲', label: 'ปั่นจักรยาน' }, { id: 'rope', icon: '🦘', label: 'กระโดดเชือก' }, { id: 'dance', icon: '💃', label: 'เต้น' },
      { id: 'martial', icon: '🥋', label: 'ศิลปะป้องกันตัว' }, { id: 'gym', icon: '🤸', label: 'ยิมนาสติก' }
    ],
    goals: [
      { id: 'strong', icon: '💪', label: 'แข็งแรงขึ้น' }, { id: 'fast', icon: '⚡', label: 'วิ่งเร็วขึ้น' }, { id: 'flex', icon: '🧘', label: 'ตัวอ่อนขึ้น' },
      { id: 'stamina', icon: '🫀', label: 'เหนื่อยช้าลง' }, { id: 'sleep', icon: '🌙', label: 'นอนเร็วขึ้น' }, { id: 'water', icon: '💧', label: 'ดื่มน้ำให้พอ' },
      { id: 'veg', icon: '🥦', label: 'กินผักมากขึ้น' }, { id: 'screen', icon: '📵', label: 'เล่นจอน้อยลง' }, { id: 'team', icon: '🏆', label: 'ติดทีมโรงเรียน' },
      { id: 'daily', icon: '🎯', label: 'ขยับทุกวัน' }
    ],
    mottos: [
      { id: 'm1', label: 'ไม่ยอมแพ้!' }, { id: 'm2', label: 'วันนี้ดีกว่าเมื่อวาน' }, { id: 'm3', label: 'ขยับทุกวัน แข็งแรงทุกวัน' },
      { id: 'm4', label: 'สนุกไว้ก่อน' }, { id: 'm5', label: 'ลุยเลย!' }, { id: 'm6', label: 'ทำได้แน่นอน' }, { id: 'm7', label: 'เหนื่อยแต่ไหว' },
      { id: 'm8', label: 'ฝึกหนัก ยิ้มกว้าง' }, { id: 'm9', label: 'เพื่อนกันต้องขยับด้วยกัน' }, { id: 'm10', label: 'ไฟไม่มีวันดับ' }
    ],
    outfits: [
      { id: 'sport', label: 'ชุดกีฬา', lv: 1 }, { id: 'hero', label: 'หน้ากากฮีโร่', lv: 4 },
      { id: 'space', label: 'หมวกนักบินอวกาศ', lv: 7 }, { id: 'crown', label: 'มงกุฎตำนาน', lv: 10 }
    ],
    colors: [
      { id: 'violet', label: 'ม่วง', hex: '#8B6CFF', lv: 1 }, { id: 'pink', label: 'ชมพู', hex: '#FF5FA8', lv: 1 }, { id: 'sky', label: 'ฟ้า', hex: '#4DD8FF', lv: 2 },
      { id: 'lime', label: 'เขียวมะนาว', hex: '#C6FF4D', lv: 3 }, { id: 'orange', label: 'ส้ม', hex: '#FFB23F', lv: 5 }, { id: 'red', label: 'แดง', hex: '#FF4D6D', lv: 6 },
      { id: 'mint', label: 'มิ้นต์', hex: '#3FE0B0', lv: 8 }, { id: 'gold', label: 'ทอง', hex: '#FFD25C', lv: 9 }
    ],
    maxSports: 2, maxPins: 3, nickMax: 12, nickDays: 7
  };
  function findIn(list, v) { return find(list, v); }

  /* ชื่อเล่น: ตัวอักษรไทยหรืออังกฤษ ไม่มีตัวเลข 2–12 ตัว (ไม่นับสระบน-ล่างและวรรณยุกต์) และไม่มีคำไม่สุภาพ */
  var BAD_WORDS = ['ควย', 'เหี้ย', 'สัส', 'เย็ด', 'แตด', 'มึง', 'ไอ้สัตว์', 'อีดอก', 'ดอกทอง', 'ระยำ', 'จัญไร', 'ส้นตีน',
    'เงี่ยน', 'กะหรี่', 'ร่าน', 'ชาติหมา', 'พ่อง', 'แม่ง', 'โง่', 'ควาย', 'ตอแหล', 'หน้าหี', 'อีเหี้ย', 'ไอ้เหี้ย', 'ครู', 'แอดมิน',
    'fuck', 'shit', 'bitch', 'dick', 'pussy', 'porn', 'sex', 'cunt', 'slut', 'whore', 'nigg', 'fag', 'admin'];
  function nickLen(t) { return String(t).replace(/[\u0E31\u0E34-\u0E3A\u0E47-\u0E4E]/g, '').length; }
  function checkNick(v) {
    var t = String(v === undefined || v === null ? '' : v).replace(/\s+/g, ' ').trim();
    if (!t) return fail('ใส่ชื่อเล่นก่อนนะ', 'INPUT');
    if (!/^[\u0E01-\u0E4E a-zA-Z]+$/.test(t) || /[\u0E50-\u0E59]/.test(t)) return fail('ชื่อเล่นใช้ได้แค่ตัวอักษรไทยหรืออังกฤษ ไม่มีตัวเลขหรือสัญลักษณ์', 'NICK_CHARS');
    var n = nickLen(t);
    if (n < 2 || n > PROFILE.nickMax) return fail('ชื่อเล่นยาว 2–' + PROFILE.nickMax + ' ตัวอักษร', 'NICK_LEN');
    var flat = t.toLowerCase().replace(/[\s]/g, '').replace(/(.)\1+/g, '$1');
    for (var i = 0; i < BAD_WORDS.length; i++) {
      if (flat.indexOf(BAD_WORDS[i]) >= 0 || t.toLowerCase().replace(/\s/g, '').indexOf(BAD_WORDS[i]) >= 0) return fail('ชื่อนี้ใช้ไม่ได้ ลองชื่ออื่นนะ', 'NICK_BAD');
    }
    return { ok: true, value: t };
  }

  /* ตรวจสิ่งที่เด็กแก้ในโปรไฟล์ (ส่งมาเฉพาะช่องที่แก้) คืนค่าที่จะเขียนลงชีต  st = นักเรียน, xp = xpStatus ของเด็ก */
  function planProfile(entry, st, xp, today) {
    var e = entry || {}, out = {}, lv = xp.level.lv;
    if (e.nick !== undefined) {
      if (st.nickLock) return fail('ครูล็อกชื่อเล่นไว้ ถ้าอยากเปลี่ยนให้บอกครู', 'NICK_LOCK');
      var c = checkNick(e.nick);
      if (!c.ok) return c;
      if (c.value !== st.nick) {
        var wait = st.nickAt ? PROFILE.nickDays - (dayNum(today) - dayNum(st.nickAt)) : 0;
        if (wait > 0) return fail('เปลี่ยนชื่อเล่นได้อีกครั้งในอีก ' + wait + ' วัน', 'NICK_WAIT');
        out.nick = c.value;
        out.nickAt = today;
      }
    }
    if (e.outfit !== undefined) {
      var o = findIn(PROFILE.outfits, e.outfit);
      if (!o) return fail('ไม่พบชุดนี้', 'INPUT');
      if (o.lv > lv) return fail(o.label + ' ปลดล็อกที่ระดับ ' + o.lv, 'LOCKED_ITEM');
      out.outfit = o.label;
    }
    if (e.color !== undefined) {
      var k = findIn(PROFILE.colors, e.color);
      if (!k) return fail('ไม่พบสีนี้', 'INPUT');
      if (k.lv > lv) return fail('สี' + k.label + ' ปลดล็อกที่ระดับ ' + k.lv, 'LOCKED_ITEM');
      out.color = k.label;
    }
    if (e.sports !== undefined) {
      var sp = (Array.isArray(e.sports) ? e.sports : []).map(function (x) { return findIn(PROFILE.sports, x); });
      if (sp.some(function (x) { return !x; }) || sp.length > PROFILE.maxSports) return fail('เลือกกีฬาที่ชอบได้ไม่เกิน ' + PROFILE.maxSports + ' อย่าง', 'INPUT');
      out.sports = sp.filter(function (x, i) { return sp.indexOf(x) === i; }).map(function (x) { return x.label; }).join(', ');
    }
    if (e.goal !== undefined) {
      var g = e.goal === '' ? { label: '' } : findIn(PROFILE.goals, e.goal);
      if (!g) return fail('ไม่พบเป้าหมายนี้', 'INPUT');
      out.goal = g.label;
    }
    if (e.motto !== undefined) {
      var m = e.motto === '' ? { label: '' } : findIn(PROFILE.mottos, e.motto);
      if (!m) return fail('ไม่พบคำประจำตัวนี้', 'INPUT');
      out.motto = m.label;
    }
    if (e.pins !== undefined) {
      var have = {};
      (xp.stickers || []).forEach(function (x) { if (x.got) have[x.id] = 1; });
      (xp.eventStickers || []).forEach(function (x) { have['ev:' + x.id] = 1; });
      var pins = Array.isArray(e.pins) ? e.pins.map(String) : [];
      if (pins.length > PROFILE.maxPins) return fail('โชว์สติกเกอร์ได้ไม่เกิน ' + PROFILE.maxPins + ' อัน', 'INPUT');
      for (var i = 0; i < pins.length; i++) if (!have[pins[i]]) return fail('ยังไม่ได้สติกเกอร์นี้', 'INPUT');
      out.pins = pins.filter(function (x, i) { return pins.indexOf(x) === i; }).join(',');
    }
    return { ok: true, cells: out };
  }

  /* สติกเกอร์ที่ปักไว้ → ไอคอนและชื่อ (ปกติ หรือ ev:รหัสอีเวนต์ = รุ่นพิเศษ) */
  function pinsView(ids, xp, events) {
    var all = {};
    STICKERS.forEach(function (k) { all[k.id] = { id: k.id, icon: k.icon, name: k.name }; });
    (events || []).forEach(function (ev) {
      var sp = String(ev.sticker || ''), m = /^(\S+)\s+(.+)$/.exec(sp);
      all['ev:' + ev.id] = { id: 'ev:' + ev.id, icon: m ? m[1] : '🎉', name: m ? m[2] : (sp || ev.name), special: true };
    });
    return String(ids || '').split(',').map(function (x) { return all[x.trim()]; }).filter(Boolean).slice(0, PROFILE.maxPins);
  }

  /* โปรไฟล์ของเด็กเอง (หน้าแต่งโปรไฟล์) */
  function profileView(st, xp, s, today, events) {
    var lv = xp.level.lv, o = findIn(PROFILE.outfits, st.outfit) || PROFILE.outfits[0], c = findIn(PROFILE.colors, st.color) || PROFILE.colors[0];
    var wait = st.nickAt ? Math.max(0, PROFILE.nickDays - (dayNum(today) - dayNum(st.nickAt))) : 0;
    return {
      nick: st.nick || '', nickLocked: !!st.nickLock, nickWait: wait,
      outfit: o.id, color: c.id,
      sports: String(st.sports || '').split(',').map(function (x) { var k = findIn(PROFILE.sports, x.trim()); return k ? k.id : ''; }).filter(Boolean),
      goal: (findIn(PROFILE.goals, st.goal) || {}).id || '', motto: (findIn(PROFILE.mottos, st.motto) || {}).id || '',
      pins: pinsView(st.pins, xp, events),
      /* rejected = ครูไม่อนุมัติรูปล่าสุด (รูปถูกลบแล้ว) เด็กเห็นข้อความนุ่มนวลให้ลองรูปใหม่ */
      photo: st.photo ? (st.photoOk === 'อนุมัติ' ? 'approved' : 'pending') : (st.photoOk === 'ไม่อนุมัติ' ? 'rejected' : 'none'),
      unlocked: {
        outfits: PROFILE.outfits.filter(function (x) { return x.lv <= lv; }).map(function (x) { return x.id; }),
        colors: PROFILE.colors.filter(function (x) { return x.lv <= lv; }).map(function (x) { return x.id; })
      }
    };
  }

  /* การ์ดนักกีฬาที่เพื่อนเห็น: ไม่มีชื่อจริง เลขประจำตัว หรือรูปจริง */
  function cardView(st, lv, events, extra) {
    var L = LEVELS[Math.max(0, Math.min(LEVELS.length - 1, (lv || 1) - 1))];
    var o = findIn(PROFILE.outfits, st.outfit) || PROFILE.outfits[0], c = findIn(PROFILE.colors, st.color) || PROFILE.colors[0];
    var g = findIn(PROFILE.goals, st.goal), m = findIn(PROFILE.mottos, st.motto);
    return {
      name: st.nick || ('เลขที่ ' + (st.no || '?')), classId: st.classId, lv: L.lv, icon: L.icon, title: L.title, arc: L.arc, arcName: ARCS[L.arc],
      outfit: o.id, color: c.id,
      sports: String(st.sports || '').split(',').map(function (x) { return findIn(PROFILE.sports, x.trim()); }).filter(Boolean)
        .map(function (x) { return { icon: x.icon, label: x.label }; }),
      goal: g ? { icon: g.icon, label: g.label } : null, motto: m ? m.label : '',
      pins: pinsView(st.pins, { stickers: [] }, events)
    };
  }

  /* ---------- อันดับ (สร้างทุกชั่วโมงจากข้อมูลทั้งโรงเรียน) ----------
   * people = [{ sid, name (ชื่อเล่นหรือ เลขที่ n), classId, arc, lv, week (แต้มสัปดาห์นี้), total, moved (ขยับสัปดาห์นี้), minutes, member (สมัครแล้ว) }]
   * คืน raw = ข้อมูลอันดับที่เก็บไว้ และ ranks = อันดับลีกของแต่ละคน { sid: [ภาค, อันดับ, แต้ม, จำนวนคนในลีก] } */
  function makeBoard(people, s, today, updated) {
    var ws = addDays(today, -weekdayIdx(today)), leagues = {}, ranks = {}, rooms = {};
    Object.keys(ARCS).forEach(function (a) { leagues[a] = []; });
    people.forEach(function (p) {
      if (p.week > 0 && leagues[p.arc]) leagues[p.arc].push(p);
      if (!p.member) return;
      var r = rooms[p.classId] || (rooms[p.classId] = { r: p.classId, m: 0, a: 0, min: 0 });
      r.m++;
      if (p.moved) r.a++;
      r.min += p.minutes || 0;
    });
    var out = {};
    Object.keys(leagues).forEach(function (a) {
      var list = leagues[a].sort(function (x, y) {
        return y.week - x.week || y.total - x.total || (x.classId < y.classId ? -1 : x.classId > y.classId ? 1 : 0) || (x.sid < y.sid ? -1 : 1);
      });
      list.forEach(function (p, i) { ranks[p.sid] = [+a, i + 1, p.week, list.length]; });
      out[a] = list.slice(0, s.leagueSize).map(function (p) {
        return { c: p.sid, k: p.card || '', n: p.name, r: p.classId, x: p.week, l: p.lv, o: p.outfit || '', cl: p.color || '' };
      });
    });
    var roomList = Object.keys(rooms).map(function (k) {
      var r = rooms[k];
      r.p = r.m ? Math.round(r.a * 100 / r.m) : 0;
      r.ok = r.m >= s.roomMinMembers;
      return r;
    }).sort(function (x, y) {
      return (y.ok - x.ok) || y.p - x.p || y.a - x.a || (x.r < y.r ? -1 : 1);
    });
    var k = 0;
    roomList.forEach(function (r) { r.k = r.ok ? ++k : 0; });
    return { raw: { updated: updated || '', week: ws, leagues: out, rooms: roomList }, ranks: ranks };
  }

  /* อันดับที่ส่งให้หน้าเว็บ: ไม่มีเลขประจำตัวของใคร มีแค่ me = ใช่ตัวเองไหม */
  function boardView(b, rank, student, lvNow, s, today) {
    if (!b || !b.week) return { ready: false };
    var ws = addDays(today, -weekdayIdx(today)), leagues = {};
    Object.keys(ARCS).forEach(function (a) {
      leagues[a] = ((b.leagues || {})[a] || []).map(function (e, i) {
        return { rank: i + 1, name: e.n, classId: e.r, xp: e.x, lv: e.l, me: e.c === student.code, card: e.k || '', outfit: e.o || 'sport', color: e.cl || 'violet' };
      });
    });
    var arc = rank && rank[0] ? rank[0] : lvNow.arc;
    var rooms = (b.rooms || []).map(function (r) {
      return { rank: r.k, classId: r.r, pct: r.p, moved: r.a, members: r.m, minutes: r.min, ok: r.ok, me: r.r === student.classId };
    });
    var myRoom = null;
    rooms.forEach(function (r) { if (r.me) myRoom = r; });
    return {
      ready: true, updated: b.updated, week: b.week, fresh: b.week === ws,
      arc: arc, arcName: ARCS[arc], arcs: ARCS, leagues: leagues,
      me: rank ? { arc: rank[0], rank: rank[1], xp: rank[2], of: rank[3] } : null,
      rooms: { minMembers: s.roomMinMembers, top: rooms.filter(function (r) { return r.ok; }).slice(0, 10), me: myRoom }
    };
  }

  /* ข้อมูลที่ส่งกลับให้หน้าเว็บ: เฉพาะของเด็กคนนี้ กับนาทีรวมของห้อง
   * o.logs/o.done = ของเด็กคนนี้ (หรือทั้งหมดก็ได้) o.board = อันดับที่สร้างทุกชั่วโมง o.rank = อันดับลีกของเด็กคนนี้ */
  function buildStatus(o) {
    var s = o.settings, k = o.klass, st = o.student, today = o.todayKey;
    var mine = mineOf(o.logs, k, st);
    var sum = summarize(mine, k, s, today);
    var ws = sum.current.start, we = sum.current.end;
    var classMinutes = 0, who = {}, classMoved = -1;
    var bw = o.board && o.board.week === addDays(today, -weekdayIdx(today)) ? o.board : null;
    (bw ? bw.rooms || [] : []).forEach(function (r) { if (r.r === k.id) { classMinutes = r.min; classMoved = r.a; } });
    if (classMoved < 0) {
      for (var i = 0; i < o.logs.length; i++) {
        var l = o.logs[i];
        if (l.classId === k.id && !l.excluded && l.date >= ws && l.date <= we) {
          classMinutes += Number(l.minutes) || 0;
          who[l.code] = 1;
        }
      }
      classMoved = Object.keys(who).length;
    }
    var dates = allowedDates(today, s.backfillDays);
    var list = mine.filter(function (x) { return (x.date >= ws && x.date <= we) || dates.indexOf(x.date) >= 0; })
      .sort(newestFirst).slice(0, 40).map(function (x) {
        var act = findActivity(x.activity), feel = findFeeling(x.feeling);
        return {
          id: x.id || '', date: x.date, minutes: Number(x.minutes) || 0,
          activity: act ? act.id : 'other', activityLabel: act ? act.label : String(x.activity || 'อื่น ๆ'),
          feeling: feel ? feel.id : '',
          status: x.excluded ? 'excluded' : 'counted',
          canDelete: canDelete(x, dates)
        };
      });
    var doneMine = missionsOf(o.done, st), exMine = extrasOf(o.extra, st);
    var xp = xpStatus(mine, doneMine, k, s, today, { extra: exMine, events: o.events });
    var missionDays = dates.map(function (d) {
      var items = [];
      MISSION_TYPES.forEach(function (t) {
        var m = missionFor(d, t.id, o.pool, k.grade, 1);
        var rec = findDone(doneMine, d, t.id);
        if (!m && !rec) return;
        var options = m ? [1, 2, 3].map(function (df) {
          var mt = missionFor(d, t.id, o.pool, k.grade, df).text;
          return {
            diff: df, stars: DIFF_STARS[df], text: mt, timer: timerOf(mt),
            points: s.xpMissionDiff[df - 1], locked: df > xp.maxDiff, unlockLv: df === 1 ? 1 : s.diffUnlock[df - 2]
          };
        }) : [];
        items.push({
          type: t.id, label: t.label, icon: t.icon, clip: m ? m.clip : '', clipDone: !!clipDone(exMine, t.id, d, today), options: options,
          done: !!rec, text: rec ? rec.text : '', diff: rec ? rec.diff : 0, stars: rec ? DIFF_STARS[rec.diff || 1] : '',
          proof: rec ? rec.proof : '', check: rec ? rec.check : '', points: rec ? missionPoints(rec, s) : 0
        });
      });
      return { date: d, items: items };
    });
    var qo = questOf(o.quests, k, today), quest = qo ? qo.text : '';
    var qDone = questDoneThisWeek(doneMine, today);
    return {
      today: today,
      schoolName: s.schoolName,
      student: { classId: k.id, code: st.code, grade: k.grade || 0 },
      settings: {
        minMinutesForStar: s.minMinutesForStar, starCapPerWeek: s.starCapPerWeek,
        backfillDays: s.backfillDays, maxMinutesPerLog: s.maxMinutesPerLog, maxMinutesPerDay: s.maxMinutesPerDay,
        maxLogsPerDay: s.maxLogsPerDay, minuteChoices: s.minuteChoices,
        xpMissionDiff: s.xpMissionDiff, diffUnlock: s.diffUnlock, xpMissionVideo: s.xpMissionVideo, xpClip: s.xpClip, clipSeconds: s.clipSeconds,
        xpMinuteCap: s.xpMinuteCap, xpPerStar: s.xpPerStar, xpStreak3: s.xpStreak3, xpStreak7: s.xpStreak7, streakRest: s.streakRest,
        dayBadges: s.dayBadges, xpWeekGoal: s.xpWeekGoal, xpQuizRight: s.xpQuizRight, xpQuizWrong: s.xpQuizWrong, xpEvent: s.xpEvent
      },
      xp: xp,
      missions: missionDays,
      program: { phase: sum.phase, week: sum.currentWeek, weeks: sum.weeks, start: sum.start },
      week: sum.current,
      history: sum.history,
      totalStars: sum.totalStars,
      programMinutes: sum.programMinutes,
      quest: quest,
      questWeek: qo ? {
        week: qo.week, text: qo.text, clip: qo.clip, clipDone: !!clipDone(exMine, 'quest', today, today),
        done: !!qDone, points: qDone ? missionPoints(qDone, s) : s.xpMissionVideo, check: qDone ? qDone.check : ''
      } : null,
      clip: { points: s.xpClip, seconds: s.clipSeconds },
      classWeek: { minutes: classMinutes, students: classMoved },
      board: boardView(o.board, o.rank, { code: st.code, classId: k.id }, xp.level, s, today),
      allowedDates: dates,
      dayUsage: dayUsage(mine, dates),
      logs: list,
      quiz: quizView(quizFor(today, k.grade, o.questions), quizToday(exMine, today), s),
      events: eventsView(o.events, mine, doneMine, exMine, s, today),
      dust: dustBlock(o.dust, exMine, s, today)
    };
  }

  /* ปฏิทินขยับของเด็ก 1 คน: นาทีที่นับของแต่ละวัน (ตั้งแต่วันเริ่มโครงการ ไม่เกิน 400 วัน) และสถิติของฉัน
   * ส่งแยกจากข้อมูลหลัก โหลดเฉพาะตอนเปิดหน้าปฏิทินหรือการ์ดของฉัน หน้าแรกจะได้ไม่ช้า */
  var WEEKDAY_NAMES = ['จันทร์', 'อังคาร', 'พุธ', 'พฤหัสบดี', 'ศุกร์', 'เสาร์', 'อาทิตย์'];
  function calendarView(o) {
    var s = o.settings, k = o.klass, today = o.todayKey;
    var mine = mineOf(o.logs || [], k, o.student), doneMine = missionsOf(o.done || [], o.student), exMine = extrasOf(o.extra || [], o.student);
    var totals = dayTotals(mine, s), first = '';
    Object.keys(totals).forEach(function (d) { if (totals[d].counted > 0 && (!first || d < first)) first = d; });
    var start = k.start && k.start <= today ? k.start : (first || today);
    if (dayNum(today) - dayNum(start) > 399) start = addDays(today, -399);
    var days = {}, active = 0, total = 0, byWd = [0, 0, 0, 0, 0, 0, 0];
    Object.keys(totals).forEach(function (d) {
      var m = totals[d].counted;
      if (d < start || d > today || !(m > 0)) return;
      days[d] = m; active++; total += m; byWd[weekdayIdx(d)] += m;
    });
    var acts = {};
    mine.forEach(function (l) {
      if (!isCounted(l) || l.date < start || l.date > today) return;
      var a = findActivity(l.activity), key = a ? a.id : 'other';
      acts[key] = (acts[key] || 0) + 1;
    });
    var top = null;
    Object.keys(acts).forEach(function (id) { if (!top || acts[id] > top.count) top = { id: id, count: acts[id] }; });
    if (top) { var ta = findActivity(top.id) || { icon: '✨', label: 'อื่น ๆ' }; top.icon = ta.icon; top.label = ta.label; }
    var wd = -1;
    byWd.forEach(function (m, i) { if (m > 0 && (wd < 0 || m > byWd[wd])) wd = i; });
    var xp = xpStatus(mine, doneMine, k, s, today, { extra: exMine, events: o.events });
    var goalDays = s.dayBadges.length ? s.dayBadges[s.dayBadges.length - 1].days : 0;
    return {
      start: start, today: today, days: days,
      activeDays: active, totalMinutes: total, avgMinutes: active ? Math.round(total / active) : 0,
      goalDays: goalDays, badges: s.dayBadges.map(function (b, i) { return { days: b.days, icon: BADGE_ICONS[i] || '🏅' }; }),
      bestStreak: xp.streak.best, streak: xp.streak.current,
      topActivity: top, bestWeekday: wd >= 0 ? WEEKDAY_NAMES[wd] : '',
      missions: doneMine.filter(function (m) { return m.check !== 'ไม่นับ'; }).length,
      events: (o.events || []).filter(function (ev) { return ev.end >= start && ev.start <= today; })
        .map(function (ev) { return { id: ev.id, name: ev.name, start: ev.start, end: ev.end }; })
    };
  }

  /* ---------- 6B-25 สรุปสัปดาห์ที่แล้วแบบสตอรี่ (ของเด็กคนเดียว ไม่มีข้อมูลเพื่อน) ----------
   * สัปดาห์ = จันทร์–อาทิตย์ก่อนสัปดาห์นี้ · ใช้ข้อมูลที่มีอยู่แล้ว: บันทึก ภารกิจ คำถาม แต้ม เป้าสัปดาห์ ศูนย์ฝึก */
  function storyView(o) {
    var s = o.settings, k = o.klass, today = o.todayKey;
    var mine = mineOf(o.logs || [], k, o.student), doneMine = missionsOf(o.done || [], o.student), exMine = extrasOf(o.extra || [], o.student);
    var ws = addDays(today, -weekdayIdx(today)), from = addDays(ws, -7), to = addDays(ws, -1);
    var totals = dayTotals(mine, s), days = [], minutes = 0, active = 0, best = -1, prev = 0, i;
    for (i = 0; i < 7; i++) {
      var d = addDays(from, i), m = totals[d] ? totals[d].counted : 0, pd = addDays(from, i - 7);
      days.push(m); minutes += m;
      if (m > 0) { active++; if (best < 0 || m > days[best]) best = i; }
      prev += totals[pd] ? totals[pd].counted : 0;
    }
    var acts = {};
    mine.forEach(function (l) {
      if (!isCounted(l) || l.date < from || l.date > to) return;
      var a = findActivity(l.activity), id = a ? a.id : 'other';
      if (!acts[id]) acts[id] = { id: id, icon: a ? a.icon : '✨', label: a ? a.label : 'อื่น ๆ', count: 0, minutes: 0 };
      acts[id].count++; acts[id].minutes += Number(l.minutes) || 0;
    });
    var actList = Object.keys(acts).map(function (x) { return acts[x]; }).sort(function (a, b) { return b.count - a.count || b.minutes - a.minutes; }).slice(0, 4);
    var mis = doneMine.filter(function (x) { return x.date >= from && x.date <= to && x.check !== 'ไม่นับ'; }), misDays = {};
    mis.forEach(function (x) { misDays[x.date] = 1; });
    var quiz = exMine.filter(function (x) { return x.kind === 'quiz' && x.check !== 'ไม่นับ' && x.ok && x.date >= from && x.date <= to; }).length;
    var L = xpLedger({ logs: mine, done: doneMine, extra: exMine, events: o.events, start: k.start, weeks: k.weeks, settings: s, today: today }), pts = 0, gl = null, gn = null;
    Object.keys(L.byDate).forEach(function (x) { if (x >= from && x <= to) pts += L.byDate[x]; });
    (L.goals || []).forEach(function (g) { if (g.start === from) gl = g; if (g.start === ws) gn = g; });
    return {
      from: from, to: to, minutes: minutes, prevMinutes: prev, days: days, activeDays: active,
      best: best >= 0 ? { day: best, minutes: days[best] } : null,
      acts: actList, missions: mis.length, missionDays: Object.keys(misDays).length, quizRight: quiz, points: pts,
      streak: L.streak.current, bestStreak: L.streak.best,
      goal: gl ? { goal: gl.goal, minutes: gl.minutes, reached: !!gl.reached } : null,
      next: gn ? { goal: gn.goal, xp: s.xpWeekGoal, school: true } : { goal: Math.max(60, Math.min(420, Math.ceil((minutes + 30) / 10) * 10)), xp: 0, school: false },
      center: storyCenter(o.center, today),
      empty: !minutes && !mis.length && !quiz
    };
  }

  /* ---------- 6B-25 จอใหญ่หน้าเสาธง (โหมดครู) มีแค่ห้องกับยอดรวม ไม่มีชื่อเด็ก ----------
   * อันดับห้อง = นาทีที่นับได้ของสัปดาห์นี้ ÷ จำนวนนักเรียนในห้อง (ห้องเล็กห้องใหญ่สู้กันได้) */
  function boardStats(o) {
    var s = o.settings, today = o.todayKey, ws = addDays(today, -weekdayIdx(today)), lw = addDays(ws, -7), yd = addDays(today, -1);
    var who = {}, rooms = {}, kids = 0, by = {};
    (o.roster || []).forEach(function (st) {
      if (!st || !st.active || !st.classId || !st.code || who[st.code]) return;
      who[st.code] = st.classId; kids++;
      (rooms[st.classId] || (rooms[st.classId] = { room: st.classId, kids: 0, week: 0, last: 0, today: 0 })).kids++;
    });
    (o.logs || []).forEach(function (l) { if (who[l.code] && l.date >= lw && l.date <= today) (by[l.code] = by[l.code] || []).push(l); });
    var tMin = 0, yMin = 0, movers = 0, full = 0, acts = {}, actN = 0;
    Object.keys(by).forEach(function (code) {
      var T = dayTotals(by[code], s), R = rooms[who[code]];
      Object.keys(T).forEach(function (d) {
        var m = T[d].counted;
        if (d === today) { tMin += m; if (m > 0) { movers++; R.today++; } if (m >= 60) full++; }
        if (d === yd) yMin += m;
        if (d >= ws) R.week += m; else R.last += m;
      });
      by[code].forEach(function (l) {
        if (l.date !== today || !isCounted(l)) return;
        var a = findActivity(l.activity), id = a ? a.id : 'other';
        if (!acts[id]) acts[id] = { id: id, icon: a ? a.icon : '✨', label: a ? a.label : 'อื่น ๆ', n: 0 };
        acts[id].n++; actN++;
      });
    });
    var list = Object.keys(rooms).map(function (x) { var R = rooms[x]; return { room: R.room, kids: R.kids, avg: Math.round(R.week / R.kids), last: R.last / R.kids, today: R.today, all: R.today >= R.kids }; }), win = null;
    list.forEach(function (R) { if (R.last > 0 && (!win || R.last > win.last)) win = R; });
    list.sort(function (a, b) { return b.avg - a.avg || (a.room < b.room ? -1 : a.room > b.room ? 1 : 0); });
    return {
      today: today, kids: kids, minutes: tMin, movers: movers, full60: full, yesterday: yMin,
      acts: Object.keys(acts).map(function (x) { return acts[x]; }).sort(function (a, b) { return b.n - a.n; }).slice(0, 4)
        .map(function (a) { return { id: a.id, icon: a.icon, label: a.label, pct: Math.round(a.n * 100 / actN) }; }),
      rooms: list.map(function (R) { return { room: R.room, kids: R.kids, avg: R.avg, today: R.today, all: R.all }; }),
      allToday: list.filter(function (R) { return R.all; }).map(function (R) { return R.room; }),
      lastWinner: win ? { room: win.room, avg: Math.round(win.last) } : null
    };
  }

  /* ตรวจรายการแล้วเตรียมแถวที่จะบันทึก พร้อมผลที่บอกเด็ก (ยังไม่เขียนลงที่เก็บ) */
  function planSubmit(o) {
    var mine = mineOf(o.logs, o.klass, o.student);
    var v = validateEntry(o.entry, { todayKey: o.todayKey, settings: o.settings, studentLogs: mine });
    if (!v.ok) return v;
    var before = summarize(mine, o.klass, o.settings, o.todayKey);
    var rec = {
      id: o.id, date: v.value.date, classId: o.klass.id, code: o.student.code,
      activity: v.value.activity.label, minutes: v.value.minutes, feeling: v.value.feeling.label,
      excluded: false, channel: 'เว็บแอป',
      week: weekOf(v.value.date, o.klass.start), row: 0
    };
    var withRec = mine.concat([rec]);
    var after = summarize(withRec, o.klass, o.settings, o.todayKey);
    var day = dayTotals(withRec, o.settings)[rec.date] || { counted: 0 };
    var doneMine = missionsOf(o.done, o.student), more = moreOf(o);
    var xb = xpStatus(mine, doneMine, o.klass, o.settings, o.todayKey, more);
    var xa = xpStatus(withRec, doneMine, o.klass, o.settings, o.todayKey, more);
    var weeks = o.klass.weeks || 8;
    var inProgram = rec.week >= 1 && rec.week <= weeks && after.history.length >= rec.week;
    return {
      ok: true, rec: rec,
      result: {
        id: rec.id, date: rec.date, minutes: rec.minutes,
        starsGained: after.totalStars - before.totalStars,
        dayCounted: day.counted, inProgram: inProgram, week: rec.week,
        weekStars: inProgram ? after.history[rec.week - 1].stars : 0,
        starCap: o.settings.starCapPerWeek, minForStar: o.settings.minMinutesForStar,
        xpGained: xa.total - xb.total, levelUp: levelUp(xb.level, xa.level, o.settings), badge: badgeGained(xb, xa),
        goal: !xb.weekGoal || xb.weekGoal.reached || !xa.weekGoal || !xa.weekGoal.reached ? null : xa.weekGoal,
        stickers: stickersGained(xb, xa), events: eventGained(xb, xa)
      }
    };
  }

  /* กดทำภารกิจแล้ว o = { settings, klass, student, logs, done (ทั้งหมด), pool, todayKey, entry: {date, type, diff}, id } */
  function planMission(o) {
    var e = o.entry || {}, s = o.settings;
    var type = String(e.type || '');
    var t = null;
    for (var i = 0; i < MISSION_TYPES.length; i++) if (MISSION_TYPES[i].id === type) t = MISSION_TYPES[i];
    if (!t) return fail('ไม่พบภารกิจนี้', 'INPUT');
    var date = toKey(e.date);
    if (!date || allowedDates(o.todayKey, s.backfillDays).indexOf(date) < 0) {
      return fail('ภารกิจกดย้อนหลังได้ไม่เกิน ' + s.backfillDays + ' วัน', 'DATE');
    }
    var diff = parseInt(e.diff, 10);
    if (!(diff >= 1 && diff <= 3)) return fail('เลือกความยาก ⭐ ⭐⭐ หรือ ⭐⭐⭐ ก่อนนะ', 'INPUT');
    var m = missionFor(date, type, o.pool, o.klass.grade, diff);
    if (!m) return fail('วันนี้ยังไม่มี' + t.label + ' ให้บอกครู', 'NO_MISSION');
    var mine = mineOf(o.logs, o.klass, o.student), doneMine = missionsOf(o.done, o.student);
    if (findDone(doneMine, date, type)) return fail(t.label + 'ของวันนั้นทำไปแล้ว เก่งมาก', 'DONE');
    var more = moreOf(o);
    var xb = xpStatus(mine, doneMine, o.klass, s, o.todayKey, more);
    if (diff > xb.maxDiff) {
      return fail(DIFF_STARS[diff] + ' จะเปิดเมื่อถึงระดับ ' + s.diffUnlock[diff - 2] + ' สู้ ๆ นะ', 'LOCKED_DIFF');
    }
    var rec = {
      id: o.id, date: date, classId: o.klass.id, code: o.student.code, type: type, text: m.text, diff: diff,
      proof: '', file: '', gesture: '', check: '', tag: tagOf(m.text), row: 0
    };
    var xa = xpStatus(mine, doneMine.concat([rec]), o.klass, s, o.todayKey, more);
    return {
      ok: true, rec: rec,
      result: {
        kind: 'mission', type: type, label: t.label, icon: t.icon, text: m.text, date: date, diff: diff, stars: DIFF_STARS[diff],
        xpGained: xa.total - xb.total, started: xa.started, levelUp: levelUp(xb.level, xa.level, s), badge: badgeGained(xb, xa),
        stickers: stickersGained(xb, xa), events: eventGained(xb, xa)
      }
    };
  }

  function findDeletable(mine, id, okDates) {
    var hit = null;
    for (var i = 0; i < mine.length; i++) if (mine[i].id && mine[i].id === String(id)) hit = mine[i];
    if (!hit) return fail('ไม่พบรายการนี้ อาจถูกลบไปแล้ว', 'NOT_FOUND');
    if (!canDelete(hit, okDates)) return fail('รายการนี้ลบเองไม่ได้แล้ว ถ้าบันทึกผิดให้บอกครู', 'NO_DELETE');
    return { ok: true, log: hit };
  }

  /* เควสบ้านประจำสัปดาห์: กดทำแล้ว (ทำกับคนในบ้าน + สัญญานิ้วก้อย) สัปดาห์ละ 1 ครั้ง
   * o = { ...เหมือน planMission, quests } */
  function planQuest(o) {
    var s = o.settings, today = o.todayKey;
    var q = questOf(o.quests, o.klass, today);
    if (!q) return fail('ตอนนี้ยังไม่มีเควสบ้านประจำสัปดาห์', 'NO_QUEST');
    var mine = mineOf(o.logs, o.klass, o.student), doneMine = missionsOf(o.done, o.student), more = moreOf(o);
    if (questDoneThisWeek(doneMine, today)) return fail('ทำเควสบ้านของสัปดาห์นี้แล้ว เก่งมาก', 'WEEK_DONE');
    var rec = {
      id: o.id, date: today, classId: o.klass.id, code: o.student.code, type: 'quest', text: q.text, diff: 0,
      proof: '', file: '', gesture: '', check: '', tag: '', row: 0
    };
    var xb = xpStatus(mine, doneMine, o.klass, s, today, more);
    var xa = xpStatus(mine, doneMine.concat([rec]), o.klass, s, today, more);
    return {
      ok: true, rec: rec,
      result: {
        kind: 'quest', type: 'quest', label: 'เควสบ้าน', icon: '🏡', text: q.text, date: today,
        xpGained: xa.total - xb.total, started: xa.started, levelUp: levelUp(xb.level, xa.level, s), badge: badgeGained(xb, xa),
        stickers: stickersGained(xb, xa), events: eventGained(xb, xa)
      }
    };
  }

  /* ดูคลิปครบ: หน้าเว็บนับเวลาที่เล่นจริง (ข้ามไปข้างหน้าไม่นับ) แล้วส่งมา
   * entry = { kind: move|habit|quest, date } ภารกิจได้วันละ 1 ครั้งต่อภารกิจ เควสบ้านสัปดาห์ละ 1 ครั้ง */
  var CLIP_KINDS = { move: 'ภารกิจขยับ', habit: 'ภารกิจสุขนิสัย', quest: 'เควสบ้าน' };
  function planClip(o) {
    var s = o.settings, today = o.todayKey, e = o.entry || {}, kind = String(e.kind || '');
    if (!CLIP_KINDS.hasOwnProperty(kind)) return fail('ไม่พบคลิปนี้', 'INPUT');
    var date = today, clip = '', text = '';
    if (kind === 'quest') {
      var q = questOf(o.quests, o.klass, today);
      if (!q || !q.clip) return fail('เควสบ้านสัปดาห์นี้ไม่มีคลิป', 'NO_CLIP');
      clip = q.clip; text = q.text;
    } else {
      date = toKey(e.date);
      if (!date || allowedDates(today, s.backfillDays).indexOf(date) < 0) {
        return fail('คลิปของภารกิจย้อนหลังได้ไม่เกิน ' + s.backfillDays + ' วัน', 'DATE');
      }
      var m = missionFor(date, kind, o.pool, o.klass.grade, 1);
      if (!m || !m.clip) return fail('ภารกิจนี้ไม่มีคลิป', 'NO_CLIP');
      clip = m.clip; text = m.text;
    }
    var mine = mineOf(o.logs, o.klass, o.student), doneMine = missionsOf(o.done, o.student), more = moreOf(o);
    if (clipDone(more.extra, kind, date, today)) return fail('ดูคลิปนี้ครบแล้ว ได้แต้มไปแล้วนะ', 'DONE');
    var rec = { id: o.id, date: date, classId: o.klass.id, code: o.student.code, kind: 'clip', ref: kind, text: clip, answer: -1, ok: true, check: '', row: 0 };
    var xb = xpStatus(mine, doneMine, o.klass, s, today, more);
    var xa = xpStatus(mine, doneMine, o.klass, s, today, { extra: more.extra.concat([rec]), events: more.events });
    return {
      ok: true, rec: rec,
      result: {
        kind: 'clip', type: kind, label: CLIP_KINDS[kind], text: text, date: date,
        xpGained: xa.total - xb.total, started: xa.started, levelUp: levelUp(xb.level, xa.level, s), badge: badgeGained(xb, xa),
        stickers: stickersGained(xb, xa), events: eventGained(xb, xa)
      }
    };
  }

  function moreOf(o) { return { extra: extrasOf(o.extra, o.student), events: o.events || [] }; }

  /* ตอบคำถามวันนี้ o = { ...เหมือน planMission, extra, events, questions, entry: { choice } } */
  function planQuiz(o) {
    var s = o.settings, today = o.todayKey;
    var q = quizFor(today, o.klass.grade, o.questions);
    if (!q) return fail('วันนี้ยังไม่มีคำถาม', 'NO_QUIZ');
    var mine = mineOf(o.logs, o.klass, o.student), doneMine = missionsOf(o.done, o.student), more = moreOf(o);
    if (quizToday(more.extra, today)) return fail('วันนี้ตอบไปแล้ว พรุ่งนี้มีข้อใหม่นะ', 'DONE');
    var c = parseInt(o.entry && o.entry.choice, 10);
    if (!(c >= 0 && c < q.choices.length && q.choices[c])) return fail('เลือกคำตอบก่อนนะ', 'INPUT');
    var rec = { id: o.id, date: today, classId: o.klass.id, code: o.student.code, kind: 'quiz', ref: q.ref || '', answer: c, ok: c === q.answer, check: '', row: 0 };
    var xb = xpStatus(mine, doneMine, o.klass, s, today, more);
    var xa = xpStatus(mine, doneMine, o.klass, s, today, { extra: more.extra.concat([rec]), events: more.events });
    return {
      ok: true, rec: rec,
      result: {
        kind: 'quiz', correct: rec.ok, chosen: c, answer: q.answer, why: q.why || '',
        xpGained: xa.total - xb.total, levelUp: levelUp(xb.level, xa.level, s), badge: badgeGained(xb, xa),
        stickers: stickersGained(xb, xa), events: eventGained(xb, xa)
      }
    };
  }

  /* กด "ทำแล้ว" ภารกิจอีเวนต์แบบกดทำเอง o.entry = { event: รหัสอีเวนต์, task: 1–3 } */
  function planEvent(o) {
    var s = o.settings, today = o.todayKey, e = o.entry || {}, ev = null;
    (o.events || []).forEach(function (x) { if (x.id === String(e.event || '')) ev = x; });
    if (!ev || today < ev.start || today > ev.end) return fail('อีเวนต์นี้ไม่ได้เปิดอยู่ตอนนี้', 'NO_EVENT');
    var i = parseInt(e.task, 10), t = null;
    (ev.tasks || []).forEach(function (x, k) { if ((x.n || k + 1) === i) t = x; });
    if (!t) return fail('ไม่พบภารกิจนี้', 'INPUT');
    if (t.kind !== 'check') return fail('ภารกิจนี้ระบบนับให้เองจากที่บันทึก', 'AUTO');
    var mine = mineOf(o.logs, o.klass, o.student), doneMine = missionsOf(o.done, o.student), more = moreOf(o);
    var ref = ev.id + '#' + i;
    for (var k = 0; k < more.extra.length; k++) {
      var x = more.extra[k];
      if (x.kind === 'event' && x.ref === ref) {
        return x.check === 'ไม่นับ' ? fail('ครูไม่นับรายการนี้ ถ้าสงสัยถามครูได้นะ', 'NO_COUNT') : fail('ทำภารกิจนี้แล้ว เก่งมาก', 'DONE');
      }
    }
    var rec = { id: o.id, date: today, classId: o.klass.id, code: o.student.code, kind: 'event', ref: ref, text: t.text, answer: -1, ok: true, check: '', row: 0 };
    var xb = xpStatus(mine, doneMine, o.klass, s, today, more);
    var xa = xpStatus(mine, doneMine, o.klass, s, today, { extra: more.extra.concat([rec]), events: more.events });
    return {
      ok: true, rec: rec, event: ev,
      result: {
        kind: 'event', event: ev.id, name: ev.name, task: i, text: t.text,
        xpGained: xa.total - xb.total, levelUp: levelUp(xb.level, xa.level, s), badge: badgeGained(xb, xa),
        stickers: stickersGained(xb, xa), events: eventGained(xb, xa)
      }
    };
  }

  /* ---------- โหมดฝุ่น PM2.5 ----------
   * เกณฑ์กรมควบคุมมลพิษ (PM2.5 เฉลี่ย 24 ชม. มคก./ลบ.ม. ตั้งแต่ 1 มิ.ย. 2566):
   * 0–15 ฟ้า · 15.1–25 เขียว · 25.1–37.5 เหลือง · 37.6–75 ส้ม · 75.1 ขึ้นไป แดง
   * เก็บค่าของวันนี้ไว้ 1 ก้อน { date, v, lv, at, st, id, max, ovr, err } max = ระดับสูงสุดของวันนี้ ovr = ครูกำหนดเอง (1–5) */
  var DUST = [
    null,
    { lv: 1, id: 'blue', label: 'ฟ้า', name: 'อากาศดีมาก', color: '#3FB6F2', max: 15 },
    { lv: 2, id: 'green', label: 'เขียว', name: 'อากาศดี', color: '#4CC764', max: 25 },
    { lv: 3, id: 'yellow', label: 'เหลือง', name: 'ปานกลาง', color: '#F2C21B', max: 37.5 },
    { lv: 4, id: 'orange', label: 'ส้ม', name: 'เริ่มมีผลต่อสุขภาพ', color: '#FF8A1F', max: 75 },
    { lv: 5, id: 'red', label: 'แดง', name: 'มีผลต่อสุขภาพ', color: '#E5383B', max: Infinity }
  ];
  var DUST_TIPS = [
    '',
    'อากาศดีมาก ออกไปวิ่งเล่นได้เต็มที่เลย!',
    'อากาศดี ขยับกลางแจ้งได้ตามปกติ',
    'อากาศพอใช้ ขยับได้ ถ้าไอหรือแสบตาให้พักนะ',
    'ฝุ่นเยอะ ขยับในบ้านดีกว่า ออกนอกบ้านใส่หน้ากากนะ',
    'ฝุ่นเยอะมาก งดเล่นกลางแจ้ง ขยับในบ้าน ปิดประตูหน้าต่างนะ'
  ];
  var DUST_CARE = 'ถ้าไอ หายใจไม่สะดวก หรือเป็นหอบหืด ให้หยุดพักแล้วบอกผู้ใหญ่';
  /* ภารกิจนักสู้ฝุ่น: วันฝุ่นได้ 1 ข้อ หมุนตามวัน ทั้งโรงเรียนได้ข้อเดียวกัน */
  var DUST_TASKS = [
    'บอกคนในบ้านว่าวันนี้ฝุ่นสีอะไร',
    'ช่วยปิดประตูหน้าต่างตอนฝุ่นเยอะ',
    'กลับเข้าบ้านแล้วล้างหน้าล้างมือ',
    'ดื่มน้ำเปล่าเพิ่มอีก 2 แก้ว',
    'ใส่หน้ากากทุกครั้งที่ออกนอกบ้านวันนี้',
    'ชวนคนในบ้านขยับในบ้านด้วยกัน 10 นาที'
  ];
  function dustLevel(v) {
    v = Number(v);
    if (!isFinite(v) || v < 0) return 0;
    for (var i = 1; i < DUST.length; i++) if (v <= DUST[i].max) return i;
    return 5;
  }
  function dustDist(a, b, c, d) {
    var R = Math.PI / 180, x = (d - b) * R * Math.cos((a + c) / 2 * R), y = (c - a) * R;
    return Math.sqrt(x * x + y * y) * 6371;
  }
  /* ค่าจาก Air4Thai → สถานีที่ใช้ (สถานีที่ครูกำหนด หรือสถานีใกล้โรงเรียนที่สุดในรัศมี 30 กม. ที่มีค่า PM2.5) */
  function dustPick(data, s) {
    var list = data && (data.stations || data.Stations || (Array.isArray(data) ? data : [])) || [], best = null;
    list.forEach(function (x) {
      var a = x.AQILast || x.LastUpdate || {}, pm = a.PM25 || a['PM2.5'] || {};
      var v = parseFloat(pm.value !== undefined ? pm.value : pm.Value);
      if (!isFinite(v) || v < 0) return;
      var id = String(x.stationID || x.StationID || ''), la = parseFloat(x.lat), ln = parseFloat(x['long'] !== undefined ? x['long'] : x.lng);
      var km = isFinite(la) && isFinite(ln) ? dustDist(s.dustLat, s.dustLng, la, ln) : 9999;
      var mine = s.dustStation && id.toLowerCase() === s.dustStation.toLowerCase();
      if (!mine && km > 30) return;
      var c = { id: id, st: String(x.nameTH || x.areaTH || x.nameEN || id).slice(0, 80), v: Math.round(v * 10) / 10, at: String((a.date || '') + ' ' + (a.time || '')).trim(), km: Math.round(km * 10) / 10, mine: mine };
      if (!best || (c.mine && !best.mine) || (c.mine === best.mine && c.km < best.km)) best = c;
    });
    return best;
  }
  /* รวมค่าที่ดึงได้เข้ากับของเดิม: ข้ามวันเริ่มใหม่ ระดับสูงสุดของวันไม่ลด */
  function dustMerge(prev, pick, today) {
    var p = prev && prev.date === today ? prev : { date: today, max: 0, ovr: 0 };
    if (!pick) return { date: today, v: p.v, lv: p.lv || 0, at: p.at || '', st: p.st || '', id: p.id || '', max: p.max || 0, ovr: p.ovr || 0, err: 'ไม่มีค่าฝุ่นจากสถานีใกล้โรงเรียน' };
    var lv = dustLevel(pick.v);
    return { date: today, v: pick.v, lv: lv, at: pick.at, st: pick.st, id: pick.id, max: Math.max(p.max || 0, lv), ovr: p.ovr || 0, err: '' };
  }
  /* สิ่งที่หน้าเว็บใช้: lv = ระดับของวันนี้ (ครูกำหนด หรือสูงสุดของวัน) on = ถึงระดับวันฝุ่น */
  function dustView(d, today, s) {
    if (!s || !s.dustOn) return null;
    var ok = d && d.date === today, lv = ok ? (d.ovr || d.max || 0) : 0, L = DUST[lv];
    return {
      lv: lv, id: L ? L.id : '', label: L ? L.label : '', name: L ? L.name : '', color: L ? L.color : '',
      v: ok && isFinite(d.v) ? d.v : null, now: ok ? d.lv || 0 : 0, at: ok ? d.at || '' : '', st: ok ? d.st || '' : '',
      src: ok && d.ovr ? 'teacher' : lv ? 'auto' : '', on: lv >= s.dustFrom, from: s.dustFrom,
      tip: DUST_TIPS[lv] || '', care: lv >= 4 ? DUST_CARE : ''
    };
  }
  function dustTaskFor(today) {
    var n = DUST_TASKS.length, i = ((dayNum(today) % n) + n) % n;
    return { n: i + 1, text: DUST_TASKS[i] };
  }
  function dustToday(exMine, today) {
    for (var i = 0; i < (exMine || []).length; i++) if (exMine[i].kind === 'dust' && exMine[i].date === today) return exMine[i];
    return null;
  }
  /* ข้อมูลฝุ่นในหน้าหลักของเด็ก */
  function dustBlock(d, exMine, s, today) {
    var v = dustView(d, today, s);
    if (!v) return null;
    if (v.on) {
      var t = dustTaskFor(today), rec = dustToday(exMine, today);
      v.task = { n: t.n, text: t.text, points: s.xpDust, done: !!rec, check: rec ? rec.check : '' };
    }
    return v;
  }
  /* กด "ทำแล้ว" ภารกิจนักสู้ฝุ่น  o.dust = ค่าฝุ่นที่เก็บไว้ */
  function planDust(o) {
    var s = o.settings, today = o.todayKey, v = dustView(o.dust, today, s);
    if (!v || !v.on) return fail('วันนี้ไม่ใช่วันฝุ่นเยอะ ภารกิจนี้ยังไม่เปิดนะ', 'NO_DUST');
    var mine = mineOf(o.logs, o.klass, o.student), doneMine = missionsOf(o.done, o.student), more = moreOf(o);
    if (dustToday(more.extra, today)) return fail('วันนี้ทำภารกิจนักสู้ฝุ่นแล้ว เก่งมาก', 'DONE');
    var t = dustTaskFor(today);
    var rec = { id: o.id, date: today, classId: o.klass.id, code: o.student.code, kind: 'dust', ref: String(t.n), text: t.text, answer: -1, ok: true, check: '', row: 0 };
    var xb = xpStatus(mine, doneMine, o.klass, s, today, more);
    var xa = xpStatus(mine, doneMine, o.klass, s, today, { extra: more.extra.concat([rec]), events: more.events });
    return {
      ok: true, rec: rec,
      result: {
        kind: 'dust', text: t.text, xpGained: xa.total - xb.total, levelUp: levelUp(xb.level, xa.level, s), badge: badgeGained(xb, xa),
        stickers: stickersGained(xb, xa), events: eventGained(xb, xa)
      }
    };
  }

  /* ---------- เกมศูนย์ฝึกกีฬา ----------
   * เหรียญ = แต้มรวมทั้งหมด − ราคาของที่ตั้งอยู่บนลาน (ใช้เหรียญแล้วแต้ม เลเวล และอันดับไม่ลด)
   * รื้อของได้ คืนเหรียญเต็ม ย้ายฟรี  ลานเริ่ม 3×3 ช่อง Lv.4 ขยายเป็น 4×4 Lv.7 เป็น 5×5
   * ช่อง = แถว × 5 + คอลัมน์ (0–24) ขยายลานแล้วของเดิมอยู่ที่เดิม  ผัง = [[ช่อง, ของ, ดาว], ...]
   * ดาวอาคาร = ผลรวมดาวของอาคาร (ของตกแต่งไม่มีดาว) ใช้จัดอันดับแยกชั้น */
  var GAME = {
    items: [
      { id: 'track', icon: '🏃', label: 'ลู่วิ่ง', kind: 'b', cost: [60, 90, 120], lv: 1, tile: 'track' },
      { id: 'yoga', icon: '🧘', label: 'ลานโยคะ', kind: 'b', cost: [60, 90, 120], lv: 1, tile: 'sand' },
      { id: 'badminton', icon: '🏸', label: 'สนามแบดมินตัน', kind: 'b', cost: [80, 120, 160], lv: 1, tile: 'court' },
      { id: 'football', icon: '⚽', label: 'สนามฟุตบอล', kind: 'b', cost: [100, 150, 200], lv: 1, tile: 'grass' },
      { id: 'basketball', icon: '🏀', label: 'สนามบาส', kind: 'b', cost: [100, 150, 200], lv: 1, tile: 'court' },
      { id: 'boxing', icon: '🥊', label: 'เวทีมวย', kind: 'b', cost: [120, 180, 240], lv: 4, tile: 'ring' },
      { id: 'gym', icon: '🏋️', label: 'ยิม', kind: 'b', cost: [150, 225, 300], lv: 4, tile: 'floor' },
      { id: 'pool', icon: '🏊', label: 'สระว่ายน้ำ', kind: 'b', cost: [200, 300, 400], lv: 7, tile: 'water' },
      /* 6B-22: อาคารเพิ่ม 13 แบบ ปลดล็อกกระจาย Lv.1–8 */
      { id: 'rope', icon: '🦘', label: 'ลานกระโดดเชือก', kind: 'b', cost: [60, 90, 120], lv: 1, tile: 'floor' },
      { id: 'pingpong', icon: '🏓', label: 'ลานปิงปอง', kind: 'b', cost: [70, 105, 140], lv: 1, tile: 'floor' },
      { id: 'takraw', icon: '🧶', label: 'สนามตะกร้อ', kind: 'b', cost: [80, 120, 160], lv: 2, tile: 'court' },
      { id: 'petanque', icon: '⚪', label: 'ลานเปตอง', kind: 'b', cost: [70, 105, 140], lv: 2, tile: 'sand' },
      { id: 'volleyball', icon: '🏐', label: 'สนามวอลเลย์บอล', kind: 'b', cost: [100, 150, 200], lv: 3, tile: 'sand' },
      { id: 'futsal', icon: '🥅', label: 'สนามฟุตซอล', kind: 'b', cost: [110, 165, 220], lv: 3, tile: 'court' },
      { id: 'tennis', icon: '🎾', label: 'สนามเทนนิส', kind: 'b', cost: [120, 180, 240], lv: 4, tile: 'court' },
      { id: 'skate', icon: '🛹', label: 'ลานสเก็ตบอร์ด', kind: 'b', cost: [130, 195, 260], lv: 5, tile: 'floor' },
      { id: 'dojo', icon: '🥋', label: 'โดโจเทควันโด', kind: 'b', cost: [140, 210, 280], lv: 5, tile: 'floor' },
      { id: 'bike', icon: '🚴', label: 'ลู่จักรยาน', kind: 'b', cost: [150, 225, 300], lv: 6, tile: 'track' },
      { id: 'gymnast', icon: '🤸', label: 'ลานยิมนาสติก', kind: 'b', cost: [150, 225, 300], lv: 6, tile: 'floor' },
      { id: 'climb', icon: '🧗', label: 'กำแพงปีนผา', kind: 'b', cost: [200, 300, 400], lv: 7, tile: 'floor' },
      { id: 'archery', icon: '🏹', label: 'ลานยิงธนู', kind: 'b', cost: [220, 330, 440], lv: 8, tile: 'grass' },
      { id: 'tree', icon: '🌳', label: 'ต้นไม้', kind: 'd', cost: [10], lv: 1, tile: 'grass' },
      { id: 'flag', icon: '🚩', label: 'ธง', kind: 'd', cost: [20], lv: 1, tile: 'grass' },
      { id: 'light', icon: '💡', label: 'ไฟสนาม', kind: 'd', cost: [30], lv: 1, tile: 'grass' },
      { id: 'stand', icon: '🪑', label: 'อัฒจันทร์', kind: 'd', cost: [50], lv: 1, tile: 'floor' },
      /* 6B-22: ของตกแต่งเพิ่ม 12 แบบ ปลดล็อกกระจาย Lv.1–10 */
      { id: 'water', icon: '🚰', label: 'ตู้น้ำดื่ม', kind: 'd', cost: [20], lv: 1, tile: 'floor' },
      { id: 'bench', icon: '💺', label: 'ม้านั่งพัก', kind: 'd', cost: [15], lv: 1, tile: 'grass' },
      { id: 'flowers', icon: '🌷', label: 'แปลงดอกไม้', kind: 'd', cost: [15], lv: 1, tile: 'grass' },
      { id: 'bins', icon: '♻️', label: 'ถังขยะแยกประเภท', kind: 'd', cost: [20], lv: 2, tile: 'floor' },
      { id: 'balloons', icon: '🎈', label: 'ลูกโป่ง', kind: 'd', cost: [25], lv: 2, tile: 'grass' },
      { id: 'palm', icon: '🌴', label: 'ต้นมะพร้าว', kind: 'd', cost: [30], lv: 3, tile: 'grass' },
      { id: 'tent', icon: '⛺', label: 'เต็นท์พักแรม', kind: 'd', cost: [40], lv: 3, tile: 'grass' },
      { id: 'playground', icon: '🎠', label: 'สนามเด็กเล่น', kind: 'd', cost: [60], lv: 4, tile: 'sand' },
      { id: 'fountain', icon: '⛲', label: 'น้ำพุ', kind: 'd', cost: [80], lv: 5, tile: 'floor' },
      { id: 'arch', icon: '⛩️', label: 'ซุ้มประตู', kind: 'd', cost: [70], lv: 6, tile: 'grass' },
      { id: 'statue', icon: '🗿', label: 'รูปปั้นนักกีฬา', kind: 'd', cost: [120], lv: 9, tile: 'floor' },
      { id: 'trophy', icon: '🏆', label: 'ถ้วยรางวัลยักษ์', kind: 'd', cost: [150], lv: 10, tile: 'floor' }
    ],
    sizes: [{ lv: 1, n: 3 }, { lv: 4, n: 4 }, { lv: 7, n: 5 }],
    likesPerDay: 3
  };
  function gameItem(id) { for (var i = 0; i < GAME.items.length; i++) if (GAME.items[i].id === id) return GAME.items[i]; return null; }
  function gameSize(lv) { var n = 3; GAME.sizes.forEach(function (z) { if ((lv || 1) >= z.lv) n = z.n; }); return n; }
  function gameNext(lv) { for (var i = 0; i < GAME.sizes.length; i++) if (GAME.sizes[i].lv > (lv || 1)) return GAME.sizes[i]; return null; }
  function gameCell(p) { return typeof p === 'number' && p >= 0 && p < 25 && p === Math.floor(p); }
  function gameIn(p, n) { return gameCell(p) && p % 5 < n && Math.floor(p / 5) < n; }
  function gameCost(it, s) { var t = 0; for (var i = 0; it && i < s && i < it.cost.length; i++) t += it.cost[i]; return t; }
  /* ผังจากชีต → ตัดของที่ไม่รู้จัก ช่องซ้ำ และดาวเกินออก */
  function gameParse(raw) {
    var list = raw, out = [], used = {};
    if (typeof raw === 'string') { try { list = JSON.parse(raw || '[]'); } catch (e) { list = []; } }
    (Array.isArray(list) ? list : []).forEach(function (x) {
      if (!Array.isArray(x)) return;
      var p = Number(x[0]), it = gameItem(String(x[1])), s = Math.round(Number(x[2]) || 1);
      if (!it || !gameCell(p) || used[p]) return;
      used[p] = 1;
      out.push([p, it.id, Math.max(1, Math.min(it.cost.length, s))]);
    });
    return out.sort(function (a, b) { return a[0] - b[0]; });
  }
  function gameSpent(L) { var t = 0; L.forEach(function (x) { t += gameCost(gameItem(x[1]), x[2]); }); return t; }
  function gameStars(L) { var t = 0; L.forEach(function (x) { var it = gameItem(x[1]); if (it && it.kind === 'b') t += x[2]; }); return t; }
  function gameAt(L, p) { for (var i = 0; i < L.length; i++) if (L[i][0] === p) return i; return -1; }
  /* ขนาดลานที่ต้องวาดให้เห็นของครบ (ถ้าแต้มลดเพราะครูไม่นับ ของที่อยู่นอกลานยังเห็นและย้ายเข้ามาได้) */
  function gameExtent(L) { var n = 3; L.forEach(function (x) { n = Math.max(n, x[0] % 5 + 1, Math.floor(x[0] / 5) + 1); }); return n; }

  /* ศูนย์ฝึกของฉัน (xp = ผลจาก xpStatus) */
  /* ex = { petSpent, pet, today } (สัตว์เลี้ยงคู่หู ใช้เหรียญกระเป๋าเดียวกัน) */
  function gameView(L, xp, likes, ex) {
    ex = ex || {};
    var total = Number(xp && xp.total) || 0, lv = xp && xp.level ? xp.level.lv : 1, spent = gameSpent(L), nx = gameNext(lv), n = gameSize(lv), ps = Number(ex.petSpent) || 0;
    return {
      coins: Math.max(0, total - spent - ps), total: total, spent: spent, petSpent: ps, lv: lv, open: n, size: Math.max(n, gameExtent(L)),
      pet: petView(ex.pet, lv, ex.today, true), petCat: petCatalog(),
      next: nx ? { lv: nx.lv, n: nx.n } : null, cells: L, stars: gameStars(L), likes: Number(likes) || 0,
      likesPerDay: GAME.likesPerDay,
      items: GAME.items.map(function (it) { return { id: it.id, icon: it.icon, label: it.label, kind: it.kind, cost: it.cost.slice(), lv: it.lv, tile: it.tile }; })
    };
  }

  /* สร้าง อัปดาว ย้าย (ช่องปลายทางมีของ = สลับที่) หรือรื้อ ครั้งละ 1 อย่าง
   * o = { layout, xp, op: build|up|move|remove, p, to, item } */
  function planGame(o) {
    var L = gameParse(o.layout).map(function (x) { return x.slice(); });
    var lv = o.xp && o.xp.level ? o.xp.level.lv : 1, n = gameSize(lv), nx = gameNext(lv);
    var coins = (Number(o.xp && o.xp.total) || 0) - gameSpent(L) - (Number(o.petSpent) || 0);
    var p = Number(o.p), i = gameAt(L, p), op = String(o.op || ''), res = { op: op, p: p };
    if (!gameCell(p)) return fail('ไม่พบช่องนี้', 'BAD');
    var short = function (cost) { return fail('เหรียญยังไม่พอ ขาดอีก ' + (cost - Math.max(0, coins)) + ' เหรียญ ไปทำภารกิจเก็บแต้มเพิ่มนะ', 'COINS'); };
    if (op === 'build') {
      var it = gameItem(String(o.item || ''));
      if (!it) return fail('ไม่พบสิ่งก่อสร้างนี้', 'BAD');
      if (!gameIn(p, n)) return fail(nx ? 'ช่องนี้ยังล็อกอยู่ ถึง Lv.' + nx.lv + ' ลานจะขยายเป็น ' + nx.n + '×' + nx.n : 'ช่องนี้ใช้ไม่ได้', 'LOCKED');
      if (i >= 0) return fail('ช่องนี้มีของแล้ว', 'TAKEN');
      if (lv < it.lv) return fail(it.label + ' ปลดล็อกตอน Lv.' + it.lv, 'LOCKED');
      if (coins < it.cost[0]) return short(it.cost[0]);
      L.push([p, it.id, 1]);
      res.item = it.id; res.stars = 1; res.paid = it.cost[0];
    } else if (op === 'up') {
      if (i < 0) return fail('ช่องนี้ยังว่าง', 'EMPTY');
      var u = gameItem(L[i][1]), s = L[i][2];
      if (u.kind !== 'b') return fail('ของตกแต่งอัปดาวไม่ได้', 'BAD');
      if (s >= u.cost.length) return fail(u.label + ' ได้ดาวเต็มแล้ว', 'MAX');
      if (coins < u.cost[s]) return short(u.cost[s]);
      L[i][2] = s + 1;
      res.item = u.id; res.stars = s + 1; res.paid = u.cost[s];
    } else if (op === 'move') {
      var to = Number(o.to);
      if (i < 0) return fail('ช่องนี้ยังว่าง', 'EMPTY');
      if (!gameIn(to, n)) return fail('ย้ายไปช่องนี้ไม่ได้ ช่องยังล็อกอยู่', 'LOCKED');
      var j = gameAt(L, to);
      if (j >= 0 && j !== i) L[j][0] = p;
      L[i][0] = to;
      res.item = L[i][1]; res.to = to; res.swap = j >= 0 && j !== i;
    } else if (op === 'remove') {
      if (i < 0) return fail('ช่องนี้ยังว่าง', 'EMPTY');
      res.item = L[i][1]; res.refund = gameCost(gameItem(L[i][1]), L[i][2]);
      L.splice(i, 1);
    } else return fail('ไม่รู้จักคำสั่งนี้', 'BAD');
    L.sort(function (a, b) { return a[0] - b[0]; });
    return { ok: true, layout: L, result: res };
  }

  /* ศูนย์ฝึกต้นแบบของครู (เก็บใน Script Properties ชื่อ TCENTER): ลาน 5×5 เหรียญไม่จำกัด ปลดล็อกทุกอย่าง
   * ฉาก 1–4 = กลางวัน / ยามเย็น / กลางคืนอวกาศ / ตำนานสีทอง  show = ให้นักเรียนเห็นในหน้าเยี่ยมชม */
  var MODEL_LV = [1, 4, 7, 10];
  function modelCenter(raw) {
    var x = raw;
    if (typeof raw === 'string') { try { x = JSON.parse(raw || '{}'); } catch (e) { x = {}; } }
    x = x && typeof x === 'object' ? x : {};
    var L = gameParse(Array.isArray(x.cells) ? x.cells : []), sc = Math.round(Number(x.scene)) || 1;
    if (sc < 1 || sc > 4) sc = 1;
    return { cells: L, scene: sc, lv: MODEL_LV[sc - 1], show: x.show === true, size: 5, stars: gameStars(L), n: L.length, at: String(x.at || '') };
  }

  /* ถูกใจศูนย์ฝึกเพื่อน: วันละ 3 ครั้ง เพื่อนคนเดิมวันละครั้ง ของตัวเองไม่ได้ (ถูกใจไม่ได้เหรียญ)
   * given = ช่อง กดถูกใจวันนี้ ในชีต {"d": วันที่, "to": [เลขประจำตัว...]} */
  function likesGiven(raw, today) {
    var x = raw;
    if (typeof raw === 'string') { try { x = JSON.parse(raw || '{}'); } catch (e) { x = null; } }
    return x && x.d === today && Array.isArray(x.to) ? x.to.map(String) : [];
  }
  function planLike(o) {
    var g = likesGiven(o.given, o.today);
    if (o.me === o.target) return fail('กดถูกใจศูนย์ฝึกของตัวเองไม่ได้นะ', 'SELF');
    if (g.indexOf(o.target) >= 0) return fail('วันนี้กดถูกใจศูนย์ฝึกนี้แล้ว พรุ่งนี้กดใหม่ได้', 'DONE');
    if (g.length >= CENTER.likesPerDay) return fail('วันนี้กดถูกใจครบ ' + CENTER.likesPerDay + ' ครั้งแล้ว พรุ่งนี้กดใหม่ได้', 'LIMIT');
    g.push(o.target);
    return { ok: true, given: JSON.stringify({ d: o.today, to: g }), left: CENTER.likesPerDay - g.length };
  }

  /* รายชื่อศูนย์ฝึก people = [{ c: เลขประจำตัว, k, n: ชื่อเล่นหรือ เลขที่ n, r: ห้อง, g: ชั้น, s: ดาว, h: ถูกใจ, b: จำนวนของ }]
   * room = ห้องฉัน  school = 50 อันดับดาวสูงสุดทั้งโรงเรียน  rank = อันดับดาวในชั้นที่เลือก 30 อันดับแรก (+ ตัวฉันถ้าอยู่นอก 30) */
  function gameBoard(people, o) {
    var me = o.sid, liked = o.liked || [], list;
    if (o.view === 'rank') list = people.filter(function (p) { return p.g === o.grade && p.s > 0; });
    else if (o.view === 'school') list = people.filter(function (p) { return p.b > 0; });
    else list = people.filter(function (p) { return p.r === o.classId && p.b > 0; });
    list = list.map(function (p) { return { c: p.c, k: p.k, n: p.n, r: p.r, s: p.s, t: p.t || 0, h: p.h, b: p.b }; })
      .sort(function (a, b) { return b.s - a.s || b.h - a.h || b.b - a.b || (a.n < b.n ? -1 : a.n > b.n ? 1 : 0); });
    var rank = 0, prev = null, mine = null;
    list.forEach(function (p, i) { if (p.s !== prev) { rank = i + 1; prev = p.s; } p.i = rank; if (p.c === me) mine = p; });
    var top = list.slice(0, o.view === 'room' ? 60 : o.view === 'school' ? 50 : 30);
    if (mine && top.indexOf(mine) < 0) top.push(mine);
    return top.map(function (p) { return { k: p.k, n: p.n, r: p.r, s: p.s, t: p.t || 0, h: p.h, b: p.b, i: p.i, me: p.c === me, lk: liked.indexOf(p.c) >= 0 }; });
  }


  /* ---------- 6B-23 ศูนย์ฝึกแบบใหม่: ปุ่มอัปเกรดปุ่มเดียว (ระดับศูนย์ฝึก) ----------
   * ฉากเดียวตลอด 5 ชิ้น (ยิม อัฒจันทร์ ลู่วิ่ง สนามบอล สระว่ายน้ำ) ชิ้นละ 5 ขั้น
   * ระดับ 0 = ลานโล่ง · กดอัปเกรด 1 ครั้ง = ขึ้น 1 ระดับ ได้ของเพิ่ม 1 อย่างตามลำดับที่กำหนด:
   *   ทุกชิ้นขึ้นขั้น 1 ก่อน (ลู่วิ่ง → สนามบอล → อัฒจันทร์ → ยิม → สระ) แล้วค่อยขั้น 2 … ถึงขั้น 5
   * ระดับ 25 = ศูนย์ฝึกเต็ม ได้ถ้วย 1 ใบ · ระดับ 26–50 ของประดับธีมทอง · 51–75 เพชร · สายรุ้ง · ทับทิม · มรกต · วนกลับทอง
   * ราคา: ระดับ 1–5 = 20 · 6–10 = 35 · 11–15 = 50 · 16–20 = 70 · 21–25 = 95 (รวม 1,350) รอบถัดไปแพงขึ้นรอบละ 1.5 เท่า ปัดหลัก 5
   * ข้อมูลในชีต (ช่องข้อมูลศูนย์ฝึก) = {"v":3,"lv":ระดับ} · ข้อมูลแบบ {"r","s"} อ่านเป็นระดับรวมได้ · ผังลานเดิม (อาร์เรย์) = ระดับ 0
   * เหรียญ = แต้มรวม − ราคาทุกระดับที่อัปแล้ว − เหรียญที่ใช้กับน้องคู่หู */
  var CENTER = {
    parts: [
      { id: 'gym', icon: '🏋️', label: 'ยิม' },
      { id: 'stand', icon: '🏟️', label: 'อัฒจันทร์' },
      { id: 'track', icon: '🏃', label: 'ลู่วิ่ง' },
      { id: 'field', icon: '⚽', label: 'สนามบอล' },
      { id: 'pool', icon: '🏊', label: 'สระว่ายน้ำ' }
    ],
    order: ['track', 'field', 'stand', 'gym', 'pool'],
    steps: 5,
    cost: [20, 35, 50, 70, 95],
    mul: 1.5,
    maxRound: 99,
    themes: ['ทอง', 'เพชร', 'สายรุ้ง', 'ทับทิม', 'มรกต'],
    /* สิ่งที่ได้ในแต่ละขั้น (รอบแรก) และของประดับแต่ละช่อง (รอบพิเศษ) */
    names: {
      track: ['ลู่วิ่งดิน', 'ลู่ยางสีแดง', 'ลู่ 4 เลน + เส้นออกตัว', 'เส้นชัย + รั้วกระโดด', 'ซุ้มเส้นชัย + ธงรอบลู่'],
      field: ['สนามหญ้า + ลูกบอล', 'ประตูฟุตบอล', 'เส้นสนาม', 'หญ้าลายทาง + ตาข่ายประตู', 'นักฟุตบอลลงสนาม'],
      stand: ['ม้านั่งไม้', 'อัฒจันทร์เหล็ก 3 แถว', 'อัฒจันทร์ 4 แถว + คนดู', 'หลังคา + ธงห้อย', 'ป้ายคะแนน + ไฟสนาม'],
      gym: ['เต็นท์ยิม + ดัมเบล', 'บ้านไม้ยิม', 'อาคารยิม', 'ยิม 2 ชั้น', 'ดัมเบลยักษ์บนหลังคา + ธง'],
      pool: ['สระเป่าลม + เป็ดยาง', 'สระว่ายน้ำเล็ก', 'สระใหญ่ + ทุ่นแบ่งลู่', 'สไลเดอร์', 'แป้นกระโดด + ร่ม + เก้าอี้']
    },
    deco: {
      track: ['เส้นลู่', 'ขอบลู่', 'ซุ้มเส้นชัย', 'ธงรอบลู่', 'ประกายรอบลู่'],
      field: ['เส้นสนาม', 'เสาประตู', 'วงกลางสนาม', 'ธงมุมสนาม', 'ถ้วยกลางสนาม'],
      stand: ['หลังคาอัฒจันทร์', 'ธงห้อย', 'กรอบป้ายคะแนน', 'ธงบนหลังคา', 'มงกุฎบนป้ายคะแนน'],
      gym: ['ขอบหลังคายิม', 'ป้ายชื่อยิม', 'ดัมเบลยักษ์', 'ธงยิม', 'มงกุฎบนยิม'],
      pool: ['ขอบสระ', 'สไลเดอร์', 'ร่มริมสระ', 'แป้นกระโดด', 'น้ำพุในสระ']
    },
    likesPerDay: 3
  };
  var CENTER_N = CENTER.steps * CENTER.parts.length; /* ระดับต่อรอบ = 25 */
  function centerMax() { return CENTER.maxRound * CENTER_N; }
  function centerParse(raw) {
    var x = raw, lv = 0;
    if (typeof raw === 'string') { try { x = JSON.parse(raw || '{}'); } catch (e) { x = null; } }
    if (x && typeof x === 'object' && !Array.isArray(x)) {
      if (x.lv != null) lv = Math.floor(Number(x.lv)) || 0;
      else if (Array.isArray(x.s)) { /* ข้อมูลแบบ 5 ชิ้น (ทดลองก่อนหน้า) → ระดับรวม */
        lv = (Math.floor(Number(x.r)) || 0) * CENTER_N;
        for (var i = 0; i < CENTER.parts.length; i++) lv += Math.max(0, Math.min(CENTER.steps, Math.floor(Number(x.s[i])) || 0));
      }
    }
    var out = { lv: Math.max(0, Math.min(centerMax(), lv)) }, clamp = function (v) { return Math.max(0, Math.min(centerMax(), Math.floor(Number(v)) || 0)); };
    /* จำระดับตอนต้นสัปดาห์ (wk, w0) และสัปดาห์ก่อนหน้า (pk: p0 → p1) ไว้ทำสรุปสัปดาห์ */
    if (x && typeof x === 'object' && /^\d{4}-\d{2}-\d{2}$/.test(String(x.wk || ''))) {
      out.wk = String(x.wk); out.w0 = clamp(x.w0);
      if (/^\d{4}-\d{2}-\d{2}$/.test(String(x.pk || ''))) { out.pk = String(x.pk); out.p0 = clamp(x.p0); out.p1 = clamp(x.p1); }
    }
    return out;
  }
  function centerCost(r, k) { return Math.round(CENTER.cost[k] * Math.pow(CENTER.mul, Math.min(r || 0, 30)) / 5) * 5; }
  function centerRoundCost(r) { var t = 0; for (var k = 0; k < CENTER.steps; k++) t += centerCost(r, k); return t * CENTER.parts.length; }
  /* ระดับ lv → รอบ r, ระดับในรอบ k, ขั้นของแต่ละชิ้น s (เรียงตาม CENTER.parts) */
  function centerAt(lv) {
    var r = Math.floor(lv / CENTER_N), k = lv - r * CENTER_N, n = CENTER.order.length, full = Math.floor(k / n), rest = k - full * n;
    var s = CENTER.parts.map(function (p) { var o = CENTER.order.indexOf(p.id); return full + (o < rest ? 1 : 0); });
    return { r: r, k: k, s: s };
  }
  /* การอัปจาก lv ไป lv + 1: ได้ชิ้นไหน ขั้นไหน ราคาเท่าไร */
  function centerNext(lv) {
    var a = centerAt(lv), n = CENTER.order.length, stage = Math.floor(a.k / n), id = CENTER.order[a.k % n], p = null;
    CENTER.parts.forEach(function (q) { if (q.id === id) p = q; });
    return { level: lv + 1, r: a.r, part: id, icon: p.icon, label: p.label, stage: stage + 1, cost: centerCost(a.r, stage), deco: a.r >= 1,
      name: a.r >= 1 ? CENTER.deco[id][stage] + 'ชุด' + centerTheme(a.r) : CENTER.names[id][stage] };
  }
  function centerSpent(c) {
    var lv = c.lv, r = Math.floor(lv / CENTER_N), k = lv - r * CENTER_N, t = 0, i;
    for (i = 0; i < r; i++) t += centerRoundCost(i);
    for (i = 0; i < k; i++) t += centerCost(r, Math.floor(i / CENTER.order.length));
    return t;
  }
  function centerSteps(c) { return c.lv; }
  function centerData(c) {
    var o = { v: 3, lv: c.lv };
    if (c.wk) { o.wk = c.wk; o.w0 = c.w0 || 0; if (c.pk) { o.pk = c.pk; o.p0 = c.p0 || 0; o.p1 = c.p1 || 0; } }
    return JSON.stringify(o);
  }
  /* หลังอัป 1 ระดับวันนี้: ถ้าเป็นสัปดาห์ใหม่ เลื่อนข้อมูลสัปดาห์เดิมไปเป็น "สัปดาห์ก่อน" */
  function centerTrack(c, today) {
    var t = {};
    ['wk', 'w0', 'pk', 'p0', 'p1'].forEach(function (f) { if (c[f] !== undefined) t[f] = c[f]; });
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(today || ''))) return t;
    var wk = addDays(today, -weekdayIdx(today));
    if (t.wk === wk) return t;
    if (t.wk) return { wk: wk, w0: c.lv, pk: t.wk, p0: t.w0, p1: c.lv };
    return { wk: wk, w0: c.lv };
  }
  /* ศูนย์ฝึกในสัปดาห์ที่แล้ว: ระดับจาก → ถึง (ยังไม่เคยจำ = บอกแค่ระดับตอนนี้) */
  function storyCenter(c, today) {
    if (!c) return null;
    var L = addDays(today, -weekdayIdx(today) - 7);
    if (c.wk === L) return { from: c.w0, to: c.lv, now: c.lv };
    if (c.pk === L) return { from: c.p0, to: c.p1, now: c.lv };
    if (c.wk && c.wk > L) return { from: c.w0, to: c.w0, now: c.lv };
    if (c.wk && c.wk < L) return { from: c.lv, to: c.lv, now: c.lv };
    return { now: c.lv };
  }
  function centerTheme(r) { return r ? CENTER.themes[(r - 1) % CENTER.themes.length] : ''; }
  function centerRoundName(r) { return r ? 'รอบ' + centerTheme(r) + ' ⭐' + r : 'รอบแรก'; }
  /* ข้อมูลสำหรับวาดฉาก (ส่งให้เพื่อนที่มาเยี่ยมชมและการ์ดได้ ไม่มีเหรียญ) */
  function centerBrief(c) { var a = centerAt(c.lv); return { level: c.lv, r: a.r, s: a.s, done: a.k, need: CENTER_N }; }
  /* ศูนย์ฝึกของฉัน ex = { petSpent, pet, today } (น้องคู่หูใช้เหรียญกระเป๋าเดียวกัน) · lv = เลเวลเด็ก level = ระดับศูนย์ฝึก */
  function centerView(c, xp, likes, ex) {
    ex = ex || {};
    var total = Number(xp && xp.total) || 0, plv = xp && xp.level ? xp.level.lv : 1, spent = centerSpent(c), ps = Number(ex.petSpent) || 0, b = centerBrief(c), left = 0;
    for (var i = b.done; i < CENTER_N; i++) left += centerCost(b.r, Math.floor(i / CENTER.order.length));
    return {
      v: 3, coins: Math.max(0, total - spent - ps), total: total, spent: spent, petSpent: ps, lv: plv,
      level: b.level, r: b.r, s: b.s, done: b.done, need: b.need, trophies: b.r, round: centerRoundName(b.r), nextRound: centerRoundName(b.r + 1), theme: centerTheme(b.r),
      next: c.lv < centerMax() ? centerNext(c.lv) : null, left: left, roundCost: centerRoundCost(b.r),
      parts: CENTER.parts.map(function (p, j) { return { id: p.id, icon: p.icon, label: p.label, s: b.s[j], max: CENTER.steps }; }),
      likes: Number(likes) || 0, likesPerDay: CENTER.likesPerDay,
      pet: petView(ex.pet, plv, ex.today, true), petCat: petCatalog()
    };
  }
  /* อัปเกรด 1 ระดับ o = { data, xp, petSpent, op: 'up' } ครบรอบ (ทุก 25 ระดับ) = ได้ถ้วย */
  function planCenter(o) {
    var c = centerParse(o.data), op = String(o.op || '');
    var coins = (Number(o.xp && o.xp.total) || 0) - centerSpent(c) - (Number(o.petSpent) || 0);
    if (op !== 'up') return fail('ไม่รู้จักคำสั่งนี้', 'BAD');
    if (c.lv >= centerMax()) return fail('ศูนย์ฝึกระดับสูงสุดแล้ว เก่งมาก!', 'MAX');
    var nx = centerNext(c.lv);
    if (coins < nx.cost) return fail('เหรียญยังไม่พอ ขาดอีก ' + (nx.cost - Math.max(0, coins)) + ' เหรียญ ไปทำภารกิจเก็บแต้มเพิ่มนะ', 'COINS');
    var lv = c.lv + 1, res = { level: lv, part: nx.part, stage: nx.stage, name: nx.name, deco: nx.deco, paid: nx.cost, r: nx.r };
    if (lv % CENTER_N === 0) { res.round = lv / CENTER_N; res.roundName = centerRoundName(nx.r); res.nextRound = centerRoundName(nx.r + 1); res.nextTheme = centerTheme(nx.r + 1); }
    var cen = centerTrack(c, o.today);
    cen.lv = lv;
    return { ok: true, center: cen, result: res };
  }
  /* ฉากของครู (Script Properties ชื่อ TCENTER) ครูกด + / − ระดับได้ตามสะดวก ไม่ใช้เหรียญ
   * show = ให้นักเรียนเห็นในหน้าเยี่ยมชม (ข้อมูลแบบลานเดิมที่เป็นผังลาน อ่านเป็นระดับ 0) */
  function centerModel(raw) {
    var x = raw;
    if (typeof raw === 'string') { try { x = JSON.parse(raw || '{}'); } catch (e) { x = {}; } }
    x = x && typeof x === 'object' && !Array.isArray(x) ? x : {};
    var b = centerBrief(centerParse(x));
    b.show = x.show === true; b.at = String(x.at || '');
    return b;
  }

  /* ---------- 6B-24 เป้าหมายรวมทั้งโรงเรียน ----------
   * รวมระดับศูนย์ฝึกของนักเรียนทุกคน ครบเป้าขั้นไหน ทุกคนได้งานพลุในศูนย์ฝึก 3 วัน (นับวันที่ครบเป็นวันแรก)
   * เป้าเพิ่มทีละขั้นตาม goals แล้วต่อด้วย step · ขั้นที่ครบแล้วไม่ถอยกลับ (stored = { tier, at } ใน Script Properties) */
  var SCHOOL = { goals: [300, 600, 1000, 1500, 2000, 3000, 4000, 5000, 7500, 10000, 15000, 20000, 25000, 30000, 40000, 50000], step: 10000, partyDays: 3 };
  function schoolGoalAt(i) { var G = SCHOOL.goals; return i < G.length ? G[i] : G[G.length - 1] + (i - G.length + 1) * SCHOOL.step; }
  /* ===== 6B-26: ทั้งโรงเรียนเดินทางด้วยก้าว =====
   * นาทีที่นับได้ทั้งโรงเรียน (ตามเพดานนาทีต่อวันของแต่ละคน ไม่นับรายการที่ครูใส่ ไม่นับ) แยกนาทีของวันนี้ไว้
   * byCode = { รหัสนักเรียน: [บันทึก] } → { d: วันนี้, m: นาทีรวมถึงวันนี้, t: นาทีของวันนี้ } */
  function tripCount(byCode, s, today) {
    var m = 0, t = 0;
    Object.keys(byCode || {}).forEach(function (code) {
      var T = dayTotals(byCode[code] || [], s);
      Object.keys(T).forEach(function (d) {
        if (d > today) return;
        m += T[d].counted;
        if (d === today) t += T[d].counted;
      });
    });
    return { d: today, m: m, t: t };
  }
  /* นาทีรวมตอนนี้: base = ที่นับไว้ล่าสุด (ทุกชั่วโมง) · live = นาทีของวันนี้แบบสด (จอใหญ่) ไม่ส่ง = ใช้ base */
  function tripMinutes(base, today, live) {
    var hasLive = typeof live === 'number' && isFinite(live) && live >= 0;
    if (!base || typeof base.m !== 'number') return hasLive ? live : 0;
    if (!hasLive) return Math.max(0, base.m);
    if (base.d === today) return Math.max(0, base.m - (Number(base.t) || 0) + live);
    if (base.d < today) return Math.max(0, base.m) + live;
    return Math.max(0, base.m);
  }

  function schoolGoal(sum, stored, today) {
    sum = Math.max(0, Math.floor(Number(sum)) || 0);
    stored = stored && typeof stored === 'object' ? stored : {};
    var tier = 0;
    while (tier < 500 && sum >= schoolGoalAt(tier)) tier++;
    var had = Math.max(0, Math.min(500, Math.floor(Number(stored.tier)) || 0)), at = /^\d{4}-\d{2}-\d{2}$/.test(String(stored.at || '')) ? String(stored.at) : '', save = null;
    if (tier > had) { had = tier; at = String(today || ''); save = { tier: had, at: at }; }
    var until = had && at ? addDays(at, SCHOOL.partyDays - 1) : '';
    return {
      sum: sum, tier: had, goal: schoolGoalAt(had), prev: had ? schoolGoalAt(had - 1) : 0, partyGoal: had ? schoolGoalAt(had - 1) : 0,
      at: at, until: until, party: !!(until && today && at <= today && today <= until), save: save
    };
  }

  /* ---------- สัตว์เลี้ยงคู่หู ----------
   * ไข่ใบแรกฟรี สุ่มได้ 1 ใน 21 ตัว · ไม่ชอบซื้อไข่ใบใหม่ (สุ่มใหม่ ไม่ซ้ำตัวเดิม) ซื้อได้วันละ 1 ใบ
   * ความหายาก: ธรรมดา 8 ตัว รวม 65% · ✨ หายาก 5 ตัว รวม 24% · 🌈 หายากมาก 2 ตัว รวม 8% · 👑 สัตว์ในตำนาน 6 ตัว รวม 3%
   * (บอกโอกาสให้เด็กเห็นบนหน้าฟักไข่)
   * น้องโตตามเลเวลเด็ก (ลูก Lv.1–3 วัยรุ่น 4–6 ตัวเต็มวัย 7–9 ร่างตำนาน 10) เปลี่ยนตัวแล้วร่างไม่หาย
   * ขนมสุขภาพ ชิ้นละ 5 เหรียญ วันละไม่เกิน 3 ชิ้น · ของแต่งตัวซื้อครั้งเดียว ใส่ได้ตลอด ใช้กับน้องทุกตัว
   * ใช้เหรียญกระเป๋าเดียวกับศูนย์ฝึก เหรียญที่ใช้กับน้องไม่คืน */
  var PETS = {
    species: [
      { id: 'dog', label: 'ลูกหมานักวิ่ง', tier: 1 }, { id: 'cat', label: 'แมวโยคะ', tier: 1 }, { id: 'turtle', label: 'เต่านักว่าย', tier: 1 },
      { id: 'rabbit', label: 'กระต่ายกระโดดเชือก', tier: 1 }, { id: 'frog', label: 'กบน้อยกระโดดไกล', tier: 1 }, { id: 'chick', label: 'ไก่น้อยเปตอง', tier: 1 },
      { id: 'penguin', label: 'เพนกวินนักปิงปอง', tier: 1 }, { id: 'bear', label: 'หมีน้อยเทควันโด', tier: 1 },
      { id: 'hamster', label: 'หนูแฮมสเตอร์วิ่งวงล้อ', tier: 1 }, { id: 'squirrel', label: 'กระรอกโยนรับบอล', tier: 1 },
      { id: 'parrot', label: 'นกแก้วกระโดดตบ', tier: 1 }, { id: 'mouse', label: 'หนูน้อยเดินกะลา', tier: 1 },
      { id: 'cow', label: 'วัวน้อยแอโรบิก', tier: 1 }, { id: 'goat', label: 'แพะน้อยเดินทรงตัว', tier: 1 },
      { id: 'sheep', label: 'แกะน้อยฮูลาฮูป', tier: 1 }, { id: 'horse', label: 'ม้าน้อยกระโดดยาง', tier: 1 },
      { id: 'ant', label: 'มดน้อยวิ่งผลัด', tier: 1 }, { id: 'ladybug', label: 'เต่าทองโยนห่วง', tier: 1 },
      { id: 'crab', label: 'ปูน้อยเดินปู', tier: 1 }, { id: 'gecko', label: 'จิ้งจกน้อยวิดพื้น', tier: 1 },
      { id: 'seal', label: 'แมวน้ำเลี้ยงลูกบอล', tier: 1 }, { id: 'sparrow', label: 'นกกระจอกเล่นว่าว', tier: 1 },
      { id: 'alpaca', label: 'อัลปาก้าโบว์ลิ่ง', tier: 1 }, { id: 'armadillo', label: 'ตัวนิ่มม้วนหน้า', tier: 1 },
      { id: 'elephant', label: 'ช้างน้อยยกน้ำหนัก', tier: 2 }, { id: 'panda', label: 'แพนด้านักแบด', tier: 2 }, { id: 'monkey', label: 'ลิงน้อยตะกร้อ', tier: 2 },
      { id: 'fox', label: 'จิ้งจอกนักฟุตบอล', tier: 2 }, { id: 'giraffe', label: 'ยีราฟนักวอลเลย์', tier: 2 },
      { id: 'buffalo', label: 'ควายน้อยชักเย่อ', tier: 2 }, { id: 'hedgehog', label: 'เม่นนักยิมนาสติก', tier: 2 },
      { id: 'koala', label: 'โคอาล่าปีนผา', tier: 2 }, { id: 'kangaroo', label: 'จิงโจ้วิ่งข้ามรั้ว', tier: 2 },
      { id: 'otter', label: 'นากน้อยโต้คลื่น', tier: 2 }, { id: 'pig', label: 'หมูน้อยแชร์บอล', tier: 2 },
      { id: 'zebra', label: 'ม้าลายปั่นจักรยาน', tier: 2 }, { id: 'raccoon', label: 'แรคคูนสเก็ตบอร์ด', tier: 2 },
      { id: 'hippo', label: 'ฮิปโปกระโดดน้ำ', tier: 2 }, { id: 'owl', label: 'นกฮูกตีกอล์ฟ', tier: 2 },
      { id: 'deer', label: 'กวางน้อยเทนนิส', tier: 2 }, { id: 'duck', label: 'เป็ดน้อยพายเรือคายัค', tier: 2 },
      { id: 'lion', label: 'สิงโตนักบาส', tier: 3 }, { id: 'tiger', label: 'เสือน้อยมวยไทย', tier: 3 },
      { id: 'gaur', label: 'กระทิงรักบี้', tier: 3 }, { id: 'peacock', label: 'นกยูงยิมนาสติกลีลา', tier: 3 },
      { id: 'panther', label: 'เสือดำวิ่ง 100 เมตร', tier: 3 }, { id: 'polarbear', label: 'หมีขาวฮอกกี้น้ำแข็ง', tier: 3 },
      { id: 'whitetiger', label: 'เสือขาวกระบี่กระบอง', tier: 3 }, { id: 'shark', label: 'ฉลามว่ายผีเสื้อ', tier: 3 },
      { id: 'flamingo', label: 'ฟลามิงโกสเก็ตลีลา', tier: 3 }, { id: 'orangutan', label: 'อุรังอุตังโหนบาร์', tier: 3 },
      { id: 'rhino', label: 'แรดยูโด', tier: 3 }, { id: 'wolf', label: 'หมาป่าสกี', tier: 3 },
      { id: 'eagle', label: 'นกอินทรีร่มร่อน', tier: 3 }, { id: 'snowleopard', label: 'เสือดาวหิมะสโนว์บอร์ด', tier: 3 },
      { id: 'dragon', label: 'มังกรพายเรือมังกร', tier: 4 }, { id: 'phoenix', label: 'ฟีนิกซ์ถือคบเพลิง', tier: 4 }, { id: 'unicorn', label: 'ยูนิคอร์นเชียร์ลีดเดอร์', tier: 4 },
      { id: 'qilin', label: 'กิเลนไทเก๊ก', tier: 4 }, { id: 'griffin', label: 'กริฟฟินยิงธนู', tier: 4 }, { id: 'pegasus', label: 'เพกาซัสกระโดดสูง', tier: 4 }
    ],
    tiers: { 1: { label: 'ธรรมดา', total: 65 }, 2: { label: 'หายาก', total: 24 }, 3: { label: 'หายากมาก', total: 8 }, 4: { label: 'สัตว์ในตำนาน', total: 3 } },
    rerollCost: 100, rerollPerDay: 3, snackCost: 5, snacksPerDay: 3, nameMax: 12,
    snacks: [
      { id: 'apple', icon: '🍎', label: 'แอปเปิล' }, { id: 'banana', icon: '🍌', label: 'กล้วย' }, { id: 'carrot', icon: '🥕', label: 'แครอท' },
      { id: 'broccoli', icon: '🥦', label: 'บรอกโคลี' }, { id: 'watermelon', icon: '🍉', label: 'แตงโม' }, { id: 'milk', icon: '🥛', label: 'นมจืด' }
    ],
    wear: [
      { id: 'cap', slot: 'hat', label: 'หมวกแก๊ป', cost: 40 }, { id: 'beanie', slot: 'hat', label: 'หมวกไหมพรม', cost: 40 },
      { id: 'party', slot: 'hat', label: 'หมวกปาร์ตี้', cost: 30 }, { id: 'flower', slot: 'hat', label: 'มงกุฎดอกไม้', cost: 60 },
      { id: 'sun', slot: 'face', label: 'แว่นกันแดด', cost: 50 }, { id: 'round', slot: 'face', label: 'แว่นกลม', cost: 40 }, { id: 'star', slot: 'face', label: 'แว่นดาว', cost: 60 },
      { id: 'scarf', slot: 'neck', label: 'ผ้าพันคอ', cost: 40 }, { id: 'bow', slot: 'neck', label: 'หูกระต่าย', cost: 30 }, { id: 'whistle', slot: 'neck', label: 'นกหวีดครูพละ', cost: 50 }
    ],
    names: ['โทโต้', 'ปุยฝ้าย', 'ข้าวปั้น', 'มะลิ', 'ส้มโอ', 'บัวลอย', 'โมจิ', 'ถั่วแดง', 'ขนมปัง', 'น้ำตาล', 'ทองคำ', 'ฟ้าใส', 'ลูกชิ้น', 'เต้าหู้', 'มะปราง',
      'ชมพู่', 'ลำไย', 'สายไหม', 'คุกกี้', 'บิสกิต', 'เจ้าจุก', 'ป๊อปคอร์น', 'มะม่วง', 'ฟักทอง', 'ก้อนเมฆ', 'ดาวเหนือ', 'สายฟ้า', 'จัมโบ้', 'พุดดิ้ง', 'วุ้นเส้น']
  };
  function petSpecies(v) {
    var t = String(v || '').trim();
    for (var i = 0; i < PETS.species.length; i++) if (PETS.species[i].id === t || PETS.species[i].label === t) return PETS.species[i];
    return null;
  }
  function petWear(id) { for (var i = 0; i < PETS.wear.length; i++) if (PETS.wear[i].id === id) return PETS.wear[i]; return null; }
  function petSnack(id) { for (var i = 0; i < PETS.snacks.length; i++) if (PETS.snacks[i].id === id) return PETS.snacks[i]; return null; }
  /* ข้อมูลน้องจากชีต (ชนิด ชื่อ และข้อมูลเพิ่ม JSON) → null ถ้ายังไม่ฟักไข่ */
  function petParse(sp, name, raw) {
    var s = petSpecies(sp);
    if (!s) return null;
    var x = {};
    if (raw && typeof raw === 'object') x = raw;
    else { try { x = JSON.parse(raw || '{}') || {}; } catch (e) { x = {}; } }
    var own = (Array.isArray(x.own) ? x.own : []).filter(function (id, i, a) { return petWear(id) && a.indexOf(id) === i; }), wear = {};
    ['hat', 'face', 'neck'].forEach(function (slot) { var w = x.wear && petWear(x.wear[slot]); if (w && w.slot === slot && own.indexOf(w.id) >= 0) wear[slot] = w.id; });
    return {
      sp: s.id, name: String(name || '').trim().slice(0, 30), own: own, wear: wear,
      fed: x.fed && x.fed.d ? { d: String(x.fed.d), n: Math.max(0, Math.round(Number(x.fed.n) || 0)), last: petSnack(x.fed.last) ? x.fed.last : '' } : { d: '', n: 0, last: '' },
      rolls: Math.max(0, Math.round(Number(x.rolls) || 0)), rollDay: String(x.rollDay || ''), rollN: x.rollN != null ? Math.max(0, Math.round(Number(x.rollN) || 0)) : (x.rollDay ? 1 : 0),
      egg: x.egg ? 1 : 0, at: String(x.at || ''), nameOk: String(x.nameOk || '')
    };
  }
  function petData(p) { return JSON.stringify({ own: p.own, wear: p.wear, fed: p.fed, rolls: p.rolls, rollDay: p.rollDay || '', rollN: p.rollN || 0, egg: p.egg ? 1 : 0, at: p.at, nameOk: p.nameOk || '' }); }
  /* โอกาสของแต่ละตัว (%) = โอกาสรวมของระดับ ÷ จำนวนตัวในระดับ */
  function petChance(sp) {
    var n = PETS.species.filter(function (x) { return x.tier === sp.tier; }).length;
    return PETS.tiers[sp.tier].total / n;
  }
  /* สุ่มแบบถ่วงตามความหายาก (ไม่เอาตัว not) r = 0–1 */
  function petPick(r, not) {
    var list = PETS.species.filter(function (x) { return x.id !== not; }), sum = 0, acc = 0;
    list.forEach(function (x) { sum += petChance(x); });
    for (var i = 0; i < list.length; i++) { acc += petChance(list[i]) / sum; if (r < acc) return list[i]; }
    return list[list.length - 1];
  }
  function petStage(lv) { lv = lv || 1; return lv >= 10 ? 4 : lv >= 7 ? 3 : lv >= 4 ? 2 : 1; }
  /* ชื่อน้อง: เลือกจากรายชื่อ หรือพิมพ์เอง (ตัวกรองคำแบบเดียวกับชื่อเล่น) */
  function checkPetName(v) {
    var t = String(v === undefined || v === null ? '' : v).replace(/\s+/g, ' ').trim();
    if (!t) return fail('ตั้งชื่อน้องก่อนนะ', 'INPUT');
    if (PETS.names.indexOf(t) >= 0) return { ok: true, value: t };
    if (!/^[ก-๎ a-zA-Z]+$/.test(t) || /[๐-๙]/.test(t)) return fail('ชื่อน้องใช้ได้แค่ตัวอักษรไทยหรืออังกฤษ ไม่มีตัวเลขหรือสัญลักษณ์', 'NAME_CHARS');
    var n = nickLen(t);
    if (n < 2 || n > PETS.nameMax) return fail('ชื่อน้องยาว 2–' + PETS.nameMax + ' ตัวอักษร', 'NAME_LEN');
    var flat = t.toLowerCase().replace(/\s/g, '').replace(/(.)\1+/g, '$1');
    for (var i = 0; i < BAD_WORDS.length; i++) {
      if (flat.indexOf(BAD_WORDS[i]) >= 0 || t.toLowerCase().replace(/\s/g, '').indexOf(BAD_WORDS[i]) >= 0) return fail('ชื่อนี้ใช้ไม่ได้ ลองชื่ออื่นนะ', 'NAME_BAD');
    }
    return { ok: true, value: t };
  }
  /* สิ่งที่หน้าเว็บใช้วาดน้อง (ของเพื่อน = ไม่ส่งของที่มี/ขนม) */
  function petView(p, lv, today, full) {
    if (!p) return null;
    var s = petSpecies(p.sp), v = { sp: p.sp, label: s.label, tier: s.tier, name: p.name || s.label, named: !!p.name, stage: petStage(lv), wear: p.wear };
    if (full) {
      v.own = p.own; v.fedToday = p.fed.d === today ? p.fed.n : 0; v.lastSnack = p.fed.d === today ? p.fed.last : ''; v.rolls = p.rolls; v.egg = !!p.egg;
      v.rollsLeft = Math.max(0, PETS.rerollPerDay - (p.rollDay === today ? (p.rollN || 0) : 0)); v.rolledToday = v.rollsLeft <= 0;
    }
    return v;
  }
  function petCatalog() { return { species: PETS.species.map(function (x) { return { id: x.id, label: x.label, tier: x.tier, chance: Math.round(petChance(x) * 100) / 100 }; }), tiers: PETS.tiers, snacks: PETS.snacks, wear: PETS.wear, names: PETS.names, rerollCost: PETS.rerollCost, rerollPerDay: PETS.rerollPerDay, snackCost: PETS.snackCost, snacksPerDay: PETS.snacksPerDay, nameMax: PETS.nameMax }; }

  /* ฟักไข่ ซื้อไข่ใบใหม่ ตั้งชื่อ ให้ขนม ซื้อของ ใส่/ถอดของ
   * o = { pet, xp, spent: เหรียญที่ใช้สร้าง, petSpent, op, item, slot, name, today, rand: ค่าสุ่ม 0–1 } */
  function planPet(o) {
    var p = o.pet ? JSON.parse(JSON.stringify(o.pet)) : null, op = String(o.op || ''), paid = 0, res = { op: op };
    var coins = (Number(o.xp && o.xp.total) || 0) - (Number(o.spent) || 0) - (Number(o.petSpent) || 0);
    var r = typeof o.rand === 'number' ? Math.min(0.999999, Math.max(0, o.rand)) : Math.random();
    var short = function (cost) { return fail('เหรียญยังไม่พอ ขาดอีก ' + (cost - Math.max(0, coins)) + ' เหรียญ ไปทำภารกิจเก็บแต้มเพิ่มนะ', 'COINS'); };
    if (op === 'hatch') {
      if (p && !p.egg) return fail('มีน้องอยู่แล้ว', 'HAS_PET');
      if (p) { /* ฟักไข่ใบใหม่ที่ซื้อไว้: ได้ตัวใหม่ (ไม่ซ้ำตัวเดิม) ชื่อและของยังอยู่ */
        res.from = p.sp;
        var nx = petPick(r, p.sp);
        p.sp = nx.id; p.egg = 0; res.sp = p.sp; res.tier = nx.tier; res.again = true;
      } else {
        var sp = petPick(r, '');
        p = { sp: sp.id, name: '', own: [], wear: {}, fed: { d: '', n: 0, last: '' }, rolls: 0, rollDay: '', rollN: 0, egg: 0, at: o.today };
        res.sp = sp.id; res.tier = sp.tier;
      }
    } else {
      if (!p) return fail('ยังไม่ได้ฟักไข่น้อง', 'NO_PET');
      if (p.egg && op !== 'name') return fail('ฟักไข่ใบใหม่ก่อนนะ แตะไข่ 3 ครั้ง', 'EGG_WAIT');
      if (op === 'reroll') {
        var used = p.rollDay === o.today ? (p.rollN || 0) : 0;
        if (used >= PETS.rerollPerDay) return fail('วันนี้ซื้อไข่ใบใหม่ครบ ' + PETS.rerollPerDay + ' ใบแล้ว พรุ่งนี้ซื้อได้อีกนะ', 'ROLL_DAY');
        if (coins < PETS.rerollCost) return short(PETS.rerollCost);
        p.egg = 1; p.rollDay = o.today; p.rollN = used + 1;
        p.rolls += 1; paid = PETS.rerollCost; res.egg = true; res.left = PETS.rerollPerDay - used - 1;
      } else if (op === 'name') {
        var nm = checkPetName(o.name);
        if (!nm.ok) return nm;
        p.name = nm.value; res.name = nm.value;
      } else if (op === 'feed') {
        var sn = petSnack(String(o.item || ''));
        if (!sn) return fail('ไม่พบขนมนี้', 'BAD');
        var n = p.fed.d === o.today ? p.fed.n : 0;
        if (n >= PETS.snacksPerDay) return fail('วันนี้น้องอิ่มแล้ว กินวันละ ' + PETS.snacksPerDay + ' ชิ้นพอดี ๆ พรุ่งนี้ค่อยให้ใหม่นะ', 'LIMIT');
        if (coins < PETS.snackCost) return short(PETS.snackCost);
        p.fed = { d: o.today, n: n + 1, last: sn.id };
        paid = PETS.snackCost; res.item = sn.id; res.left = PETS.snacksPerDay - n - 1;
      } else if (op === 'buy') {
        var w = petWear(String(o.item || ''));
        if (!w) return fail('ไม่พบของชิ้นนี้', 'BAD');
        if (p.own.indexOf(w.id) >= 0) return fail('มี' + w.label + 'แล้ว', 'OWNED');
        if (coins < w.cost) return short(w.cost);
        p.own.push(w.id); p.wear[w.slot] = w.id;
        paid = w.cost; res.item = w.id;
      } else if (op === 'wear') {
        var slot = String(o.slot || ''), id = String(o.item || '');
        if (['hat', 'face', 'neck'].indexOf(slot) < 0) return fail('ไม่พบช่องนี้', 'BAD');
        if (!id) { delete p.wear[slot]; res.slot = slot; }
        else {
          var x = petWear(id);
          if (!x || x.slot !== slot) return fail('ไม่พบของชิ้นนี้', 'BAD');
          if (p.own.indexOf(id) < 0) return fail('ยังไม่มี' + x.label + ' ซื้อก่อนนะ', 'NOT_OWNED');
          p.wear[slot] = id; res.item = id;
        }
      } else return fail('ไม่รู้จักคำสั่งนี้', 'BAD');
    }
    res.paid = paid;
    return { ok: true, pet: p, paid: paid, result: res };
  }

  /* แต้มรวมของนักเรียน 1 คน (ใช้คิดเหรียญ) */
  function xpOf(o) {
    var mine = mineOf(o.logs, o.klass, o.student);
    return xpStatus(mine, missionsOf(o.done, o.student), o.klass, o.settings, o.todayKey, { extra: extrasOf(o.extra, o.student), events: o.events });
  }

  return {
    mineOf: mineOf, buildStatus: buildStatus, calendarView: calendarView, storyView: storyView, boardStats: boardStats, centerTrack: centerTrack, storyCenter: storyCenter, planSubmit: planSubmit, planMission: planMission, planQuest: planQuest, planClip: planClip, clipDone: clipDone,
    questOf: questOf,
    LEVELS: LEVELS, ARCS: ARCS, MISSION_TYPES: MISSION_TYPES, DEFAULT_MISSIONS: DEFAULT_MISSIONS,
    BADGE_ICONS: BADGE_ICONS, DIFF_STARS: DIFF_STARS, unlockedDiff: unlockedDiff, numList: numList, badgeList: badgeList,
    levelInfo: levelInfo, levelList: levelList, xpLedger: xpLedger, xpStatus: xpStatus, missionPoints: missionPoints,
    missionFor: missionFor, missionsOf: missionsOf,
    weekGoals: weekGoals, STICKERS: STICKERS, tagOf: tagOf, stickerFacts: stickerFacts, stickersOf: stickersOf,
    makeBoard: makeBoard, boardView: boardView, fromDayNum: fromDayNum,
    PROFILE: PROFILE, checkNick: checkNick, planProfile: planProfile, profileView: profileView, cardView: cardView, pinsView: pinsView,
    EVENT_KINDS: EVENT_KINDS, eventKind: eventKind, eventProgress: eventProgress, eventsView: eventsView, extrasOf: extrasOf,
    quizFor: quizFor, quizView: quizView, planQuiz: planQuiz, planEvent: planEvent, timerOf: timerOf, eventGained: eventGained,
    findDeletable: findDeletable, canDelete: canDelete,
    GAME: GAME, gameItem: gameItem, gameSize: gameSize, gameParse: gameParse, gameSpent: gameSpent, gameStars: gameStars, gameExtent: gameExtent,
    DUST: DUST, DUST_TASKS: DUST_TASKS, dustLevel: dustLevel, dustPick: dustPick, dustMerge: dustMerge, dustView: dustView, dustTaskFor: dustTaskFor, dustBlock: dustBlock, planDust: planDust,
    PETS: PETS, petPick: petPick, petChance: petChance, petParse: petParse, petData: petData, petView: petView, petStage: petStage, planPet: planPet, checkPetName: checkPetName, petCatalog: petCatalog,
    gameView: gameView, planGame: planGame, modelCenter: modelCenter, planLike: planLike, likesGiven: likesGiven, gameBoard: gameBoard, xpOf: xpOf,
    CENTER: CENTER, centerParse: centerParse, centerCost: centerCost, centerRoundCost: centerRoundCost, centerSpent: centerSpent, centerSteps: centerSteps, centerAt: centerAt, centerNext: centerNext,
    centerData: centerData, centerBrief: centerBrief, centerView: centerView, planCenter: planCenter, centerModel: centerModel, centerRoundName: centerRoundName, centerTheme: centerTheme,
    SCHOOL: SCHOOL, schoolGoal: schoolGoal, schoolGoalAt: schoolGoalAt, tripCount: tripCount, tripMinutes: tripMinutes,
    ACTIVITIES: ACTIVITIES, FEELINGS: FEELINGS, DEFAULTS: DEFAULTS, MINUTE_CHOICES: MINUTE_CHOICES,
    toKey: toKey, addDays: addDays, dayNum: dayNum, weekdayIdx: weekdayIdx, weekOf: weekOf,
    thaiDate: thaiDate, dayLetter: dayLetter, dayName: dayName, allowedDates: allowedDates,
    findActivity: findActivity, findFeeling: findFeeling, yes: yes, normSettings: normSettings,
    isCounted: isCounted, dayTotals: dayTotals, summarize: summarize,
    validateEntry: validateEntry, dayUsage: dayUsage, fail: fail
  };
})();

/* ===== สมุดสุขภาพ: ฝั่ง Apps Script (ข้อมูลอยู่ใน Google Sheet ที่ผูกกับโค้ดนี้) ===== */

var TZ = 'Asia/Bangkok';
var TAB = {
  settings: 'ตั้งค่า', roster: 'นักเรียน', quests: 'เควสบ้าน',
  logs: 'บันทึก', summary: 'สรุปดาว', missions: 'ภารกิจประจำวัน', done: 'ภารกิจที่ทำ', spot: 'สุ่มตรวจ',
  cache: 'แคชระบบ', questions: 'คำถามสุขภาพ', events: 'อีเวนต์', extra: 'กิจกรรมเสริม', fitness: 'สมรรถภาพ', game: 'ศูนย์ฝึก'
};
/* หัวคอลัมน์แท็บนักเรียน (นักเรียนสมัครเองจากหน้าเว็บ แบบโปรแกรมกระโดดเชือก) */
var SC = {
  sid: 'เลขประจำตัว', name: 'ชื่อ-สกุล', grade: 'ชั้น', room: 'ห้อง', no: 'เลขที่',
  pin: 'PIN (เข้ารหัสไว้ ลบช่องนี้เพื่อรีเซ็ต)', created: 'สมัครเมื่อ', last: 'เข้าใช้ล่าสุด',
  fails: 'ใส่ PIN ผิด (ครั้ง)', lockUntil: 'ล็อกถึง', active: 'ใช้งาน', nick: 'ชื่อเล่น',
  nickAt: 'ตั้งชื่อเล่นเมื่อ', nickLock: 'ล็อกชื่อเล่น', outfit: 'อวตาร (ชุด)', color: 'สีพื้น', sports: 'กีฬาที่ชอบ',
  goal: 'เป้าหมาย', motto: 'คำประจำตัว', pins: 'สติกเกอร์โชว์', photo: 'รูปจริง', photoOk: 'รูปจริง (ครูอนุมัติ)'
};
var H = {
  roster: [SC.sid, SC.name, SC.grade, SC.room, SC.no, SC.pin, SC.created, SC.last, SC.fails, SC.lockUntil, SC.active],
  /* ช่องโปรไฟล์ (ไม่มีก็ยังเข้าสู่ระบบได้ ครูกดเมนู 1 เพื่อเติมช่อง) */
  rosterOpt: [SC.nick, SC.nickAt, SC.nickLock, SC.outfit, SC.color, SC.sports, SC.goal, SC.motto, SC.pins, SC.photo, SC.photoOk],
  quests: ['สัปดาห์', 'เควสบ้าน ป.1–3', 'เควสบ้าน ป.4–6'],
  missions: ['ประเภท', 'ขั้น 1', 'ขั้น 2', 'ขั้น 3', 'ขั้น 4', 'ใช้งาน'],
  done: ['รหัส', 'เวลาที่ส่ง', 'วันที่ทำ', 'ห้อง', SC.sid, 'ประเภท', 'ภารกิจ', 'ความยาก', 'หลักฐาน', 'ไฟล์', 'ท่าลับ', 'ครูตรวจ', 'หมายเหตุ'],
  logs: ['รหัสบันทึก', 'เวลาที่ส่ง', 'วันที่ทำ', 'ห้อง', SC.sid, 'สัปดาห์', 'กิจกรรม', 'นาที', 'ความรู้สึก',
    'ช่องทาง', 'ครูตรวจ', 'หมายเหตุ'],
  /* แท็บซ่อน ระบบสร้างเองทุกชั่วโมง แถว 2 = อันดับ แถว 3 ขึ้นไป = ข้อมูลเก่าของนักเรียนทีละคน */
  cache: [SC.sid, 'บันทึก', 'ภารกิจ', 'ตัดที่วันที่', 'อันดับ', 'อัปเดต', 'กิจกรรมเสริม', 'กำลังใจ'],
  questions: ['ช่วงชั้น', 'คำถาม', 'ตัวเลือก ก', 'ตัวเลือก ข', 'ตัวเลือก ค', 'ตัวเลือก ง', 'เฉลย', 'อธิบาย', 'ใช้งาน'],
  events: ['รหัส', 'ชื่ออีเวนต์', 'เริ่ม', 'จบ', 'คำชวน', 'ภารกิจ 1', 'นับจาก 1', 'เป้า 1', 'ภารกิจ 2', 'นับจาก 2', 'เป้า 2',
    'ภารกิจ 3', 'นับจาก 3', 'เป้า 3', 'สติกเกอร์', 'ใช้งาน'],
  /* คำตอบคำถามสุขภาพ ภารกิจอีเวนต์ที่เด็กกดทำเอง กำลังใจ และคลิปที่ดูครบ */
  extra: ['รหัส', 'เวลาที่ส่ง', 'วันที่ทำ', 'ห้อง', SC.sid, 'ประเภท', 'เรื่อง', 'คำตอบ', 'ผล', 'ครูตรวจ', 'หมายเหตุ'],
  game: [SC.sid, 'ห้อง', 'ข้อมูลศูนย์ฝึก', 'เหรียญที่ใช้สร้าง', 'ระดับศูนย์ฝึก', 'ถูกใจที่ได้', 'กดถูกใจวันนี้', 'เลเวล', 'น้องคู่หู', 'ชื่อน้อง', 'ข้อมูลน้อง', 'เหรียญที่ใช้กับน้อง', 'อัปเดตล่าสุด'],
  fitness: [SC.sid, 'ห้อง', 'เลขที่', 'ภาคเรียน', 'นั่งงอตัว (ซม.)', 'ดันพื้น 30 วิ (ครั้ง)', 'ลุกนั่ง 60 วิ (ครั้ง)', 'ยืนยกเข่า 3 นาที (ครั้ง)', 'บันทึกเมื่อ']
};
/* ผลทดสอบสมรรถภาพ 4 รายการ (ไม่เก็บน้ำหนัก-ส่วนสูง) ค่ามากกว่า = ดีขึ้น */
var FITNESS_TESTS = [
  { key: 'reach', head: 'นั่งงอตัว (ซม.)', label: 'นั่งงอตัวไปข้างหน้า', unit: 'ซม.', min: -30, max: 50 },
  { key: 'push', head: 'ดันพื้น 30 วิ (ครั้ง)', label: 'ดันพื้นประยุกต์ 30 วินาที', unit: 'ครั้ง', min: 0, max: 100 },
  { key: 'sit', head: 'ลุกนั่ง 60 วิ (ครั้ง)', label: 'ลุกนั่ง 60 วินาที', unit: 'ครั้ง', min: 0, max: 100 },
  { key: 'step', head: 'ยืนยกเข่า 3 นาที (ครั้ง)', label: 'ยืนยกเข่าขึ้นลง 3 นาที', unit: 'ครั้ง', min: 0, max: 400 }
];
var CLIP_HEAD = 'คลิปสาธิต', QUEST_CLIP_HEAD = 'คลิป', OUTDOOR_HEAD = 'กลางแจ้ง';
var OUTDOOR_RX = /กลางแจ้ง|นอกบ้าน|เดินเร็วกับผู้ใหญ่|ปั่นจักรยาน|วิ่งรอบ/;
var LETTERS = ['ก', 'ข', 'ค', 'ง'];
/* [ป้ายในแท็บตั้งค่า, ชื่อในโค้ด, ค่าเริ่มต้น, คำอธิบาย] */
var SETTING_ROWS = [
  ['ชื่อโรงเรียน', 'schoolName', 'โรงเรียนวัดบรมนิวาส', 'แสดงบนหน้าเว็บ'],
  ['นาทีขั้นต่ำต่อวันที่ได้ดาว', 'minMinutesForStar', 15, 'รวมนาทีที่บันทึกของวันนั้น'],
  ['ดาวบ้านสูงสุดต่อสัปดาห์', 'starCapPerWeek', 2, 'ตามหัวข้อ 3.1 ของเอกสาร D1 ดาวบ้านไม่ใช่ XP'],
  ['บันทึกย้อนหลังได้ (วัน)', 'backfillDays', 2, 'เด็กที่ไม่มีเครื่องมาบันทึกที่โรงเรียนในวันถัดไปได้ และลบรายการของตัวเองได้ในช่วงนี้'],
  ['นาทีสูงสุดต่อครั้ง', 'maxMinutesPerLog', 60, 'กันตัวเลขเกินจริง'],
  ['นาทีสูงสุดต่อวัน', 'maxMinutesPerDay', 120, 'กันตัวเลขเกินจริง และเตือนให้พัก'],
  ['บันทึกสูงสุดต่อวัน (ครั้ง)', 'maxLogsPerDay', 6, ''],
  ['วันเริ่มโปรแกรม (วันจันทร์)', 'programStart', '', 'ใช้ทั้งโรงเรียน ใส่วันจันทร์ของสัปดาห์ที่ 1 เช่น 16/11/2569 ว่างไว้ = ยังไม่เริ่มนับดาว'],
  ['จำนวนสัปดาห์', 'programWeeks', 8, 'ใช้ทั้งโรงเรียน 1–12 สัปดาห์'],
  ['แต้มต่อนาที', 'xpPerMinute', 1, 'บันทึกการขยับ 1 นาที ได้กี่แต้ม (แต้มนับตั้งแต่วันเริ่มโปรแกรม ไม่มีวันจบ)'],
  ['นาทีที่ได้แต้มสูงสุดต่อวัน', 'xpMinuteCap', 60, 'กันกรอกนาทีเกินจริงเพื่อไล่ระดับ เด็กควรขยับเฉลี่ยวันละ 60 นาที ตามคำแนะนำ WHO ดาวกับนาทีรวมยังนับตามปกติ'],
  ['แต้มต่อดาวบ้าน 1 ดวง', 'xpPerStar', 20, 'ดาวบ้านนับเฉพาะช่วงโปรแกรม'],
  ['แต้มภารกิจ ⭐ / ⭐⭐ / ⭐⭐⭐', 'xpMissionDiff', '10,15,20', 'ใส่ 3 ตัวเลข คั่นด้วยจุลภาค ภารกิจประจำวันมี 2 อัน: ขยับ และสุขนิสัย'],
  ['ปลดล็อก ⭐⭐ / ⭐⭐⭐ ที่ระดับ', 'diffUnlock', '4,7', 'ใส่ 2 ตัวเลข เช่น 4,7 = ถึงระดับ 4 เลือก ⭐⭐ ได้ ถึงระดับ 7 เลือก ⭐⭐⭐ ได้'],
  ['แต้มเควสบ้านประจำสัปดาห์', 'xpMissionVideo', 30, 'ทำเควสบ้านกับคนในบ้าน แล้วกดทำแล้ว สัปดาห์ละ 1 ครั้ง ใส่ลิงก์คลิปในแท็บเควสบ้านได้'],
  ['ดูคลิปครบได้แต้ม', 'xpClip', 10, 'คลิปในการ์ดภารกิจ (วันละครั้งต่อภารกิจ) และคลิปเควสบ้าน (สัปดาห์ละครั้ง) ลิงก์คลิปอยู่ในแท็บภารกิจประจำวันและแท็บเควสบ้าน'],
  ['ดูคลิปกี่วินาทีจึงนับว่าครบ', 'clipSeconds', 180, 'ดูครบเท่านี้ หรือดูจนจบคลิปที่สั้นกว่า ข้ามไปข้างหน้าไม่นับ 180 = 3 นาที ไม่ให้เด็กอยู่หน้าจอนาน'],
  ['โหมดฝุ่น PM2.5', 'dustOn', 'เปิด', 'เปิด = ดึงค่าฝุ่นจาก Air4Thai (กรมควบคุมมลพิษ) ทุกชั่วโมง ต้องเปิด ให้ระบบทำงานเองทุกชั่วโมง ในเมนูด้วย · ปิด = ไม่ใช้'],
  ['โหมดฝุ่นเริ่มที่สี', 'dustFrom', 'ส้ม', 'เหลือง / ส้ม / แดง  ถึงสีนี้ = วันฝุ่น: แอปเตือนให้ขยับในบ้าน ภารกิจกลางแจ้งสลับเป็นในบ้าน น้องใส่หน้ากาก มีภารกิจนักสู้ฝุ่น · ครูเปลี่ยนสีของวันนี้เองได้ในโหมดครู'],
  ['พิกัดโรงเรียน (ละติจูด,ลองจิจูด)', 'dustPlace', '13.746,100.518', 'ใช้หาสถานีวัดฝุ่นที่ใกล้ที่สุด ค่าเริ่มต้นคือแถวหัวลำโพง คัดลอกพิกัดจาก Google Maps มาวางได้ เช่น 13.7465,100.5182'],
  ['รหัสสถานี Air4Thai (ไม่บังคับ)', 'dustStation', '', 'ว่างไว้ = ใช้สถานีที่ใกล้โรงเรียนที่สุด ใส่รหัส เช่น bkp97t = ใช้สถานีนี้เสมอ'],
  ['ภารกิจนักสู้ฝุ่น: ได้แต้ม', 'xpDust', 10, 'วันฝุ่นเยอะ เด็กได้ภารกิจพิเศษ 1 ข้อ ทำครบ 3 วันได้สติกเกอร์นักสู้ฝุ่น'],
  ['โบนัสไฟต่อเนื่อง 3 วัน', 'xpStreak3', 15, 'บันทึกการขยับติดกันครบ 3 วัน ได้ 1 ครั้งต่อรอบ'],
  ['โบนัสไฟต่อเนื่องทุก 7 วัน', 'xpStreak7', 50, 'ครบ 7, 14, 21 … วัน'],
  ['วันพักต่อสัปดาห์ (ไฟไม่ดับ)', 'streakRest', 1, 'ไม่ได้บันทึกได้กี่วันต่อสัปดาห์ (จันทร์–อาทิตย์) โดยไฟต่อเนื่องไม่ดับ'],
  ['เหรียญวันสะสม (วัน:แต้ม)', 'dayBadges', '30:100,60:200,90:300,120:400,150:500', 'นับวันที่บันทึกการขยับรวมทั้งหมด ไฟขาดหรือปิดเทอมก็ไม่หาย 🥉 🥈 🥇 💎 👑'],
  ['เกณฑ์ระดับ 1–10 (แต้มสะสม)', 'levelXp', '0,200,700,1500,3000,4500,6500,9000,11500,14000', 'ออกแบบให้เด็กที่ทำสม่ำเสมอ (5 วัน/สัปดาห์) ถึงระดับ 10 เมื่อทำครบ ~150 วัน ใส่ 10 ตัวเลข ตัวแรกเป็น 0 และเพิ่มขึ้นเรื่อย ๆ'],
  ['ดาวตำนาน ★ ทุกกี่แต้ม (หลังระดับ 10)', 'legendStep', 2000, 'ถึงระดับ 10 แล้ว ทุก ๆ กี่แต้มได้ดาวตำนาน 1 ดวง'],
  ['เป้าสัปดาห์เริ่มต้น (นาที)', 'weekGoalStart', 60, 'เป้าสัปดาห์แรกของทุกคน'],
  ['เป้าสัปดาห์เพิ่มครั้งละ (%)', 'weekGoalStep', 10, 'ถึงเป้า → สัปดาห์ต่อไปเพิ่ม 10% / ไม่ถึง → ใช้เป้าเดิม ปัดขึ้นทีละ 5 นาที ใส่ 0 = เป้าคงที่ทั้งปี'],
  ['เป้าสัปดาห์สูงสุด (นาที)', 'weekGoalMax', 420, 'WHO แนะนำเด็กขยับเฉลี่ยวันละ 60 นาที = 420 นาทีต่อสัปดาห์'],
  ['แต้มเมื่อถึงเป้าสัปดาห์', 'xpWeekGoal', 20, 'ได้สัปดาห์ละ 1 ครั้ง'],
  ['ห้องแข่งห้อง: สมัครอย่างน้อย (คน)', 'roomMinMembers', 5, 'คะแนนห้อง = % เพื่อนในห้องที่ขยับสัปดาห์นี้ ห้องที่สมัครน้อยกว่านี้ยังไม่ขึ้นตาราง'],
  ['ลีกตามภาค: แสดงกี่อันดับ', 'leagueSize', 10, 'ใช้แต้มสัปดาห์นี้ เริ่มนับใหม่ทุกวันจันทร์ อัปเดตทุกชั่วโมง ตารางโชว์ชื่อเล่น + ห้อง ไม่โชว์ชื่อจริง'],
  ['คำถามสุขภาพ: ตอบถูกได้แต้ม', 'xpQuizRight', 5, 'วันละ 1 ข้อ ทั้งช่วงชั้นได้ข้อเดียวกัน คำถามอยู่ในแท็บคำถามสุขภาพ'],
  ['คำถามสุขภาพ: ตอบผิดได้แต้ม', 'xpQuizWrong', 1, 'ตอบผิดก็ได้อ่านเฉลย'],
  ['อีเวนต์: ทำครบได้แต้ม', 'xpEvent', 50, 'ทำภารกิจอีเวนต์ครบทุกข้อ ได้แต้มนี้ + สติกเกอร์รุ่นพิเศษ อีเวนต์อยู่ในแท็บอีเวนต์'],
  ['โหมดครู: เด็กหายไปกี่วันจึงแจ้ง', 'missingDays', 7, 'ไม่ได้บันทึกติดกันตั้งแต่กี่วัน (คนที่สมัครแล้วยังไม่เคยบันทึก นับจากวันสมัคร)'],
  ['เลขประจำตัวนักเรียนมีกี่หลัก', 'sidLen', 4, 'สมัครใหม่ต้องใส่ให้ครบเท่านี้ กันพิมพ์ผิด (0 = ไม่จำกัด) เด็กที่สมัครไว้แล้วยังเข้าได้ ครูแก้เลขได้ที่ โหมดครู > ค้นหานักเรียน'],
  ['ภาคเรียนปัจจุบัน (ผลสมรรถภาพ)', 'termNow', '2/2569', 'รูปแบบ ภาคเรียน/ปี พ.ศ. เช่น 2/2569 ใช้ตอนครูกรอกผลสมรรถภาพในแอป'],
  ['การเดินทางของโรงเรียน: ก้าวต่อ 1 นาที', 'stepsPerMin', 100, 'จอใหญ่และแอปเด็กแปลงนาทีที่ทั้งโรงเรียนขยับรวมกันเป็นก้าว (ก้าวละประมาณ 0.5 เมตร) แล้วพาเที่ยวไทย อาเซียน รอบโลก ใส่ 50–200']
];
var TEXT_SETTINGS = ['programStart', 'levelXp', 'xpMissionDiff', 'diffUnlock', 'dayBadges', 'termNow', 'dustOn', 'dustFrom', 'dustPlace', 'dustStation'];
/* ป้ายเก่าในแท็บตั้งค่าของชีตที่ติดตั้งก่อนเปลี่ยนเป็นคลิป: ยังอ่านค่าได้ ไม่ต้องแก้ชีต */
var SETTING_ALIASES = {
  'แต้มภารกิจวิดีโอประจำสัปดาห์': 'xpMissionVideo', 'โบนัสแนบรูป': 'xpPhotoBonus', 'รับรูปและวิดีโอ': 'proofOn',
  'เก็บรูปไว้ (วัน)': 'photoKeepDays', 'เก็บวิดีโอไว้ (วัน)': 'videoKeepDays'
};
var SETTING_OLD_NOTES = {
  'โบนัสแนบรูป': 'ใช้กับแถวเก่าที่เคยส่งรูป และแถว สาธิตในคาบ (ตอนนี้เปลี่ยนเป็นดูคลิปแล้ว)',
  'รับรูปและวิดีโอ': 'ไม่ใช้แล้ว (เปลี่ยนจากถ่ายรูปเป็นดูคลิป) ลบแถวนี้ได้',
  'เก็บรูปไว้ (วัน)': 'ใช้ลบไฟล์รูปหลักฐานเก่าที่ส่งก่อนเปลี่ยนเป็นคลิป',
  'เก็บวิดีโอไว้ (วัน)': 'ใช้ลบไฟล์วิดีโอเควสบ้านเก่าที่ส่งก่อนเปลี่ยนเป็นคลิป'
};
/* ตัวอย่างเควสบ้าน ให้ครูและผู้เชี่ยวชาญตรวจก่อนใช้ */
var EXAMPLE_QUESTS = [
  [1, 'เล่นไล่จับหรือเดินเล่นกับคนในบ้าน 15 นาที', 'ชวนคนในบ้านเดินเร็วหรือเล่นไล่จับ 15 นาที'],
  [2, 'เต้นตามเพลงที่ชอบ 3 เพลง', 'เต้นตามเพลงที่ชอบ 3 เพลง แล้วทำท่ายืดแบบแมว'],
  [3, 'เล่นโยนรับลูกบอลกับผู้ใหญ่', 'เล่นโยนรับลูกบอลหรือตีแบดกับคนในบ้าน 15 นาที'],
  [4, 'ทำท่าแมวกับท่าผีเสื้อก่อนนอน', 'ทำท่ายืดสายแมวขั้น 1 ทั้ง 2 ท่าก่อนนอน'],
  [5, 'กระโดดเบา ๆ สลับเดิน 10 นาที', 'กระโดดเชือกหรือกระโดดตบเบา ๆ สลับเดิน 10 นาที'],
  [6, 'เล่นกระโดดยางหรือตั้งเตกับครอบครัว', 'ให้ผู้ปกครองสอนเกมสมัยเด็ก เช่น กระโดดยาง ตั้งเต แล้วเล่นด้วยกัน'],
  [7, 'เดินไปที่ใกล้บ้านกับผู้ใหญ่', 'เดินหรือปั่นจักรยานกับผู้ใหญ่ไปที่ใกล้บ้าน'],
  [8, 'สอนท่าที่ชอบให้คนในบ้าน 1 ท่า', 'สอนท่าเควสที่ชอบที่สุดให้คนในบ้าน แล้วทำด้วยกัน']
];
/* คำถามสุขภาพตั้งต้น: [ช่วงชั้น, คำถาม, คำตอบที่ถูก, ตัวเลือกผิด 1, 2, 3, เฉลยสั้น ๆ]
 * ระบบสลับตำแหน่งคำตอบที่ถูกให้ (ก ข ค ง) ตอนสร้างแท็บ ครูและผู้เชี่ยวชาญตรวจก่อนใช้ แก้หรือเพิ่มในแท็บคำถามสุขภาพได้ */
var DEFAULT_QUESTIONS = [
  ['low', 'เด็กควรขยับร่างกายวันละประมาณกี่นาที?', '60 นาที', '5 นาที', '15 นาที', '5 ชั่วโมง', 'องค์การอนามัยโลกแนะนำให้เด็กขยับเฉลี่ยวันละ 60 นาที แบ่งเล่นเป็นหลายช่วงก็ได้'],
  ['low', 'ก่อนกินข้าวควรทำอะไร?', 'ล้างมือด้วยสบู่', 'เล่นโทรศัพท์', 'วิ่งรอบบ้าน', 'นอนพัก', 'ล้างมือด้วยสบู่ช่วยกำจัดเชื้อโรคที่ติดมือ ก่อนเข้าปาก'],
  ['low', 'ควรแปรงฟันวันละกี่ครั้ง?', 'วันละ 2 ครั้ง เช้าและก่อนนอน', 'ไม่ต้องแปรงก็ได้', 'สัปดาห์ละครั้ง', 'เฉพาะวันหยุด', 'แปรงฟันเช้าและก่อนนอนทุกวัน ฟันจะแข็งแรงไม่ผุ'],
  ['low', 'แปรงฟันแต่ละครั้งควรนานประมาณเท่าไร?', '2 นาที', '5 วินาที', '20 นาที', '1 ชั่วโมง', 'แปรงนานประมาณ 2 นาที ให้ทั่วทุกซี่ ทั้งด้านนอก ด้านใน และด้านบดเคี้ยว'],
  ['low', 'เด็กวัยเรียนควรนอนคืนละประมาณกี่ชั่วโมง?', '9–12 ชั่วโมง', '3–4 ชั่วโมง', '5–6 ชั่วโมง', '15–16 ชั่วโมง', 'เด็กอายุ 6–12 ปี ควรนอน 9–12 ชั่วโมง ร่างกายจะได้เติบโตและพักผ่อนเต็มที่'],
  ['low', 'เวลากระหายน้ำ เครื่องดื่มใดดีที่สุด?', 'น้ำเปล่า', 'น้ำอัดลม', 'ชานมไข่มุก', 'น้ำหวาน', 'น้ำเปล่าดับกระหายได้ดีและไม่มีน้ำตาล ฟันจึงไม่ผุ'],
  ['low', 'ก่อนออกกำลังกายควรทำอะไรก่อน?', 'อบอุ่นร่างกาย', 'กินขนมเยอะ ๆ', 'นอนหลับ', 'ดื่มน้ำอัดลม', 'อบอุ่นร่างกายช่วยให้กล้ามเนื้อพร้อมและลดการบาดเจ็บ'],
  ['low', 'อาหารหลักของคนไทยมีกี่หมู่?', '5 หมู่', '2 หมู่', '3 หมู่', '9 หมู่', 'อาหารหลัก 5 หมู่ ควรกินให้ครบทุกวัน ร่างกายจะแข็งแรง'],
  ['low', 'ข้อใดเป็นผัก?', 'บรอกโคลี', 'ไข่ต้ม', 'นมจืด', 'ขนมปัง', 'บรอกโคลีเป็นผักสีเขียว มีวิตามินและใยอาหาร'],
  ['low', 'เวลาจะไอหรือจาม ควรทำอย่างไร?', 'ใช้ข้อพับแขนหรือทิชชูปิดปากปิดจมูก', 'หันไปจามใส่เพื่อน', 'ไม่ต้องปิดอะไร', 'จามใส่มือแล้วจับของต่อ', 'ปิดปากปิดจมูกช่วยไม่ให้เชื้อโรคกระจายไปถึงคนอื่น'],
  ['low', 'ขี่จักรยานควรสวมอะไรที่ศีรษะ?', 'หมวกกันน็อก', 'หมวกไหมพรม', 'ผ้าขนหนู', 'ไม่ต้องสวมอะไร', 'หมวกกันน็อกช่วยป้องกันศีรษะเมื่อหกล้ม'],
  ['low', 'ข้ามถนนควรข้ามตรงไหน?', 'ทางม้าลายหรือสะพานลอย', 'ตรงไหนก็ได้', 'ระหว่างรถที่จอดติดกัน', 'ตรงทางโค้ง', 'ข้ามที่ทางม้าลายหรือสะพานลอย มองซ้าย ขวา ซ้าย ก่อนข้ามเสมอ'],
  ['low', 'ดูจอนาน ๆ ควรพักสายตาอย่างไร?', 'มองไปไกล ๆ สักครู่', 'ขยี้ตาแรง ๆ', 'ดูจอต่อไปเลย', 'ปิดไฟแล้วดูจอ', 'ทุก 20 นาที ให้มองไปไกล ๆ ประมาณ 20 วินาที ตาจะได้พัก'],
  ['low', 'ผลไม้ข้อใดมีวิตามินซีมาก?', 'ฝรั่ง', 'ข้าวเหนียว', 'หมูทอด', 'ลูกอม', 'ฝรั่งมีวิตามินซีสูง ช่วยให้ร่างกายแข็งแรง'],
  ['low', 'นั่งทำการบ้านที่ถูกต้องควรนั่งอย่างไร?', 'หลังตรง เท้าวางราบกับพื้น', 'นอนคว่ำเขียน', 'ก้มหน้าชิดโต๊ะ', 'นั่งบิดตัวไปด้านข้าง', 'นั่งหลังตรงช่วยให้หลังและคอไม่ปวด'],
  ['low', 'หลังเข้าห้องน้ำควรทำอะไร?', 'ล้างมือด้วยสบู่', 'เช็ดมือกับเสื้อ', 'ไม่ต้องทำอะไร', 'กินขนมต่อเลย', 'ล้างมือด้วยสบู่หลังเข้าห้องน้ำทุกครั้ง ช่วยป้องกันท้องเสีย'],
  ['low', 'ข้อใดเป็นการเล่นที่ได้ขยับร่างกาย?', 'กระโดดเชือก', 'ดูการ์ตูน', 'เล่นเกมมือถือ', 'นั่งนิ่ง ๆ', 'กระโดดเชือกทำให้หัวใจ ขา และกระดูกแข็งแรง'],
  ['low', 'อากาศร้อนมาก เล่นกลางแจ้งควรทำอย่างไร?', 'ดื่มน้ำบ่อย ๆ และพักในที่ร่ม', 'วิ่งกลางแดดนาน ๆ', 'ไม่ต้องดื่มน้ำ', 'ใส่เสื้อหนา ๆ', 'อากาศร้อนร่างกายเสียเหงื่อมาก ต้องดื่มน้ำและพักในที่ร่มบ่อย ๆ'],
  ['low', 'นมช่วยให้ส่วนใดของร่างกายแข็งแรง?', 'กระดูกและฟัน', 'เส้นผม', 'เสียง', 'ไม่ช่วยอะไรเลย', 'นมมีแคลเซียม ช่วยให้กระดูกและฟันแข็งแรง'],
  ['low', 'เมื่อรู้สึกโกรธ วิธีที่ดีคืออะไร?', 'หายใจเข้าออกช้า ๆ', 'ตีเพื่อน', 'ขว้างของ', 'ตะโกนใส่คนอื่น', 'หายใจช้า ๆ ช่วยให้ใจเย็นลง แล้วค่อยพูดคุยกัน'],
  ['low', 'ข้อใดเป็นอาหารว่างที่ดีต่อสุขภาพ?', 'ผลไม้', 'ลูกอม', 'น้ำอัดลม', 'ขนมกรุบกรอบ', 'ผลไม้มีวิตามินและใยอาหาร เป็นอาหารว่างที่ดี'],
  ['low', 'เลือดกำเดาไหล ควรทำอย่างไร?', 'ก้มหน้าเล็กน้อย บีบปีกจมูกไว้', 'เงยหน้าขึ้นสูง ๆ', 'นอนหงาย', 'วิ่งไปมา', 'นั่งก้มหน้าเล็กน้อย บีบปีกจมูกไว้ประมาณ 10 นาที แล้วบอกผู้ใหญ่'],
  ['low', 'หลังออกกำลังกายเสร็จ ควรทำอะไร?', 'ยืดเหยียดกล้ามเนื้อ', 'นอนทันที', 'ดื่มน้ำอัดลม', 'นั่งเล่นเกมต่อทันที', 'ยืดเหยียดช่วยให้กล้ามเนื้อผ่อนคลาย ไม่ตึง'],
  ['low', 'การล้างมือที่ถูกต้องมีกี่ขั้นตอน?', '7 ขั้นตอน', '2 ขั้นตอน', '4 ขั้นตอน', '12 ขั้นตอน', 'ล้างมือ 7 ขั้นตอน ถูให้ทั่วทั้งฝ่ามือ หลังมือ ซอกนิ้ว นิ้วโป้ง ปลายนิ้ว และข้อมือ'],
  ['low', 'ฟันน้ำนมหลุดแล้วจะมีฟันอะไรขึ้นแทน?', 'ฟันแท้', 'ฟันปลอม', 'ไม่มีฟันขึ้นอีก', 'ฟันน้ำนมซี่ใหม่', 'ฟันแท้ต้องใช้ไปตลอดชีวิต จึงต้องดูแลให้ดี'],
  ['low', 'ข้อใดช่วยให้หลับสบาย?', 'เข้านอนเวลาเดิมทุกวัน', 'เล่นมือถือจนดึก', 'ดื่มน้ำอัดลมก่อนนอน', 'ดูหนังผีก่อนนอน', 'เข้านอนเวลาเดิมทุกวัน ร่างกายจะจำเวลาและหลับง่ายขึ้น'],
  ['low', 'หัวใจทำหน้าที่อะไร?', 'สูบฉีดเลือดไปทั่วร่างกาย', 'ย่อยอาหาร', 'มองเห็น', 'ได้ยินเสียง', 'หัวใจสูบฉีดเลือดพาออกซิเจนไปเลี้ยงทุกส่วนของร่างกาย'],
  ['low', 'เวลาวิ่งเร็ว ๆ หัวใจจะเต้นอย่างไร?', 'เต้นเร็วขึ้น', 'หยุดเต้น', 'เต้นช้าลง', 'เหมือนเดิมเสมอ', 'วิ่งแล้วร่างกายต้องการออกซิเจนมากขึ้น หัวใจจึงเต้นเร็วขึ้น'],
  ['low', 'อวัยวะใดใช้หายใจ?', 'ปอด', 'กระเพาะอาหาร', 'ไต', 'ตับ', 'ปอดรับออกซิเจนเข้าสู่ร่างกายและปล่อยคาร์บอนไดออกไซด์ออก'],
  ['low', 'ก่อนกินผลไม้ควรทำอะไร?', 'ล้างให้สะอาด', 'เป่าลมใส่', 'ไม่ต้องทำอะไร', 'โรยเกลือเยอะ ๆ', 'ล้างผลไม้ให้สะอาด ช่วยลดเชื้อโรคและสารเคมีที่ติดมา'],
  ['low', 'เพื่อนหกล้มเป็นแผล ควรทำอย่างไร?', 'รีบบอกครูหรือผู้ใหญ่', 'หัวเราะเยาะ', 'ปล่อยไว้', 'เอาดินทาแผล', 'บอกผู้ใหญ่ให้ช่วยทำแผล และอยู่เป็นเพื่อนเขา'],
  ['low', 'เล่นน้ำหรือว่ายน้ำ ต้องมีใครอยู่ด้วย?', 'ผู้ใหญ่', 'เล่นคนเดียวก็ได้', 'น้องเล็ก ๆ', 'ไม่ต้องมีใคร', 'เล่นน้ำต้องมีผู้ใหญ่ดูแลเสมอ เพื่อป้องกันการจมน้ำ'],
  ['low', 'ข้อใดเป็นอาหารหมู่โปรตีน?', 'ไข่', 'ข้าวสวย', 'น้ำมัน', 'น้ำตาล', 'ไข่ เนื้อสัตว์ นม และถั่ว ช่วยสร้างกล้ามเนื้อและซ่อมแซมร่างกาย'],
  ['low', 'ข้าวและแป้งให้อะไรกับร่างกาย?', 'พลังงาน', 'สีผม', 'ความสูงทันที', 'ไม่ให้อะไร', 'ข้าวและแป้งให้พลังงานสำหรับเล่นและเรียน'],
  ['low', 'แดดแรงตอนเที่ยง ถ้าต้องออกไปข้างนอก ควรทำอย่างไร?', 'สวมหมวกหรืออยู่ในที่ร่ม', 'ใส่ถุงมือยาง', 'วิ่งให้เร็วที่สุด', 'ไม่ต้องป้องกันอะไร', 'หมวกและที่ร่มช่วยกันแดด ลดความร้อนและผิวไหม้'],
  ['low', 'ข้อใดเป็นการดูแลเล็บที่ดี?', 'ตัดเล็บให้สั้นและสะอาด', 'กัดเล็บ', 'ไว้เล็บยาวสกปรก', 'ใช้เล็บแคะฟัน', 'เล็บสั้นและสะอาดไม่สะสมเชื้อโรค'],
  ['low', 'กระโดดเชือกช่วยเรื่องใด?', 'หัวใจและขาแข็งแรง', 'ทำให้ง่วงนอน', 'ทำให้ปวดฟัน', 'ไม่ช่วยอะไร', 'กระโดดเชือกช่วยให้หัวใจ ปอด ขา และกระดูกแข็งแรง'],
  ['low', 'รู้สึกเหนื่อยมากระหว่างวิ่ง ควรทำอย่างไร?', 'ชะลอหรือหยุดพัก', 'วิ่งเร็วขึ้นอีก', 'กลั้นหายใจ', 'ไม่บอกใคร', 'เหนื่อยมากให้ชะลอหรือพัก ถ้าเวียนหัวหรือเจ็บหน้าอกให้บอกผู้ใหญ่ทันที'],
  ['low', 'หลังกินข้าวควรดูแลฟันอย่างไร?', 'บ้วนปากหรือแปรงฟัน', 'กินลูกอมต่อ', 'นอนทันที', 'ไม่ต้องทำอะไร', 'บ้วนปากหรือแปรงฟันช่วยล้างเศษอาหารที่ทำให้ฟันผุ'],
  ['low', 'ดูทีวีใกล้จอเกินไปจะเป็นอย่างไร?', 'ทำให้ตาล้า', 'ทำให้ตาดีขึ้น', 'ทำให้สูงขึ้น', 'ไม่มีผลอะไรเลย', 'ดูจอใกล้ ๆ นาน ๆ ทำให้ตาล้า ควรนั่งห่างและพักสายตา'],
  ['low', 'ควรถูมือด้วยสบู่นานประมาณเท่าไร?', 'ประมาณ 20 วินาที', '1 วินาที', '10 นาที', 'ไม่ต้องถู', 'ถูมือด้วยสบู่ประมาณ 20 วินาที เท่ากับร้องเพลงแฮปปี้เบิร์ธเดย์ 2 รอบ'],
  ['low', 'ใครช่วยดูแลสุขภาพฟันของเราได้?', 'ทันตแพทย์ (หมอฟัน)', 'ช่างตัดผม', 'คนขายขนม', 'ช่างไฟ', 'ควรไปพบหมอฟันเพื่อตรวจฟันอย่างน้อยปีละครั้ง'],
  ['low', 'ข้อใดเป็นการออกกำลังกายในบ้านได้?', 'เต้นตามเพลง', 'นอนดูทีวี', 'เล่นเกมมือถือ', 'กินขนม', 'เต้นตามเพลงทำได้ในบ้าน สนุกและได้ขยับทั้งตัว'],
  ['low', 'คนแปลกหน้าชวนไปที่อื่น ควรทำอย่างไร?', 'ปฏิเสธและบอกผู้ใหญ่ที่ไว้ใจ', 'ไปด้วยทันที', 'รับขนมแล้วไปด้วย', 'ไม่บอกใคร', 'ไม่ไปกับคนแปลกหน้า และรีบบอกพ่อแม่หรือครู'],
  ['low', 'เวลาออกกำลังกาย ร่างกายเสียน้ำทางไหน?', 'เหงื่อ', 'เล็บ', 'เส้นผม', 'ฟัน', 'ร่างกายเสียน้ำทางเหงื่อ จึงต้องจิบน้ำบ่อย ๆ'],
  ['low', 'ข้อใดช่วยให้กระดูกแข็งแรง?', 'ดื่มนมและออกกำลังกาย', 'นอนดึกทุกคืน', 'กินลูกอม', 'นั่งอยู่แต่ในบ้าน', 'นมมีแคลเซียม และการกระโดด วิ่ง ช่วยให้กระดูกแข็งแรง'],
  ['low', 'ควรเปลี่ยนแปรงสีฟันเมื่อใด?', 'เมื่อขนแปรงบาน หรือประมาณทุก 3 เดือน', 'ทุก 5 ปี', 'ไม่ต้องเปลี่ยนเลย', 'เมื่อแปรงหาย', 'ขนแปรงที่บานทำความสะอาดฟันได้ไม่ดี'],
  ['low', 'ของใช้ใดไม่ควรใช้ร่วมกับคนอื่น?', 'แปรงสีฟัน', 'ลูกบอล', 'หนังสือนิทาน', 'ดินสอสี', 'แปรงสีฟันและผ้าเช็ดตัวเป็นของใช้ส่วนตัว ใช้ร่วมกันอาจติดเชื้อโรค'],
  ['low', 'ไม่สบาย มีไข้ ควรทำอย่างไร?', 'บอกพ่อแม่หรือครู และพักผ่อน', 'ไปวิ่งเล่นต่อ', 'หยิบยามากินเอง', 'ไม่บอกใคร', 'บอกผู้ใหญ่ให้ช่วยดูแล ไม่หยิบยากินเอง'],
  ['low', 'ร่างกายต้องการอะไรเพื่อเติบโตแข็งแรง?', 'อาหารดี นอนพอ ออกกำลังกาย', 'ขนมเยอะ ๆ', 'นอนดึก ๆ', 'เล่นเกมทั้งวัน', 'กินดี นอนพอ ขยับทุกวัน คือสูตรแข็งแรง'],
  ['low', 'ท่ายืนขาเดียวช่วยฝึกอะไร?', 'การทรงตัว', 'การมองเห็น', 'การได้ยิน', 'การนอนหลับ', 'ยืนขาเดียวฝึกการทรงตัว ช่วยให้ไม่ล้มง่าย'],
  ['low', 'ใส่รองเท้าไม่พอดีเท้าแล้ววิ่ง จะเป็นอย่างไร?', 'อาจเจ็บเท้าหรือหกล้ม', 'วิ่งเร็วขึ้น', 'ไม่มีผลอะไร', 'เท้าโตขึ้น', 'รองเท้าพอดีเท้าช่วยให้วิ่งได้ปลอดภัย'],
  ['low', 'ผักสีเขียว สีส้ม สีแดง ควรกินแบบไหน?', 'กินหลาย ๆ สี', 'กินสีเดียวพอ', 'ไม่ต้องกินผัก', 'กินแต่ผักทอด', 'ผักแต่ละสีมีวิตามินต่างกัน กินหลายสีได้ประโยชน์ครบ'],
  ['low', 'หลังเล่นกับสัตว์เลี้ยง ควรทำอะไร?', 'ล้างมือ', 'กินขนมทันที', 'ขยี้ตา', 'ไม่ต้องทำอะไร', 'สัตว์เลี้ยงอาจมีเชื้อโรค ล้างมือทุกครั้งหลังเล่น'],
  ['low', 'วันที่อากาศร้อน ช่วงไหนเหมาะกับการเล่นกลางแจ้ง?', 'ช่วงเช้าหรือช่วงเย็น', 'เที่ยงตรง', 'บ่ายโมงกลางแดด', 'ไม่มีช่วงไหนเลย', 'ช่วงเช้าและเย็นแดดไม่แรง เล่นได้สบายกว่า'],
  ['low', 'ข้อใดช่วยให้สมองแจ่มใสตอนเช้า?', 'กินอาหารเช้า', 'ไม่กินอะไรเลย', 'ดื่มน้ำอัดลม', 'นอนต่อจนสาย', 'อาหารเช้าให้พลังงาน ช่วยให้มีสมาธิในการเรียน'],
  ['low', 'วันที่ฝุ่นละอองเยอะ ควรทำอย่างไร?', 'เล่นในบ้าน ใส่หน้ากากเมื่อออกไปข้างนอก', 'วิ่งเล่นกลางแจ้งนาน ๆ', 'เปิดหน้าต่างให้ฝุ่นเข้า', 'ไม่ต้องสนใจ', 'ฝุ่นละอองทำร้ายปอด วันที่ฝุ่นเยอะให้เล่นในบ้านแทน'],
  ['low', 'เล่นกีฬากับเพื่อน ควรทำอย่างไร?', 'เล่นตามกติกาและมีน้ำใจ', 'โกงเพื่อชนะ', 'ผลักเพื่อน', 'โกรธเมื่อแพ้', 'แพ้ชนะไม่สำคัญเท่าการเล่นอย่างมีน้ำใจ'],
  ['low', 'ข้อใดเป็นสัญญาณว่าร่างกายต้องการน้ำ?', 'กระหายน้ำ ปากแห้ง', 'ผมยาวขึ้น', 'เล็บยาวขึ้น', 'ตัวสูงขึ้น', 'กระหายน้ำ ปากแห้ง แปลว่าร่างกายต้องการน้ำแล้ว'],
  ['low', 'ยิ้มและหัวเราะกับเพื่อน ช่วยเรื่องใด?', 'ทำให้อารมณ์ดี มีความสุข', 'ทำให้ฟันผุ', 'ทำให้ปวดหัว', 'ไม่ช่วยอะไร', 'อารมณ์ดีเป็นส่วนหนึ่งของสุขภาพที่ดี'],

  ['high', 'องค์การอนามัยโลกแนะนำให้เด็กอายุ 5–17 ปี ขยับร่างกายระดับปานกลางถึงหนัก เฉลี่ยวันละเท่าไร?', '60 นาที', '15 นาที', '30 นาที', '3 ชั่วโมง', 'เฉลี่ยวันละ 60 นาที และควรมีกิจกรรมเสริมกล้ามเนื้อและกระดูก เช่น กระโดด ปีนป่าย อย่างน้อย 3 วันต่อสัปดาห์'],
  ['high', 'วัดชีพจรด้วยตัวเองได้ง่ายที่ตำแหน่งใด?', 'ข้อมือหรือข้างลำคอ', 'ข้อศอก', 'หัวเข่า', 'ปลายจมูก', 'ใช้นิ้วชี้และนิ้วกลางแตะที่ข้อมือด้านนิ้วโป้ง หรือข้างลำคอ แล้วนับจำนวนครั้ง'],
  ['high', '"แปรง 2 2 2" หมายถึงอะไร?', 'แปรงวันละ 2 ครั้ง นาน 2 นาที งดกินหลังแปรง 2 ชั่วโมง', 'แปรง 2 วันครั้ง ครั้งละ 2 นาที', 'แปรงสัปดาห์ละ 2 ครั้ง', 'ใช้แปรง 2 อัน ยาสีฟัน 2 หลอด', 'แปรง 2 2 2 ช่วยให้ฟลูออไรด์ในยาสีฟันอยู่กับฟันนานขึ้น ป้องกันฟันผุ'],
  ['high', 'ยาสีฟันที่ช่วยป้องกันฟันผุ ควรมีสารใด?', 'ฟลูออไรด์', 'น้ำตาล', 'คาเฟอีน', 'สีผสมอาหาร', 'ฟลูออไรด์ช่วยให้ผิวฟันแข็งแรง ทนต่อกรดที่ทำให้ฟันผุ'],
  ['high', 'สารอาหารใดช่วยสร้างและซ่อมแซมกล้ามเนื้อ?', 'โปรตีน', 'น้ำตาล', 'เกลือ', 'ใยอาหาร', 'โปรตีนจากเนื้อสัตว์ ไข่ นม ถั่ว ช่วยสร้างและซ่อมแซมกล้ามเนื้อ'],
  ['high', 'ใยอาหารจากผักและผลไม้ช่วยเรื่องใด?', 'ช่วยระบบขับถ่าย', 'ทำให้ผมดำ', 'ทำให้สายตายาว', 'ทำให้ฟันผุ', 'ใยอาหารช่วยให้ขับถ่ายสะดวก ลดอาการท้องผูก'],
  ['high', 'ฉลากโภชนาการบนห่อขนมช่วยให้รู้อะไร?', 'ปริมาณน้ำตาล ไขมัน และโซเดียม', 'ราคาขายส่ง', 'ชื่อคนขาย', 'เวลาเปิดร้าน', 'อ่านฉลากก่อนซื้อ ช่วยเลือกขนมที่หวาน มัน เค็ม น้อยกว่า'],
  ['high', 'อบอุ่นร่างกายก่อนออกกำลังกายควรใช้เวลาประมาณเท่าไร?', '5–10 นาที', '5 วินาที', '1 ชั่วโมง', 'ไม่ต้องอบอุ่นร่างกาย', 'อบอุ่นร่างกาย 5–10 นาที ด้วยการเดินเร็ว วิ่งเบา ๆ หรือหมุนข้อต่อ'],
  ['high', 'ข้อใดเป็นสมรรถภาพทางกายเพื่อสุขภาพ?', 'ความอ่อนตัว', 'ความเร็วในการพิมพ์', 'ความจำ', 'ลายมือสวย', 'สมรรถภาพทางกายเพื่อสุขภาพ เช่น ความอ่อนตัว ความแข็งแรงของกล้ามเนื้อ และความอดทนของหัวใจ'],
  ['high', 'การนั่งงอตัวไปข้างหน้า ใช้วัดสมรรถภาพด้านใด?', 'ความอ่อนตัว', 'ความเร็ว', 'ความแข็งแรงของแขน', 'การมองเห็น', 'นั่งงอตัวไปข้างหน้าวัดความอ่อนตัวของหลังส่วนล่างและต้นขาด้านหลัง'],
  ['high', 'ลุกนั่ง 60 วินาที ใช้วัดความแข็งแรงและความอดทนของกล้ามเนื้อส่วนใด?', 'กล้ามเนื้อท้อง', 'กล้ามเนื้อนิ้วมือ', 'กล้ามเนื้อใบหน้า', 'กล้ามเนื้อนิ้วเท้า', 'ลุกนั่งใช้กล้ามเนื้อท้องเป็นหลัก'],
  ['high', 'ยืนยกเข่าขึ้นลง 3 นาที ใช้วัดอะไร?', 'ความอดทนของระบบหัวใจและการหายใจ', 'ความอ่อนตัว', 'ความจำ', 'ความแข็งแรงของนิ้วมือ', 'ยกเข่าต่อเนื่อง 3 นาที บอกได้ว่าหัวใจและปอดทำงานได้ทนแค่ไหน'],
  ['high', 'ดันพื้นประยุกต์ 30 วินาที วัดความแข็งแรงของส่วนใด?', 'กล้ามเนื้อแขนและลำตัวส่วนบน', 'กล้ามเนื้อน่อง', 'กล้ามเนื้อใบหน้า', 'กล้ามเนื้อนิ้วเท้า', 'ดันพื้นใช้กล้ามเนื้อแขน หัวไหล่ และอก'],
  ['high', 'ท่ายืดเหยียดแบบค้างไว้ ควรค้างประมาณกี่วินาที?', '10–30 วินาที', '1 วินาที', '5 นาที', 'ไม่ต้องค้าง ให้เด้งแรง ๆ', 'ค้างไว้ 10–30 วินาที หายใจปกติ ไม่เด้งตัว'],
  ['high', 'ขณะยืดเหยียดกล้ามเนื้อ ควรรู้สึกอย่างไร?', 'ตึงพอดี ไม่เจ็บ', 'เจ็บมากจนทนไม่ไหว', 'ชาไปทั้งขา', 'ต้องได้ยินเสียงกระดูกดัง', 'ยืดแค่รู้สึกตึง ถ้าเจ็บให้ผ่อนลง'],
  ['high', 'กฎ 20-20-20 เพื่อถนอมสายตา คืออะไร?', 'ทุก 20 นาที มองไกลประมาณ 6 เมตร นาน 20 วินาที', 'ดูจอ 20 ชั่วโมงต่อวัน', 'กะพริบตา 20 ครั้งต่อวินาที', 'นั่งห่างจอ 20 เซนติเมตร', 'พักสายตาเป็นระยะ ลดอาการตาล้าจากการดูจอ'],
  ['high', 'เด็กวัยเรียนควรดูจอเพื่อความบันเทิงไม่เกินวันละเท่าไร?', '2 ชั่วโมง', '6 ชั่วโมง', '10 ชั่วโมง', 'ไม่ต้องจำกัด', 'ดูจอเพื่อความบันเทิงไม่เกินวันละ 2 ชั่วโมง แล้วใช้เวลาที่เหลือไปขยับและเล่นกลางแจ้ง'],
  ['high', 'อาการใดบอกว่าร่างกายอาจขาดน้ำ?', 'ปัสสาวะสีเข้ม ปากแห้ง เวียนศีรษะ', 'ผมยาวเร็ว', 'ตาเป็นประกาย', 'เล็บแข็งแรง', 'ปัสสาวะสีเข้มเป็นสัญญาณให้ดื่มน้ำเพิ่ม'],
  ['high', 'เพื่อนเป็นลมแดด ตัวร้อนจัด หน้าแดง ควรช่วยอย่างไรก่อน?', 'พาเข้าที่ร่ม คลายเสื้อผ้า เช็ดตัวด้วยน้ำ และรีบบอกผู้ใหญ่', 'ให้วิ่งต่อจนจบเกม', 'ห่มผ้าหนา ๆ', 'ให้ดื่มน้ำอัดลมแล้วกลับไปเล่น', 'ลมแดดอันตรายมาก ต้องลดความร้อนในร่างกายและเรียกผู้ใหญ่ทันที'],
  ['high', 'ปฐมพยาบาลเลือดกำเดาไหลที่ถูกต้อง คือข้อใด?', 'นั่งก้มหน้าเล็กน้อย บีบปีกจมูกประมาณ 10 นาที', 'นอนหงายเงยหน้า', 'ยัดกระดาษลึก ๆ แล้ววิ่งต่อ', 'สั่งน้ำมูกแรง ๆ', 'ก้มหน้าเล็กน้อยกันเลือดไหลลงคอ ถ้าไม่หยุดใน 20 นาทีให้ไปพบแพทย์'],
  ['high', 'แผลถลอกเล็กน้อย ควรทำอย่างไรเป็นอย่างแรก?', 'ล้างแผลด้วยน้ำสะอาด', 'ทาด้วยยาสีฟัน', 'ปล่อยให้สกปรก', 'เป่าด้วยปาก', 'ล้างแผลด้วยน้ำสะอาด แล้วใส่ยาและปิดแผลให้สะอาด'],
  ['high', 'ข้อเท้าแพลงช่วงแรก ควรปฐมพยาบาลอย่างไร?', 'พัก ประคบเย็น และยกเท้าให้สูง', 'นวดแรง ๆ ทันที', 'ประคบร้อนทันที', 'วิ่งต่อให้หายเอง', 'ช่วง 1–2 วันแรกประคบเย็นช่วยลดบวม ถ้าปวดมากให้ไปพบแพทย์'],
  ['high', 'ทำไมเวลาออกกำลังกายเราหายใจเร็วขึ้น?', 'ร่างกายต้องการออกซิเจนมากขึ้น', 'เพราะหิว', 'เพราะง่วง', 'เพราะหนาว', 'กล้ามเนื้อใช้ออกซิเจนมากขึ้น ปอดจึงทำงานหนักขึ้น'],
  ['high', 'อวัยวะใดกรองของเสียออกจากเลือดเป็นปัสสาวะ?', 'ไต', 'ปอด', 'หัวใจ', 'กระเพาะอาหาร', 'ไตกรองของเสียออกจากเลือด ดื่มน้ำให้พอช่วยให้ไตทำงานดี'],
  ['high', 'กระดูกทำหน้าที่อะไร?', 'ค้ำจุนร่างกายและปกป้องอวัยวะภายใน', 'ย่อยอาหาร', 'สูบฉีดเลือด', 'ผลิตน้ำลาย', 'เช่น กะโหลกปกป้องสมอง ซี่โครงปกป้องหัวใจและปอด'],
  ['high', 'กิจกรรมใดช่วยเสริมให้กระดูกแข็งแรง?', 'กระโดดเชือกหรือวิ่ง', 'นั่งดูทีวี', 'นอนเล่นมือถือ', 'นั่งรถ', 'การกระโดดและวิ่งมีแรงกระแทกพอดี ช่วยให้กระดูกแข็งแรง'],
  ['high', 'ช่วงวัยใดที่ร่างกายสะสมความแข็งแรงของกระดูกได้ดีมาก?', 'วัยเด็กและวัยรุ่น', 'วัยชรา', 'ไม่มีวัยไหนเลย', 'หลังอายุ 60 ปี', 'วัยเด็กและวัยรุ่นคือช่วงสร้างกระดูก ดื่มนมและขยับทุกวันจึงสำคัญมาก'],
  ['high', 'นอนหลับพักผ่อนเพียงพอช่วยเรื่องใด?', 'ช่วยการเจริญเติบโตและความจำ', 'ทำให้ฟันผุ', 'ทำให้ปวดท้อง', 'ทำให้ขาดน้ำ', 'ขณะหลับร่างกายหลั่งฮอร์โมนช่วยการเจริญเติบโต และสมองจัดเก็บความจำ'],
  ['high', 'เล่นมือถือก่อนนอน มีผลอย่างไร?', 'อาจทำให้หลับยากขึ้น', 'ช่วยให้หลับเร็วขึ้น', 'ทำให้ตัวสูงขึ้น', 'ไม่มีผลใด ๆ', 'แสงจากจอทำให้สมองตื่นตัว ควรเลิกเล่นจอก่อนนอนอย่างน้อย 30 นาที'],
  ['high', 'ข้อใดเป็นการตั้งเป้าหมายออกกำลังกายที่ดี?', 'ชัดเจนและทำได้จริง เช่น ขยับวันละ 30 นาที 5 วัน', 'วิ่ง 10 กิโลเมตรทุกวันตั้งแต่วันแรก', 'ไม่ต้องมีเป้าหมาย', 'ทำเฉพาะวันที่ครูดู', 'เป้าที่ทำได้จริงช่วยให้ทำต่อเนื่อง แล้วค่อยเพิ่มทีละนิด'],
  ['high', 'ข้อใดถูกต้องเรื่องความปลอดภัยในการเล่นกีฬา?', 'แต่งกายเหมาะสมและตรวจสนามก่อนเล่น', 'ใส่รองเท้าแตะวิ่งแข่ง', 'เล่นต่อทั้งที่บาดเจ็บ', 'ไม่ต้องอบอุ่นร่างกาย', 'เตรียมตัวและตรวจสถานที่ก่อนเล่น ช่วยลดการบาดเจ็บ'],
  ['high', 'ดื่มน้ำหวานหรือน้ำอัดลมบ่อย ๆ เสี่ยงต่อปัญหาใด?', 'ฟันผุ', 'สายตาดีขึ้น', 'กระดูกแข็งแรงขึ้น', 'นอนหลับดีขึ้น', 'น้ำตาลในเครื่องดื่มทำให้เกิดกรดกัดฟัน ฟันจึงผุง่าย'],
  ['high', 'ข้อใดเป็นการเลือกที่ช่วยลดน้ำตาล?', 'เลือกนมจืดแทนนมรสหวาน', 'เติมน้ำตาลในก๋วยเตี๋ยว 3 ช้อน', 'ดื่มชานมไข่มุกทุกวัน', 'กินลูกอมแทนผลไม้', 'นมจืดยังได้แคลเซียมเท่าเดิม แต่ไม่มีน้ำตาลเพิ่ม'],
  ['high', 'อาหารหมู่ใดให้วิตามินและแร่ธาตุเป็นหลัก?', 'ผักและผลไม้', 'น้ำมัน', 'ข้าวขาว', 'น้ำตาล', 'ผักและผลไม้หลากสีให้วิตามิน แร่ธาตุ และใยอาหาร'],
  ['high', 'กินเค็มหรือโซเดียมมากเป็นประจำ ส่งผลอย่างไรในระยะยาว?', 'เสี่ยงความดันโลหิตสูงและโรคไต', 'ทำให้สูงเร็ว', 'ทำให้สายตาดี', 'ไม่มีผลอะไร', 'ลดน้ำปลา ซอส และขนมกรุบกรอบ ช่วยลดโซเดียม'],
  ['high', 'การล้างมือ 7 ขั้นตอน ขั้นสุดท้ายคือข้อใด?', 'ถูรอบข้อมือ', 'ฝ่ามือถูฝ่ามือ', 'ถูนิ้วหัวแม่มือ', 'ฝ่ามือถูหลังมือ', 'ขั้นที่ 7 คือถูรอบข้อมือทั้งสองข้าง แล้วล้างน้ำให้สะอาด'],
  ['high', 'เชื้อโรคจากมือเข้าสู่ร่างกายได้อย่างไร?', 'จับสิ่งของแล้วมาจับตา จมูก หรือปาก', 'ผ่านการมองเห็น', 'ผ่านเสียงพูด', 'ผ่านเงา', 'จึงควรล้างมือบ่อย ๆ และไม่ขยี้ตาหรือแคะจมูก'],
  ['high', 'ไข้หวัดติดต่อทางใดเป็นหลัก?', 'ละอองน้ำมูก น้ำลาย จากการไอจาม', 'ยุงกัด', 'ดูโทรทัศน์', 'แสงแดด', 'ปิดปากเวลาไอจาม ล้างมือ และพักที่บ้านเมื่อป่วย'],
  ['high', 'ไข้เลือดออกมีสัตว์ใดเป็นพาหะ?', 'ยุงลาย', 'แมลงวัน', 'หนู', 'แมว', 'ยุงลายเป็นพาหะนำโรคไข้เลือดออก'],
  ['high', 'ป้องกันยุงลายวางไข่ได้อย่างไร?', 'ปิดฝาภาชนะใส่น้ำ และเทน้ำขังทิ้ง', 'เปิดฝาโอ่งไว้', 'เก็บยางรถเก่าไว้กลางแจ้ง', 'ปล่อยน้ำขังในจานรองกระถาง', 'ยุงลายวางไข่ในน้ำนิ่งที่ใส ไม่มีน้ำขังก็ไม่มียุง'],
  ['high', 'ค่าฝุ่น PM2.5 สูงมาก ควรทำอย่างไร?', 'ลดกิจกรรมกลางแจ้ง ออกกำลังกายในอาคาร', 'วิ่งระยะไกลกลางแจ้ง', 'เปิดหน้าต่างทั้งวัน', 'เผาขยะ', 'ฝุ่นเล็กมากเข้าปอดได้ลึก วันฝุ่นเยอะให้ขยับในบ้านแทน'],
  ['high', 'หน้ากากแบบใดกรองฝุ่น PM2.5 ได้ดีกว่า?', 'หน้ากาก N95 ที่ใส่แนบหน้า', 'ผ้าเช็ดหน้าบาง ๆ', 'ผ้าพันคอหลวม ๆ', 'ไม่ต้องใส่ก็ได้', 'หน้ากากต้องแนบหน้า ไม่มีช่องว่าง จึงกรองฝุ่นได้ดี'],
  ['high', 'รู้สึกเครียดก่อนสอบ วิธีใดช่วยได้?', 'หายใจช้า ๆ ลึก ๆ และพักสั้น ๆ', 'อดนอนทั้งคืน', 'ไม่กินข้าว', 'ดื่มเครื่องดื่มชูกำลัง', 'หายใจลึก ๆ พักเป็นช่วง และนอนให้พอ ช่วยให้สมองพร้อม'],
  ['high', 'ถูกกลั่นแกล้งในโลกออนไลน์ ควรทำอย่างไร?', 'ไม่ตอบโต้ เก็บหลักฐาน และบอกผู้ใหญ่ที่ไว้ใจ', 'แกล้งกลับให้หนักกว่า', 'เก็บไว้คนเดียว', 'แชร์ต่อให้เพื่อนดู', 'ผู้ใหญ่ช่วยแจ้งและบล็อกได้ ไม่ต้องเผชิญคนเดียว'],
  ['high', 'ข้อมูลใดไม่ควรโพสต์ลงอินเทอร์เน็ต?', 'ที่อยู่บ้านและเบอร์โทรศัพท์', 'รูปวาดการ์ตูน', 'ชื่อหนังสือที่ชอบ', 'สีที่ชอบ', 'ข้อมูลส่วนตัวอาจถูกคนไม่หวังดีนำไปใช้'],
  ['high', 'หกล้มศีรษะกระแทกแรง แล้วปวดหัวหรืออาเจียน ควรทำอย่างไร?', 'รีบบอกผู้ใหญ่และไปพบแพทย์', 'นอนพักเฉย ๆ ไม่บอกใคร', 'กลับไปเล่นต่อ', 'กินขนมแล้วจะหายเอง', 'อาการแบบนี้อาจอันตราย ต้องให้แพทย์ตรวจ'],
  ['high', 'อาการใดบอกว่าควรหยุดออกกำลังกายทันที?', 'เจ็บหน้าอก เวียนหัว หายใจไม่ทัน', 'เหงื่อออกนิดหน่อย', 'หัวใจเต้นเร็วขึ้นเล็กน้อย', 'รู้สึกสนุก', 'หยุดพักแล้วบอกผู้ใหญ่ทันที'],
  ['high', 'ออกกำลังกายระดับปานกลาง สังเกตได้อย่างไร?', 'หายใจเร็วขึ้น ยังพูดได้แต่ร้องเพลงไม่ไหว', 'หายใจปกติเหมือนนั่งเฉย ๆ', 'พูดไม่ได้เลยแม้แต่คำเดียว', 'ง่วงจนหลับ', 'ใช้ "การพูด" ทดสอบความหนักได้ง่าย ๆ'],
  ['high', 'วิ่งระยะไกลด้วยความเร็วสม่ำเสมอ พัฒนาสมรรถภาพด้านใดมากที่สุด?', 'ความอดทนของหัวใจและปอด', 'ความอ่อนตัว', 'ความแข็งแรงของนิ้วมือ', 'การมองเห็น', 'วิ่งต่อเนื่องช่วยให้หัวใจและปอดทำงานได้นานขึ้น'],
  ['high', 'ท่ากระดาน (แพลงก์) ช่วยเสริมความแข็งแรงส่วนใดเป็นหลัก?', 'กล้ามเนื้อแกนกลางลำตัว ท้องและหลัง', 'กล้ามเนื้อใบหน้า', 'นิ้วเท้า', 'ลิ้น', 'แกนกลางลำตัวแข็งแรง ช่วยให้ทรงตัวดีและหลังไม่ปวด'],
  ['high', 'ทำไมต้องคลายอุ่นหลังออกกำลังกาย?', 'ให้หัวใจและการหายใจค่อย ๆ กลับสู่ปกติ', 'ให้เหนื่อยมากขึ้น', 'ให้หิวเร็วขึ้น', 'ไม่มีประโยชน์', 'เดินช้า ๆ และยืดเหยียด 5 นาที ก่อนหยุดพัก'],
  ['high', 'ดื่มน้ำระหว่างออกกำลังกายควรดื่มอย่างไร?', 'จิบทีละน้อยแต่บ่อย ๆ', 'ไม่ดื่มเลยจนจบ', 'ดื่มน้ำอัดลมแทน', 'ดื่มรวดเดียวทีเดียวเยอะ ๆ', 'จิบบ่อย ๆ ช่วยทดแทนเหงื่อโดยไม่จุกท้อง'],
  ['high', 'อาหารเช้าสำคัญอย่างไร?', 'ให้พลังงานและช่วยให้มีสมาธิเรียน', 'ทำให้ง่วงทั้งวัน', 'ไม่สำคัญเลย', 'ทำให้ฟันแข็ง', 'ร่างกายอดอาหารมาทั้งคืน อาหารเช้าช่วยเติมพลัง'],
  ['high', 'ข้อใดเป็นพฤติกรรมเสี่ยงต่อสุขภาพ?', 'เล่นมือถือในที่มืดจนดึก', 'ดื่มน้ำเปล่า', 'ออกกำลังกายสม่ำเสมอ', 'ล้างมือก่อนกินอาหาร', 'นอนดึกและดูจอในที่มืด ทำให้ตาล้าและนอนไม่พอ'],
  ['high', 'บุหรี่ไฟฟ้ามีผลต่อร่างกายอย่างไร?', 'มีสารเสพติดนิโคตินและเป็นอันตรายต่อปอด', 'ช่วยให้ปอดแข็งแรง', 'ปลอดภัยเหมือนน้ำเปล่า', 'ไม่มีสารอันตรายเลย', 'บุหรี่ไฟฟ้ามีนิโคตินที่ทำให้ติด และสารเคมีที่ทำร้ายปอด'],
  ['high', 'เพื่อนชวนลองบุหรี่หรือบุหรี่ไฟฟ้า ควรทำอย่างไร?', 'ปฏิเสธอย่างสุภาพแล้วเดินออกมา', 'ลองนิดเดียว', 'ลองเพื่อให้เพื่อนยอมรับ', 'เก็บเป็นความลับ', 'ปฏิเสธได้ เช่น "ไม่เอา ขอบใจ" แล้วชวนทำอย่างอื่นแทน'],
  ['high', 'สุขบัญญัติแห่งชาติมีกี่ข้อ?', '10 ข้อ', '3 ข้อ', '5 ข้อ', '20 ข้อ', 'สุขบัญญัติแห่งชาติ 10 ประการ เป็นข้อปฏิบัติเพื่อสุขภาพที่ดี'],
  ['high', 'ข้อใดคือการมีน้ำใจนักกีฬา?', 'ยอมรับผลแพ้ชนะและให้เกียรติคู่แข่ง', 'โวยวายเมื่อแพ้', 'เยาะเย้ยคู่แข่ง', 'เล่นนอกกติกาเพื่อชนะ', 'น้ำใจนักกีฬาทำให้ทุกคนสนุกและปลอดภัย'],
  ['high', 'ก่อนกินยาทุกครั้ง ควรทำอย่างไร?', 'อ่านฉลากและกินตามที่ผู้ใหญ่หรือแพทย์บอก', 'กินยาของเพื่อน', 'กินเพิ่มเป็นสองเท่าให้หายเร็ว', 'กินยาที่หมดอายุแล้ว', 'ใช้ยาให้ถูกคน ถูกขนาด ถูกเวลา และให้ผู้ใหญ่ดูแลเสมอ'],
  ['high', 'นั่งใช้คอมพิวเตอร์ท่าใดถูกต้อง?', 'จออยู่ระดับสายตาหรือต่ำกว่าเล็กน้อย หลังพิงพนัก', 'ก้มหน้าชิดจอ', 'นั่งบิดตัวไปด้านข้าง', 'ยกจอสูงจนต้องเงยหน้า', 'ท่าที่ถูกช่วยลดปวดคอ ปวดหลัง และตาล้า']
];

/* อีเวนต์ตั้งต้นปีการศึกษา 2569 ครูแก้วัน ภารกิจ และสติกเกอร์ในแท็บอีเวนต์ได้ */
var EXAMPLE_EVENTS = [
  ['sport69', 'ขยับวันกีฬาแห่งชาติ', '14/12/2569', '20/12/2569', '16 ธันวาคม วันกีฬาแห่งชาติ มาขยับให้ครบทั้งสัปดาห์!',
    'ขยับรวม 100 นาที', 'นาทีรวม', 100, 'ขยับให้ได้ 4 วัน', 'วันที่ขยับ', 4, 'เล่นกีฬากับคนในบ้าน 1 ครั้ง', 'กดทำเอง', 1, '🏅 นักกีฬาวันกีฬาแห่งชาติ 2569', 'ใช่'],
  ['newyear70', 'ขยับรับปีใหม่', '28/12/2569', '3/1/2570', 'เริ่มปีใหม่ด้วยร่างกายแข็งแรง',
    'ขยับให้ได้ 5 วัน', 'วันที่ขยับ', 5, 'ทำภารกิจประจำวัน 5 ครั้ง', 'ภารกิจประจำวัน', 5, 'ตั้งเป้าสุขภาพปีใหม่ 1 ข้อ แล้วบอกคนในบ้าน', 'กดทำเอง', 1, '🎆 ขยับรับปีใหม่ 2570', 'ใช่'],
  ['kids70', 'เทศกาลวันเด็ก', '4/1/2570', '10/1/2570', 'วันเด็กปีนี้ ชวนพ่อแม่มาเล่นด้วยกัน',
    'ขยับรวม 100 นาที', 'นาทีรวม', 100, 'เล่นเกมสมัยพ่อแม่ 1 เกม เช่น ตั้งเต กระโดดยาง มอญซ่อนผ้า', 'กดทำเอง', 1, 'ตอบคำถามสุขภาพ 3 ข้อ', 'ตอบคำถาม', 3, '🎈 ลูกโป่งวันเด็ก 2570', 'ใช่'],
  ['love70', 'รักตัวเอง รักสุขภาพ', '8/2/2570', '14/2/2570', 'รักตัวเองด้วยการดูแลสุขภาพทุกวัน',
    'ทำภารกิจประจำวัน 5 ครั้ง', 'ภารกิจประจำวัน', 5, 'ขยับให้ได้ 4 วัน', 'วันที่ขยับ', 4, 'บอกขอบคุณหรือบอกรักคนในบ้าน 1 คน', 'กดทำเอง', 1, '💗 รักสุขภาพ 2570', 'ใช่'],
  ['songkran70', 'สงกรานต์ดื่มน้ำคลายร้อน', '10/4/2570', '16/4/2570', 'อากาศร้อน ขยับในที่ร่ม ดื่มน้ำบ่อย ๆ เล่นน้ำต้องมีผู้ใหญ่ดูแล',
    'ขยับให้ได้ 3 วัน', 'วันที่ขยับ', 3, 'ทำภารกิจประจำวัน 3 ครั้ง', 'ภารกิจประจำวัน', 3, 'ดื่มน้ำเปล่าให้ครบ 6–8 แก้ว 1 วัน', 'กดทำเอง', 1, '💦 สงกรานต์สดชื่น 2570', 'ใช่'],
  ['term70', 'เปิดเทอมใหม่ ขยับใหม่', '17/5/2570', '23/5/2570', 'เปิดเทอมแล้ว กลับมาขยับให้ไฟลุกอีกครั้ง',
    'ขยับให้ได้ 5 วัน', 'วันที่ขยับ', 5, 'ทำภารกิจประจำวัน 5 ครั้ง', 'ภารกิจประจำวัน', 5, 'จัดกระเป๋าและเตรียมชุดพละเอง', 'กดทำเอง', 1, '🎒 เปิดเทอมใหม่ 2570', 'ใช่']
];
var MAX_STRIKES = 5;
var LOCK_SECONDS = 600;

/* ---------- รับคำขอจากหน้าเว็บ (แบบโปรแกรมกระโดดเชือก) ----------
 * หน้าเว็บ index.html ส่ง POST เป็น JSON { action, ... }
 * ใครมีลิงก์ก็ส่งได้ จึงตรวจตั๋วเข้าระบบทุกครั้ง ยกเว้นการสมัครและเข้าสู่ระบบ */
function doGet() {
  return json_({ ok: true, app: 'healthbook', version: APP_VERSION });
}

function doPost(e) {
  var req;
  try {
    req = JSON.parse((e && e.postData && e.postData.contents) || '{}');
  } catch (err) {
    return json_(FQ.fail('ข้อมูลไม่ถูกต้อง', 'BAD'));
  }
  return json_(route_(req && typeof req === 'object' ? req : {}));
}

function route_(req) {
  switch (req.action) {
    case 'ping': return safe_(function () {
      var st = readSettings_();
      return { ok: true, app: 'healthbook', version: APP_VERSION, schoolName: st.schoolName, sidLen: st.sidLen, today: todayKey_() };
    });
    case 'register': return signIn_(register_, req);
    case 'login': return signIn_(login_, req);
    case 'status': return apiStatus_(req);
    case 'submit': return apiSubmit_(req);
    case 'delete': return apiDelete_(req);
    case 'mission': return apiMission_(req);
    case 'quest': return apiQuest_(req);
    case 'clip': return apiClip_(req);
    case 'proof': return FQ.fail('ตอนนี้เปลี่ยนจากถ่ายรูปเป็นดูคลิปแล้ว ปิดแอปแล้วเปิดใหม่เพื่ออัปเดตนะ', 'OLD_APP');
    case 'quiz': return apiExtra_(req, 'quiz');
    case 'event': return apiExtra_(req, 'event');
    case 'dust': return apiExtra_(req, 'dust');
    case 'profile': return apiProfile_(req);
    case 'photo': return apiPhoto_(req, false);
    case 'photodel': return apiPhoto_(req, true);
    case 'myphoto': return apiMyPhoto_(req);
    case 'calendar': return apiCalendar_(req);
    case 'story': return apiStory_(req);
    case 'card': return apiCard_(req, false);
    case 'cheer': return apiCard_(req, true);
    case 'game': return apiGame_(req);
    case 'gboard': return apiGameBoard_(req);
    case 'gvisit': return apiGameVisit_(req, false);
    case 'glike': return apiGameVisit_(req, true);
    case 'pet': return apiPet_(req);
    case 'tphotos': return teacherApi_(req, teacherPhotos_);
    case 'tphoto': return teacherApi_(req, teacherPhoto_);
    case 'tpetnames': return teacherApi_(req, teacherPetNames_);
    case 'tdust': return teacherApi_(req, teacherDust_);
    case 'tpetname': return teacherApi_(req, teacherPetName_);
    case 'tlogin': return teacherLogin_(req);
    case 'tdash': return teacherApi_(req, teacherDash_);
    case 'tfit': return teacherApi_(req, teacherFitness_);
    case 'tfitsave': return teacherApi_(req, teacherFitnessSave_);
    case 'tstudents': return teacherApi_(req, teacherStudents_);
    case 'tsid': return teacherApi_(req, teacherSid_);
    case 'tstudent': return teacherApi_(req, teacherStudent_);
    case 'tpin': return teacherApi_(req, teacherPin_);
    case 'tactive': return teacherApi_(req, teacherActive_);
    case 'tedit': return teacherApi_(req, teacherEdit_);
    case 'tcenter': return teacherApi_(req, teacherCenter_);
    case 'tcentersave': return teacherApi_(req, teacherCenterSave_);
    case 'tboard': return teacherApi_(req, teacherBoard_);
    default: return FQ.fail('ไม่รู้จักคำสั่งนี้', 'BAD');
  }
}

function json_(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON);
}

function withLock_(fn) {
  var lock = LockService.getScriptLock();
  lock.waitLock(20000);
  try {
    return fn();
  } finally {
    lock.releaseLock();
  }
}

/* ค่าที่หน้าเว็บใช้: ตั้งค่ากับเควสบ้าน (ข้อมูลนักเรียนอ่านตอนตรวจตั๋ว) */
function loadApi_() {
  var c = { settings: readSettings_(), quests: readQuests_(), pool: readMissionPool_(), questions: readQuestions_(), events: readEvents_(), dust: readDust_() };
  /* วันฝุ่น: ภารกิจกลางแจ้งของวันนี้สลับเป็นภารกิจในบ้าน (missionFor ดู pool.dustDay) */
  var dv = FQ.dustView(c.dust, todayKey_(), c.settings);
  if (dv && dv.on) c.pool.dustDay = todayKey_();
  return c;
}

/* ---------- ค่าฝุ่น PM2.5 ----------
 * เก็บใน Script Properties คีย์ DUST ดึงใหม่ทุกชั่วโมงจาก autoSummary หรือครูกดดึงเองในโหมดครู */
var AIR4THAI_URLS = ['http://air4thai.pcd.go.th/services/getNewAQI_JSON.php', 'http://air4thai.com/forweb/getAQI_JSON.php'];
function readDust_() {
  try { return JSON.parse(PropertiesService.getScriptProperties().getProperty('DUST') || 'null'); } catch (e) { return null; }
}
function saveDust_(d) {
  PropertiesService.getScriptProperties().setProperty('DUST', JSON.stringify(d));
}
function refreshDust_() {
  var s = readSettings_(), today = todayKey_(), prev = readDust_(), pick = null, err = '';
  if (!s.dustOn) return { ok: false, error: 'โหมดฝุ่นปิดอยู่ (แท็บตั้งค่า)' };
  for (var i = 0; i < AIR4THAI_URLS.length && !pick; i++) {
    try {
      var res = UrlFetchApp.fetch(AIR4THAI_URLS[i], { muteHttpExceptions: true, followRedirects: true });
      if (res.getResponseCode() !== 200) { err = 'Air4Thai ตอบกลับ ' + res.getResponseCode(); continue; }
      pick = FQ.dustPick(JSON.parse(res.getContentText()), s);
      if (!pick) err = 'ไม่พบสถานีที่มีค่าฝุ่นใกล้โรงเรียน (ตรวจพิกัดในแท็บตั้งค่า)';
    } catch (e) {
      err = 'ดึงค่าฝุ่นไม่สำเร็จ: ' + String(e && e.message || e).slice(0, 120);
    }
  }
  var d = FQ.dustMerge(prev, pick, today);
  if (!pick) d.err = err || d.err;
  saveDust_(d);
  return { ok: !!pick, dust: d, error: pick ? '' : d.err };
}

/* สมัครหรือเข้าสู่ระบบ แล้วส่งตั๋วพร้อมข้อมูลดาวกลับไปในครั้งเดียว */
function signIn_(fn, req) {
  return safe_(function () {
    var c = loadApi_();
    var res = withLock_(function () { return fn(req); });
    if (!res.ok) return res;
    var a = auth_(c, { token: res.token });
    if (!a.ok) return a;
    var st = status_(c, a, loadMine_(c, a));
    st.token = res.token;
    return st;
  });
}

function apiStatus_(req) {
  return safe_(function () {
    var c = loadApi_();
    var a = auth_(c, req);
    if (!a.ok) return a;
    return status_(c, a, loadMine_(c, a));
  });
}

/* รหัสจากหน้าเว็บ (สุ่มตอนกดส่ง) ใช้กันบันทึกซ้ำเมื่อเน็ตหลุดแล้วหน้าเว็บส่งใหม่ */
function cidOf_(req) { var c = String((req && req.cid) || ''); return /^[A-Za-z0-9_-]{8,32}$/.test(c) ? c : ''; }
function hasId_(list, id) { for (var i = 0; i < list.length; i++) if (list[i].id === id) return true; return false; }

function apiSubmit_(req) {
  return safe_(function () {
    var c = loadApi_();
    var a = auth_(c, req);
    if (!a.ok) return a;
    var entry = (req && req.entry) || {};
    var snap = readSnap_(a.student.code);
    var lock = LockService.getScriptLock();
    lock.waitLock(20000);
    var mine, plan, cid = cidOf_(req);
    try {
      mine = loadMine_(c, a, snap);
      if (cid && hasId_(mine.logs, cid)) {
        plan = { result: { duplicate: true } };
      } else {
        plan = FQ.planSubmit({ settings: c.settings, klass: a.klass, student: a.student, logs: mine.logs, done: mine.done, extra: mine.extra, events: c.events, entry: entry, todayKey: todayKey_(), id: cid || newId_() });
        if (!plan.ok) return plan;
        writeLog_(mine.lt, plan.rec, nowText_());
        plan.rec.row = mine.lt.sheet.getLastRow();
        mine.logs.push(plan.rec);
      }
    } finally {
      lock.releaseLock();
    }
    var st = status_(c, a, mine);
    st.result = plan.result;
    return st;
  });
}

/* กดทำภารกิจประจำวันแล้ว */
function apiMission_(req) { return apiDone_(req, 'mission'); }
/* กดทำเควสบ้านประจำสัปดาห์แล้ว */
function apiQuest_(req) { return apiDone_(req, 'quest'); }
function apiDone_(req, kind) {
  return safe_(function () {
    var c = loadApi_();
    var a = auth_(c, req);
    if (!a.ok) return a;
    sheet_(TAB.done);
    var snap = readSnap_(a.student.code);
    var lock = LockService.getScriptLock();
    lock.waitLock(20000);
    var mine, plan, cid = cidOf_(req);
    try {
      mine = loadMine_(c, a, snap);
      if (cid && hasId_(mine.done, cid)) {
        plan = { result: { duplicate: true } };
      } else {
        var o = {
          settings: c.settings, klass: a.klass, student: a.student, logs: mine.logs, done: mine.done, pool: c.pool, quests: c.quests,
          extra: mine.extra, events: c.events, todayKey: todayKey_(), entry: (req && req.entry) || {}, id: cid || newId_()
        };
        plan = kind === 'quest' ? FQ.planQuest(o) : FQ.planMission(o);
        if (!plan.ok) return plan;
        writeDone_(mine.dt, plan.rec, nowText_());
        plan.rec.row = mine.dt.sheet.getLastRow();
        mine.done.push(plan.rec);
      }
    } finally {
      lock.releaseLock();
    }
    var st = status_(c, a, mine);
    st.result = plan.result;
    return st;
  });
}

/* ตอบคำถามสุขภาพวันนี้ (kind = quiz) กด "ทำแล้ว" ภารกิจอีเวนต์ (kind = event) หรือดูคลิปครบ (kind = clip) */
function apiClip_(req) { return apiExtra_(req, 'clip'); }
function apiExtra_(req, kind) {
  return safe_(function () {
    var c = loadApi_();
    if (!SpreadsheetApp.getActive().getSheetByName(TAB.extra)) {
      return FQ.fail('ยังใช้ไม่ได้ ให้ครูกดเมนู ' + APP_NAME + ' → 1) ตั้งค่าครั้งแรก', 'SETUP');
    }
    var a = auth_(c, req);
    if (!a.ok) return a;
    var snap = readSnap_(a.student.code);
    var lock = LockService.getScriptLock();
    lock.waitLock(20000);
    var mine, plan, cid = cidOf_(req);
    try {
      mine = loadMine_(c, a, snap);
      if (cid && hasId_(mine.extra, cid)) {
        plan = { result: { duplicate: true } };
      } else {
        var o = {
          settings: c.settings, klass: a.klass, student: a.student, logs: mine.logs, done: mine.done, extra: mine.extra,
          events: c.events, questions: c.questions, pool: c.pool, quests: c.quests, todayKey: todayKey_(), id: cid || newId_(),
          entry: kind === 'quiz' ? { choice: req && req.choice } : kind === 'clip' ? ((req && req.entry) || {}) : { event: req && req.event, task: req && req.task },
          dust: c.dust
        };
        plan = kind === 'quiz' ? FQ.planQuiz(o) : kind === 'clip' ? FQ.planClip(o) : kind === 'dust' ? FQ.planDust(o) : FQ.planEvent(o);
        if (!plan.ok) return plan;
        writeExtra_(mine.xt, plan.rec, nowText_());
        plan.rec.row = mine.xt.sheet.getLastRow();
        mine.extra.push(plan.rec);
      }
    } finally {
      lock.releaseLock();
    }
    var st = status_(c, a, mine);
    st.result = plan.result;
    return st;
  });
}

/* ---------- ไฟล์รูป ----------
 * ตอนนี้รับเฉพาะรูปจริงในโปรไฟล์ (รูปและวิดีโอหลักฐานแบบเก่าเลิกใช้แล้ว ไฟล์เก่าระบบลบเองตามกำหนด) */
var PROOF_MIME = {
  photo: { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' }
};

function looksLike_(b, mime) {
  var u = function (i) { return (b[i] + 256) % 256; };
  var asc = function (i, n) { var s = ''; for (var k = 0; k < n; k++) s += String.fromCharCode(u(i + k)); return s; };
  if (b.length < 12) return false;
  if (mime === 'image/jpeg') return u(0) === 0xFF && u(1) === 0xD8;
  if (mime === 'image/png') return u(0) === 0x89 && asc(1, 3) === 'PNG';
  if (mime === 'image/webp') return asc(0, 4) === 'RIFF' && asc(8, 4) === 'WEBP';
  if (mime === 'video/webm') return u(0) === 0x1A && u(1) === 0x45 && u(2) === 0xDF && u(3) === 0xA3;
  return asc(4, 4) === 'ftyp';   /* mp4 และ mov */
}

/* โฟลเดอร์ "สมุดสุขภาพ-หลักฐาน" ใน Drive ของครู (ส่วนตัว) เก็บรูปและวิดีโอแบบเก่า ใช้ตอนลบไฟล์เก่า */
function proofFolder_() {
  var props = PropertiesService.getScriptProperties();
  var id = props.getProperty('PROOF_FOLDER');
  if (id) {
    try {
      var f = DriveApp.getFolderById(id);
      if (!f.isTrashed()) return f;
    } catch (e) {}
  }
  var folder = DriveApp.createFolder(APP_NAME + '-หลักฐาน');
  props.setProperty('PROOF_FOLDER', folder.getId());
  return folder;
}

function fileIdOf_(url) {
  var m = /\/d\/([\w-]{10,})/.exec(String(url || '')) || /[?&]id=([\w-]{10,})/.exec(String(url || ''));
  return m ? m[1] : '';
}

/* ลบไฟล์หลักฐานที่เก่ากว่าที่ตั้งไว้ (all = ลบทั้งหมด ตอนจบภาคเรียน) คืนจำนวนไฟล์ที่ลบ
 * แต้มไม่หาย แถวในแท็บภารกิจที่ทำยังอยู่ ช่องไฟล์เปลี่ยนเป็น "ลบแล้ว" */
function cleanupProof_(all) {
  if (!SpreadsheetApp.getActive().getSheetByName(TAB.done)) return 0;
  var s = readSettings_(), today = todayKey_(), n = 0;
  var t = table_(TAB.done, H.done);
  doneFromTable_(t).forEach(function (m) {
    var id = fileIdOf_(m.file);
    if (!id) return;
    var keep = m.proof === 'วิดีโอ' ? s.videoKeepDays : s.photoKeepDays;
    if (!all && FQ.dayNum(today) - FQ.dayNum(m.date) < keep) return;
    try { DriveApp.getFileById(id).setTrashed(true); } catch (e) {}
    setCells_(t, m.row, [['ไฟล์', 'ลบแล้ว ' + today]]);
    n++;
  });
  return n;
}

function apiDelete_(req) {
  return safe_(function () {
    var c = loadApi_();
    var a = auth_(c, req);
    if (!a.ok) return a;
    var snap = readSnap_(a.student.code);
    var lock = LockService.getScriptLock();
    lock.waitLock(20000);
    var mine;
    try {
      mine = loadMine_(c, a, snap);
      var okDates = FQ.allowedDates(todayKey_(), c.settings.backfillDays);
      var d = FQ.findDeletable(mine.logs, req && req.id, okDates);
      if (!d.ok) return d;
      mine.lt.sheet.deleteRow(d.log.row);
      mine.logs = mine.logs.filter(function (l) { return l !== d.log; });
    } finally {
      lock.releaseLock();
    }
    return status_(c, a, mine);
  });
}

/* ---------- โปรไฟล์ ----------
 * เด็กแก้ได้เฉพาะของตัวเอง เลือกจากรายการ (ยกเว้นชื่อเล่นที่มีตัวกรอง) ครูแก้หรือล็อกได้ในแท็บนักเรียน */
function needProfileCols_(t) {
  for (var i = 0; i < H.rosterOpt.length; i++) {
    if (t.idx[H.rosterOpt[i]] === undefined) return FQ.fail('ยังแต่งโปรไฟล์ไม่ได้ ให้ครูกดเมนู ' + APP_NAME + ' → 1) ตั้งค่าครั้งแรก', 'SETUP');
  }
  return null;
}
var PROFILE_CELLS = { nick: SC.nick, nickAt: SC.nickAt, outfit: SC.outfit, color: SC.color, sports: SC.sports, goal: SC.goal, motto: SC.motto, pins: SC.pins };

function apiProfile_(req) {
  return safe_(function () {
    var c = loadApi_();
    var a = auth_(c, req);
    if (!a.ok) return a;
    var mine = loadMine_(c, a);
    var xp = FQ.xpStatus(mine.logs, mine.done, a.klass, c.settings, todayKey_(), { extra: mine.extra, events: c.events });
    var res = withLock_(function () {
      var t = table_(TAB.roster, H.roster, H.rosterOpt), miss = needProfileCols_(t);
      if (miss) return miss;
      var st = findStudentRow_(t, a.student.sid);
      var plan = FQ.planProfile((req && req.entry) || {}, st, xp, todayKey_());
      if (!plan.ok) return plan;
      var pairs = [];
      Object.keys(plan.cells).forEach(function (k) {
        var v = plan.cells[k];
        pairs.push([PROFILE_CELLS[k], k === 'nickAt' ? "'" + v : cleanText_(v, 200)]);
        a.student[k] = v;
      });
      if (pairs.length) setCells_(t, st.row, pairs);
      return { ok: true };
    });
    if (!res.ok) return res;
    return status_(c, a, mine);
  });
}

/* โฟลเดอร์รูปโปรไฟล์ (ส่วนตัวใน Drive ของครู แยกจากหลักฐาน) */
function photoFolder_() {
  var props = PropertiesService.getScriptProperties(), id = props.getProperty('PHOTO_FOLDER');
  if (id) {
    try { var f = DriveApp.getFolderById(id); if (!f.isTrashed()) return f; } catch (e) {}
  }
  var folder = DriveApp.createFolder(APP_NAME + '-รูปโปรไฟล์');
  props.setProperty('PHOTO_FOLDER', folder.getId());
  return folder;
}
var PHOTO_MAX = 400 * 1024;
function trashFile_(url) { var id = fileIdOf_(url); if (id) { try { DriveApp.getFileById(id).setTrashed(true); } catch (e) {} } }

/* ส่งรูปจริง (del = ลบรูป) เห็นเฉพาะตัวเองกับครู ครูต้องอนุมัติ */
function apiPhoto_(req, del) {
  return safe_(function () {
    var c = loadApi_();
    var a = auth_(c, req);
    if (!a.ok) return a;
    var blob = null, file = null;
    if (!del) {
      var mime = String((req && req.mime) || '').toLowerCase().split(';')[0].trim();
      var ext = PROOF_MIME.photo[mime];
      var data = String((req && req.data) || '').replace(/^data:[^,]*,/, '');
      if (!ext || !data) return FQ.fail('รับเฉพาะไฟล์รูป', 'BAD_FILE');
      if (data.length > Math.ceil(PHOTO_MAX * 4 / 3) + 8) return FQ.fail('รูปใหญ่เกินไป', 'TOO_BIG');
      var bytes;
      try { bytes = Utilities.base64Decode(data); } catch (e) { return FQ.fail('ไฟล์เสีย ลองใหม่', 'BAD_FILE'); }
      if (!bytes.length || bytes.length > PHOTO_MAX || !looksLike_(bytes, mime)) return FQ.fail('ไฟล์ไม่ใช่รูป ลองใหม่', 'BAD_FILE');
      var name = [a.klass.id.replace(/[\/\s]/g, '-'), 'เลขที่' + (a.student.no || 0), a.student.sid, 'โปรไฟล์'].join('_') + '.' + ext;
      blob = Utilities.newBlob(bytes, mime, name);
    }
    var res = withLock_(function () {
      var t = table_(TAB.roster, H.roster, H.rosterOpt), miss = needProfileCols_(t);
      if (miss) return miss;
      var st = findStudentRow_(t, a.student.sid);
      if (st.photo) trashFile_(st.photo);
      if (del) {
        setCells_(t, st.row, [[SC.photo, ''], [SC.photoOk, '']]);
        a.student.photo = ''; a.student.photoOk = '';
      } else {
        file = photoFolder_().createFile(blob);
        setCells_(t, st.row, [[SC.photo, file.getUrl()], [SC.photoOk, 'รอ']]);
        a.student.photo = file.getUrl(); a.student.photoOk = 'รอ';
      }
      return { ok: true };
    });
    if (!res.ok) return res;
    return status_(c, a, loadMine_(c, a));
  });
}

function photoData_(url) {
  var id = fileIdOf_(url);
  if (!id) return '';
  try {
    var b = DriveApp.getFileById(id).getBlob();
    var bytes = b.getBytes();
    if (bytes.length > PHOTO_MAX) return '';
    return 'data:' + (b.getContentType() || 'image/jpeg') + ';base64,' + Utilities.base64Encode(bytes);
  } catch (e) { return ''; }
}
/* ปฏิทินขยับ + สถิติของฉัน (แยกจากข้อมูลหลัก โหลดเฉพาะตอนเปิดหน้าปฏิทินหรือการ์ดของฉัน) */
function apiCalendar_(req) {
  return safe_(function () {
    var c = loadApi_();
    var a = auth_(c, req);
    if (!a.ok) return a;
    var mine = loadMine_(c, a);
    return {
      ok: true,
      calendar: FQ.calendarView({ settings: c.settings, klass: a.klass, student: a.student, logs: mine.logs, done: mine.done || [], extra: mine.extra || [], events: c.events || [], todayKey: todayKey_() })
    };
  });
}

/* 6B-25 สรุปสัปดาห์ที่แล้วของฉัน (โหลดแยก เปิดตอนดูสตอรี่เท่านั้น) */
function apiStory_(req) {
  return safe_(function () {
    var c = loadApi_();
    var a = auth_(c, req);
    if (!a.ok) return a;
    var mine = loadMine_(c, a), r = null;
    try { r = gameRowOf_(gameSheet_(false), a.student.sid); } catch (e) {}
    return {
      ok: true,
      story: FQ.storyView({ settings: c.settings, klass: a.klass, student: a.student, logs: mine.logs, done: mine.done || [], extra: mine.extra || [], events: c.events || [], todayKey: todayKey_(), center: r ? FQ.centerParse(r.layout) : null })
    };
  });
}

/* รูปจริงของตัวเอง (แยกจากข้อมูลหลัก ไม่ให้หน้าแรกโหลดช้า) */
function apiMyPhoto_(req) {
  return safe_(function () {
    var a = authToken_(req && req.token);
    if (!a.ok) return a;
    var st = a.student;
    return { ok: true, state: st.photo ? (st.photoOk === 'อนุมัติ' ? 'approved' : 'pending') : 'none', data: st.photo ? photoData_(st.photo) : '' };
  });
}

/* การ์ดนักกีฬาของเพื่อน (เปิดได้เฉพาะคนที่อยู่ในตารางอันดับ) และส่งกำลังใจ 👏 วันละครั้งต่อคน */
var CHEERS_PER_DAY = 20;
function cardKey_(sid) { return hmac_('card|' + sid).slice(0, 12); }
function apiCard_(req, cheer) {
  return safe_(function () {
    var c = loadApi_();
    var a = auth_(c, req);
    if (!a.ok) return a;
    var key = String((req && req.card) || ''), b = readBoard_(), hit = null;
    if (/^[0-9a-f]{12}$/.test(key) && b && b.leagues) {
      Object.keys(b.leagues).forEach(function (k) { (b.leagues[k] || []).forEach(function (e) { if (e.k === key) hit = e; }); });
    }
    if (!hit) return FQ.fail('ไม่พบการ์ดนี้ ลองเปิดตารางอันดับใหม่', 'NOT_FOUND');
    var target = null;
    readRoster_().forEach(function (st) { if (st.sid === hit.c) target = st; });
    if (!target || !target.active) return FQ.fail('ไม่พบการ์ดนี้', 'NOT_FOUND');
    var me = target.sid === a.student.sid, today = todayKey_();
    var mine, sent;
    var run = function () {
      mine = loadMine_(c, a);
      sent = mine.extra.filter(function (x) { return x.kind === 'cheer' && x.date === today; });
      if (!cheer) return { ok: true };
      if (me) return FQ.fail('ส่งกำลังใจให้ตัวเองไม่ได้นะ', 'SELF');
      if (!SpreadsheetApp.getActive().getSheetByName(TAB.extra)) return FQ.fail('ยังใช้ไม่ได้ ให้ครูกดเมนู 1) ตั้งค่าครั้งแรก', 'SETUP');
      if (sent.some(function (x) { return x.ref === target.sid; })) return FQ.fail('วันนี้ส่งกำลังใจให้เพื่อนคนนี้แล้ว พรุ่งนี้ส่งใหม่ได้', 'DONE');
      if (sent.length >= CHEERS_PER_DAY) return FQ.fail('วันนี้ส่งกำลังใจครบแล้ว', 'LIMIT');
      var rec = { id: newId_(), date: today, classId: a.klass.id, code: a.student.code, kind: 'cheer', ref: target.sid, answer: -1, ok: true, check: '', row: 0 };
      writeExtra_(mine.xt, rec, nowText_());
      mine.extra.push(rec);
      mine.xt.all.push(rec);
      sent.push(rec);
      return { ok: true };
    };
    var res = cheer ? withLock_(run) : run();
    if (!res.ok) return res;
    var ts = readSnap_(target.sid), ws = FQ.addDays(today, -FQ.weekdayIdx(today)), cut = ts.cutoff;
    var fresh = (mine.xt && mine.xt.all ? mine.xt.all : []).filter(function (x) {
      return x.kind === 'cheer' && x.ref === target.sid && x.check !== 'ไม่นับ' && x.date >= ws && (!cut || x.date >= cut);
    }).length;
    var card = FQ.cardView(target, hit.l, c.events);
    card.me = me;
    card.cheers = (ts.cheers && ts.cheers[0] === ws ? Number(ts.cheers[1]) || 0 : 0) + fresh;
    card.cheered = sent.some(function (x) { return x.ref === target.sid; });
    var gr = gameRowOf_(gameSheet_(false), target.sid), gc = FQ.centerParse(gr ? gr.layout : ''), gb = FQ.centerBrief(gc);
    card.center = gb.level || (gr && gr.pet) ? { c: { r: gb.r, s: gb.s }, level: gb.level, done: gb.done, trophies: gb.r, likes: gr.likes, lv: card.lv || gr.lv || 1, pet: FQ.petView(gr.pet, card.lv || gr.lv || 1, today, false) } : null;
    return { ok: true, card: card, result: cheer ? { kind: 'cheer' } : null };
  });
}

/* ---------- เกมศูนย์ฝึกกีฬา ----------
 * แท็บศูนย์ฝึก 1 แถวต่อนักเรียน 1 คน ระบบสร้างแท็บและแถวเองเมื่อเด็กสร้างของชิ้นแรก ครูไม่ต้องตั้งค่า
 * เหรียญคิดจากแต้มรวมทุกครั้ง (แต้มรวม − ราคาของบนลาน) ช่องเหรียญที่ใช้กับดาวในชีตไว้ให้ครูดูเท่านั้น
 * ลบทั้งแถว = ศูนย์ฝึกของเด็กคนนั้นกลับเป็นลานว่าง แต้มไม่หาย */
var GC = { sid: 1, room: 2, layout: 3, spent: 4, stars: 5, likes: 6, given: 7, lv: 8, pet: 9, pname: 10, pdata: 11, pspent: 12, at: 13 };
function gameSheet_(create) {
  var ss = SpreadsheetApp.getActive(), sh = ss.getSheetByName(TAB.game);
  if (!sh && create) { sh = ss.insertSheet(TAB.game); setupGame_(sh); }
  return sh;
}
function setupGame_(sh) {
  sh.getRange(1, 1, 1, H.game.length).setValues([H.game]);
  header_(sh, H.game.length);
  sh.getRange(2, GC.sid, 1000, 1).setNumberFormat('@');
  sh.getRange(1, GC.layout).setNote(GAME_NOTE_DATA);
  sh.getRange(1, GC.stars).setNote(GAME_NOTE_STEPS);
  sh.getRange(1, GC.pname).setNote('ชื่อน้องที่เด็กตั้ง (เพื่อนเห็นตอนมาเยี่ยมชม)\nถ้าชื่อไม่เหมาะสม ลบช่องนี้ให้ว่าง น้องจะกลับไปใช้ชื่อตามชนิด แล้วเด็กตั้งใหม่ได้');
  [110, 60, 320, 90, 80, 80, 200, 60, 130, 110, 260, 90, 150].forEach(function (w, i) { sh.setColumnWidth(i + 1, w); });
  try { if (sh.getMaxColumns() > H.game.length) sh.deleteColumns(H.game.length + 1, sh.getMaxColumns() - H.game.length); } catch (e) {}
}
/* แถวของนักเรียน 1 คน (หาด้วยเลขประจำตัวในคอลัมน์แรก ไม่ต้องอ่านทั้งแท็บ) */
function gameRowOf_(sh, sid) {
  if (!sh || !sid || sh.getLastRow() < 2) return null;
  var hit = sh.getRange(2, GC.sid, sh.getLastRow() - 1, 1).createTextFinder(sid).matchEntireCell(true).findNext();
  if (!hit) return null;
  var row = hit.getRow(), v = sh.getRange(row, 1, 1, H.game.length).getValues()[0];
  return {
    row: row, layout: String(v[GC.layout - 1] || ''), likes: Number(v[GC.likes - 1]) || 0, given: String(v[GC.given - 1] || ''), lv: Number(v[GC.lv - 1]) || 0,
    pet: FQ.petParse(v[GC.pet - 1], v[GC.pname - 1], String(v[GC.pdata - 1] || '')), petSpent: Number(v[GC.pspent - 1]) || 0
  };
}
/* เขียนทั้งแถว x = ช่องที่เปลี่ยน (ที่ไม่ส่งมาใช้ค่าเดิมในแถว r)
 * เลเวล = เลเวลของเด็กตอนทำอะไรในเกมครั้งล่าสุด (ใช้เลือกฉากและร่างน้องตอนเพื่อนมาเยี่ยมชม) */
function gameWrite_(sh, r, sid, room, x) {
  r = r || {};
  var C = x.C || FQ.centerParse(r.layout || ''), pet = x.pet !== undefined ? x.pet : r.pet || null, sp = pet ? FQ.PETS.species.filter(function (q) { return q.id === pet.sp; })[0] : null;
  var vals = ["'" + sid, room, FQ.centerData(C), FQ.centerSpent(C), FQ.centerSteps(C), x.likes !== undefined ? x.likes : r.likes || 0, x.given !== undefined ? x.given : r.given || '',
    x.lv || r.lv || '', sp ? sp.label : '', pet ? pet.name : '', pet ? FQ.petData(pet) : '', x.petSpent !== undefined ? x.petSpent : r.petSpent || 0, "'" + nowText_()];
  if (r.row) sh.getRange(r.row, 1, 1, vals.length).setValues([vals]);
  else sh.appendRow(vals);
  gameHeader_(sh);
  try { CacheService.getScriptCache().remove('game_people'); } catch (e) {}
}
/* 6B-23: แท็บที่สร้างตอนเป็นลานแบบเดิม เปลี่ยนหัวคอลัมน์และคำอธิบายให้ตรงกับศูนย์ฝึกแบบใหม่ (ทำครั้งเดียว) */
function gameHeader_(sh) {
  var cache = null;
  try { cache = CacheService.getScriptCache(); if (cache.get('game_hdr_v3')) return; } catch (e) {}
  try {
    var hd = sh.getRange(1, 1, 1, H.game.length).getValues()[0];
    if (String(hd[GC.layout - 1]) !== H.game[GC.layout - 1] || String(hd[GC.stars - 1]) !== H.game[GC.stars - 1]) {
      sh.getRange(1, GC.layout).setValue(H.game[GC.layout - 1]).setNote(GAME_NOTE_DATA);
      sh.getRange(1, GC.stars).setValue(H.game[GC.stars - 1]).setNote(GAME_NOTE_STEPS);
    }
    if (cache) cache.put('game_hdr_v3', '1', 21600);
  } catch (e) {}
}
var GAME_NOTE_DATA = 'ระบบเขียนเองเมื่อเด็กกดอัปเกรดศูนย์ฝึก ไม่ต้องแก้\nlv = ระดับศูนย์ฝึก (ทุก 25 ระดับได้ถ้วย 1 ใบ)\nลบทั้งแถว = ศูนย์ฝึกของเด็กคนนั้นกลับเป็นลานโล่ง แต้มไม่หาย';
var GAME_NOTE_STEPS = 'ระดับศูนย์ฝึก (0 = ลานโล่ง · 25 = เต็ม ได้ถ้วย · 26 ขึ้นไป = ของประดับรอบพิเศษ) ใช้จัดอันดับ';
function myGame_(sid, xp) {
  var r = gameRowOf_(gameSheet_(false), sid);
  return withSchool_(FQ.centerView(FQ.centerParse(r ? r.layout : ''), xp, r ? r.likes : 0, { petSpent: r ? r.petSpent : 0, pet: r ? r.pet : null, today: todayKey_() }));
}
/* 6B-24 เป้าหมายรวมทั้งโรงเรียน (แคช 5 นาที) ส่งแค่ยอดรวม ไม่มีชื่อใคร */
function schoolGoal_() {
  var cache = null, hit = null, today = todayKey_();
  try { cache = CacheService.getScriptCache(); hit = JSON.parse(cache.get('school_goal') || 'null'); } catch (e) {}
  if (hit && hit.today === today && hit.g) return hit.g;
  var sum = 0, props = PropertiesService.getScriptProperties(), stored = null;
  gamePeople_().forEach(function (p) { sum += Number(p.s) || 0; });
  try { stored = JSON.parse(props.getProperty('SCHOOL_GOAL') || 'null'); } catch (e) {}
  var g = FQ.schoolGoal(sum, stored, today);
  if (g.save) { try { props.setProperty('SCHOOL_GOAL', JSON.stringify(g.save)); } catch (e) {} }
  delete g.save;
  try { if (cache) cache.put('school_goal', JSON.stringify({ today: today, g: g }), 300); } catch (e) {}
  return g;
}
function withSchool_(view) {
  try { if (view) view.school = schoolGoal_(); } catch (e) {}
  try { if (view) view.trip = tripView_(); } catch (e) {}
  return view;
}
/* 6B-26: นาทีรวมทั้งโรงเรียน เก็บไว้ใน ScriptProperties (SCHOOL_TRIP) นับใหม่ทุกครั้งที่สรุปดาว (ทุกชั่วโมง)
 * ยังไม่เคยนับ = นับจากแท็บบันทึกตอนนี้ */
function tripBase_() {
  var props = PropertiesService.getScriptProperties(), b = null, cache = null;
  try { b = JSON.parse(props.getProperty('SCHOOL_TRIP') || 'null'); } catch (e) {}
  var ok = b && typeof b.m === 'number';
  /* ยอดเก่าเกิน 3 ชั่วโมงหรือข้ามวัน (ครูยังไม่ได้เปิด ให้ระบบทำงานเองทุกชั่วโมง) = นับใหม่ ทีละคำขอ */
  if (ok && b.d === todayKey_() && Date.now() - (Number(b.ts) || 0) < 3 * 3600 * 1000) return b;
  if (ok) {
    try { cache = CacheService.getScriptCache(); if (cache.get('trip_busy')) return b; cache.put('trip_busy', '1', 120); } catch (e) {}
  }
  try { return tripSave_(tripCountNow_()); } catch (e) { if (ok) return b; throw e; }
}
function tripCountNow_() {
  var s = readSettings_(), by = {}, who = {};
  readRoster_().forEach(function (st) { if (st.active && st.classId) who[st.sid] = 1; });
  logsFromTable_(table_(TAB.logs, H.logs)).forEach(function (l) { if (who[l.code]) (by[l.code] = by[l.code] || []).push(l); });
  return FQ.tripCount(by, s, todayKey_());
}
function tripSave_(b) {
  b.at = nowText_(); b.ts = Date.now();
  try { PropertiesService.getScriptProperties().setProperty('SCHOOL_TRIP', JSON.stringify(b)); } catch (e) {}
  try { CacheService.getScriptCache().remove('school_trip'); } catch (e) {}
  return b;
}
/* สิ่งที่แอปเด็กเห็น: { min, spm, at } (แคช 5 นาที) · live = นาทีของวันนี้แบบสด (จอใหญ่ส่งมา) */
function tripView_(live) {
  var cache = null, hit = null, today = todayKey_();
  if (live === undefined) {
    try { cache = CacheService.getScriptCache(); hit = JSON.parse(cache.get('school_trip') || 'null'); } catch (e) {}
    if (hit && hit.today === today) return hit.v;
  }
  var b = tripBase_(), s = readSettings_();
  var v = { min: FQ.tripMinutes(b, today, live), spm: s.stepsPerMin, at: b.at || '' };
  try { if (cache) cache.put('school_trip', JSON.stringify({ today: today, v: v }), 300); } catch (e) {}
  return v;
}
function xpNow_(c, a, mine) {
  return FQ.xpOf({ settings: c.settings, klass: a.klass, student: a.student, logs: mine.logs, done: mine.done || [], extra: mine.extra || [], events: c.events || [], todayKey: todayKey_() });
}

/* อัปเกรดศูนย์ฝึก 1 ระดับ (op = up) */
function apiGame_(req) {
  return safe_(function () {
    var c = loadApi_();
    var a = auth_(c, req);
    if (!a.ok) return a;
    var xp = xpNow_(c, a, loadMine_(c, a)), sid = a.student.sid, plan, r;
    var res = withLock_(function () {
      var sh = gameSheet_(true);
      r = gameRowOf_(sh, sid);
      plan = FQ.planCenter({ data: r ? r.layout : '', xp: xp, op: req.op, petSpent: r ? r.petSpent : 0, today: todayKey_() });
      if (!plan.ok) return plan;
      gameWrite_(sh, r, sid, a.klass.id, { C: plan.center, lv: xp.level ? xp.level.lv : 0 });
      return { ok: true };
    });
    if (!res.ok) return res;
    return { ok: true, game: withSchool_(FQ.centerView(plan.center, xp, r ? r.likes : 0, { petSpent: r ? r.petSpent : 0, pet: r ? r.pet : null, today: todayKey_() })), result: plan.result };
  });
}

/* สัตว์เลี้ยงคู่หู: ฟักไข่ ไข่ใบใหม่ ตั้งชื่อ ให้ขนม ซื้อ/ใส่ของ (op) */
function apiPet_(req) {
  return safe_(function () {
    var c = loadApi_();
    var a = auth_(c, req);
    if (!a.ok) return a;
    var xp = xpNow_(c, a, loadMine_(c, a)), sid = a.student.sid, today = todayKey_(), plan, r, C, ps;
    var res = withLock_(function () {
      var sh = gameSheet_(true);
      r = gameRowOf_(sh, sid);
      C = FQ.centerParse(r ? r.layout : '');
      plan = FQ.planPet({ pet: r ? r.pet : null, xp: xp, spent: FQ.centerSpent(C), petSpent: r ? r.petSpent : 0, op: req.op, item: req.item, slot: req.slot, name: req.name, today: today });
      if (!plan.ok) return plan;
      ps = (r ? r.petSpent : 0) + plan.paid;
      gameWrite_(sh, r, sid, a.klass.id, { pet: plan.pet, petSpent: ps, lv: xp.level ? xp.level.lv : 0 });
      return { ok: true };
    });
    if (!res.ok) return res;
    return { ok: true, game: withSchool_(FQ.centerView(C, xp, r ? r.likes : 0, { petSpent: ps, pet: plan.pet, today: today })), result: plan.result };
  });
}

/* ศูนย์ฝึกทั้งโรงเรียน (ใช้ทำรายชื่อเยี่ยมชมและอันดับ) เก็บในแคช 2 นาที
 * แสดงชื่อเล่นหรือ เลขที่ n กับห้อง ไม่ส่งชื่อจริงและเลขประจำตัวไปหน้าเว็บ */
function gamePeople_() {
  var cache = null, hit = null;
  try { cache = CacheService.getScriptCache(); hit = JSON.parse(cache.get('game_people') || 'null'); } catch (e) {}
  if (hit) return hit;
  var sh = gameSheet_(false), list = [];
  if (sh && sh.getLastRow() >= 2) {
    var rows = sh.getRange(2, 1, sh.getLastRow() - 1, H.game.length).getValues(), who = {}, sec = secret_();
    readRoster_().forEach(function (s) { who[s.sid] = s; });
    rows.forEach(function (v) {
      var st = who[normSid_(v[GC.sid - 1])];
      if (!st || !st.active || !st.classId) return;
      var C = FQ.centerParse(String(v[GC.layout - 1] || '')), steps = FQ.centerSteps(C);
      list.push({
        c: st.sid, k: hex_(Utilities.computeHmacSha256Signature('card|' + st.sid, sec, Utilities.Charset.UTF_8)).slice(0, 12),
        n: st.nick || ('เลขที่ ' + (st.no || '?')), r: st.classId, g: st.grade, s: steps, t: FQ.centerAt(C.lv).r, h: Number(v[GC.likes - 1]) || 0,
        b: steps + (FQ.petParse(v[GC.pet - 1], '', '') ? 1 : 0)
      });
    });
  }
  try { if (cache) cache.put('game_people', JSON.stringify(list), 120); } catch (e) {}
  return list;
}

/* รายชื่อ: view = room (ห้องฉัน) | school (ทั้งโรงเรียน) | rank (อันดับดาวในชั้น grade) */
function apiGameBoard_(req) {
  return safe_(function () {
    var c = loadApi_();
    var a = auth_(c, req);
    if (!a.ok) return a;
    var view = ['room', 'school', 'rank'].indexOf(req.view) >= 0 ? req.view : 'room';
    var grade = Math.round(Number(req.grade)) || a.student.grade;
    if (grade < 1 || grade > 6) grade = a.student.grade;
    var mine = gameRowOf_(gameSheet_(false), a.student.sid), liked = FQ.likesGiven(mine ? mine.given : '', todayKey_());
    var list = FQ.gameBoard(gamePeople_(), { view: view, sid: a.student.sid, classId: a.student.classId, grade: grade, liked: liked });
    return { ok: true, view: view, grade: grade, myGrade: a.student.grade, room: a.student.classId, list: list, likesLeft: Math.max(0, FQ.CENTER.likesPerDay - liked.length), model: view === 'rank' ? null : modelBrief_() };
  });
}

/* เปิดดูศูนย์ฝึกเพื่อน (like = กดถูกใจด้วย) */
function apiGameVisit_(req, like) {
  return safe_(function () {
    var c = loadApi_();
    var a = auth_(c, req);
    if (!a.ok) return a;
    var key = String((req && req.k) || ''), hit = null;
    if (key === 'model') return visitModel_(a, like);
    if (/^[0-9a-f]{12}$/.test(key)) gamePeople_().forEach(function (p) { if (p.k === key) hit = p; });
    if (!hit) return FQ.fail('ไม่พบศูนย์ฝึกนี้ ลองเปิดรายชื่อใหม่', 'NOT_FOUND');
    var sid = a.student.sid, me = hit.c === sid, today = todayKey_(), r, mineR;
    var run = function () {
      var sh = gameSheet_(like);
      r = gameRowOf_(sh, hit.c);
      if (!r) return FQ.fail('ไม่พบศูนย์ฝึกนี้', 'NOT_FOUND');
      mineR = me ? r : gameRowOf_(sh, sid);
      if (!like) return { ok: true };
      var pl = FQ.planLike({ given: mineR ? mineR.given : '', today: today, me: sid, target: hit.c });
      if (!pl.ok) return pl;
      if (mineR) sh.getRange(mineR.row, GC.given).setValue(pl.given);
      else gameWrite_(sh, null, sid, a.klass.id, { given: pl.given });
      r.likes += 1;
      sh.getRange(r.row, GC.likes).setValue(r.likes);
      mineR = { given: pl.given };
      return { ok: true };
    };
    var res = like ? withLock_(run) : run();
    if (!res.ok) return res;
    var C = FQ.centerParse(r.layout), B = FQ.centerBrief(C), given = FQ.likesGiven(mineR ? mineR.given : '', today);
    return {
      ok: true,
      center: { k: hit.k, n: hit.n, r: hit.r, me: me, lv: r.lv || 1, pet: FQ.petView(r.pet, r.lv || 1, today, false), c: { r: B.r, s: B.s }, level: B.level, done: B.done, trophies: B.r, likes: r.likes, liked: given.indexOf(hit.c) >= 0 },
      likesLeft: Math.max(0, FQ.CENTER.likesPerDay - given.length), result: like ? { kind: 'like' } : null
    };
  });
}

/* ---------- โหมดครู ----------
 * รหัสครูรหัสเดียว เห็นทั้งโรงเรียน ตั้งจากเมนูในชีต เก็บแบบเข้ารหัสใน Script Properties
 * ชื่อจริงของเด็กส่งออกไปเฉพาะคำขอที่มีตั๋วครูเท่านั้น */
function teacherHash_(pass) { return 't1:' + sha256_(secret_() + '|teacher|' + pass); }
function teacherToken_(hash) { return 'T.' + hmac_('teacher|' + hash).slice(0, 40); }

function teacherLogin_(req) {
  return safe_(function () {
    return withLock_(function () {
      var props = PropertiesService.getScriptProperties(), hash = props.getProperty('TEACHER_HASH');
      if (!hash) return FQ.fail('ยังไม่ได้ตั้งรหัสครู ให้กดเมนู ' + APP_NAME + ' → ตั้งรหัสครู ในชีต', 'NO_TEACHER');
      var now = Date.now(), until = Number(props.getProperty('T_LOCK')) || 0;
      if (until > now) return FQ.fail('ใส่รหัสครูผิดหลายครั้ง ลองใหม่ในอีก ' + Math.ceil((until - now) / 60000) + ' นาที', 'LOCKED');
      var pass = String((req && req.password) || '');
      if (!pass || teacherHash_(pass) !== hash) {
        var fails = (Number(props.getProperty('T_FAILS')) || 0) + 1;
        if (fails >= MAX_STRIKES) {
          props.setProperty('T_FAILS', '0');
          props.setProperty('T_LOCK', String(now + LOCK_SECONDS * 1000));
          return FQ.fail('ใส่รหัสครูผิดหลายครั้ง ล็อก ' + (LOCK_SECONDS / 60) + ' นาที', 'LOCKED');
        }
        props.setProperty('T_FAILS', String(fails));
        return FQ.fail('รหัสครูไม่ถูกต้อง', 'BAD_PASS');
      }
      props.setProperty('T_FAILS', '0');
      props.setProperty('T_LOCK', '0');
      return { ok: true, teacher: true, token: teacherToken_(hash) };
    });
  });
}

/* ตรวจตั๋วครู แล้วเรียกงานของครู ตั๋วใช้ไม่ได้ทันทีเมื่อเปลี่ยนรหัสครู */
function teacherApi_(req, fn) {
  return safe_(function () {
    var hash = PropertiesService.getScriptProperties().getProperty('TEACHER_HASH');
    if (!hash || !req || String(req.token || '') !== teacherToken_(hash)) return FQ.fail('กรุณาเข้าโหมดครูใหม่', 'AUTH_T');
    var res = fn(req || {}, readSettings_());
    if (res && res.ok !== false) res.ok = true;
    return res;
  });
}

/* 6B-25 จอใหญ่หน้าเสาธง: ยอดรวมวันนี้ + อันดับห้องสัปดาห์นี้ (แคช 1 นาที) ไม่มีชื่อเด็ก */
function teacherBoard_(req) {
  var cache = null, hit = null, today = todayKey_();
  try { cache = CacheService.getScriptCache(); hit = JSON.parse(cache.get('tboard') || 'null'); } catch (e) {}
  if (hit && hit.today === today) return hit;
  var s = readSettings_(), lw = FQ.addDays(today, -FQ.weekdayIdx(today) - 7), sc = null, dust = null;
  var st = FQ.boardStats({ settings: s, todayKey: today, roster: readRoster_(), logs: logsFromTable_(tail_(TAB.logs, H.logs, lw)) });
  try { sc = schoolGoal_(); } catch (e) {}
  try { dust = dustForTeacher_(); } catch (e) {}
  var trip = null;
  try { var tb = tripBase_(); trip = { min: FQ.tripMinutes(tb, today, st.minutes), spm: s.stepsPerMin, at: tb.at || '' }; } catch (e) {}
  var out = { today: today, at: Utilities.formatDate(new Date(), TZ, 'HH:mm'), schoolName: s.schoolName, board: st, school: sc, dust: dust, trip: trip };
  try { if (cache) cache.put('tboard', JSON.stringify(out), 60); } catch (e) {}
  return out;
}

/* ภาพรวม + เด็กที่หายไป: สร้างทุกชั่วโมงพร้อมอันดับ (ยังไม่มี = สร้างตอนนี้) */
function teacherDash_(req) {
  var d = readTeacher_();
  if (!d) { rebuildSummary_(); d = readTeacher_(); }
  return { dash: d, dust: dustForTeacher_(), petCat: FQ.petCatalog() };
}
/* ค่าฝุ่นที่ครูเห็น: ระดับของวันนี้ + ค่าล่าสุดที่ดึงได้ + ข้อผิดพลาด */
function dustForTeacher_() {
  var s = readSettings_(), d = readDust_(), today = todayKey_();
  var v = FQ.dustView(d, today, s);
  if (!v) return { off: true };
  v.ovr = d && d.date === today ? d.ovr || 0 : 0;
  v.err = d && d.date === today ? d.err || '' : '';
  v.auto = d && d.date === today ? d.max || 0 : 0;
  return v;
}
/* ครูเปลี่ยนสีฝุ่นของวันนี้ (lv 1–5, 0 = ใช้ค่าอัตโนมัติ) หรือกดดึงค่าใหม่  req = { op: 'set'|'refresh', lv } */
function teacherDust_(req) {
  var s = readSettings_();
  if (!s.dustOn) return FQ.fail('โหมดฝุ่นปิดอยู่ เปิดได้ที่แท็บตั้งค่า แถว โหมดฝุ่น PM2.5', 'OFF');
  var msg = '';
  if (req.op === 'refresh') {
    var r = refreshDust_();
    msg = r.ok ? 'ดึงค่าฝุ่นแล้ว' : r.error;
  } else {
    var lv = parseInt(req.lv, 10);
    if (!(lv >= 0 && lv <= 5)) return FQ.fail('เลือกสีไม่ถูกต้อง', 'INPUT');
    withLock_(function () {
      var today = todayKey_(), d = readDust_();
      if (!d || d.date !== today) d = { date: today, max: 0, lv: 0, v: null, at: '', st: '', id: '', err: '' };
      d.ovr = lv;
      saveDust_(d);
    });
    msg = lv ? 'ตั้งวันนี้เป็นสี' + FQ.DUST[lv].label + 'แล้ว' : 'ใช้ค่าอัตโนมัติแล้ว';
  }
  try { CacheService.getScriptCache().remove('game_people'); } catch (e) {}
  return { dust: dustForTeacher_(), message: msg };
}
function readTeacher_() {
  var sh = SpreadsheetApp.getActive().getSheetByName(TAB.cache);
  if (!sh || sh.getLastRow() < 3) return null;
  var v = sh.getRange(3, 1, 1, 2).getValues()[0];
  if (String(v[0]) !== '#teacher') return null;
  try { return JSON.parse(v[1] || 'null'); } catch (e) { return null; }
}

/* ข้อมูลหน้าภาพรวมของครู คำนวณตอนสร้างสรุปดาว  list = [{ s (นักเรียน), logs, done }] */
function teacherSummary_(list, s, today, now) {
  var ws = FQ.addDays(today, -FQ.weekdayIdx(today));
  var t = { registered: 0, loggedToday: 0, movedWeek: 0, weekMinutes: 0, clipsToday: 0, photosPending: 0 };
  var grades = {}, rooms = {}, missing = [];
  list.forEach(function (x) {
    var st = x.s;
    (x.extra || []).forEach(function (e) { if (e.kind === 'clip' && e.check !== 'ไม่นับ' && e.date === today) t.clipsToday++; });
    if (st.photo && st.photoOk !== 'อนุมัติ' && st.photoOk !== 'ไม่อนุมัติ') t.photosPending++;
    if (!st.pinHash || !st.classId) return;
    var last = '', today1 = false, week = 0, moved = false;
    (x.logs || []).forEach(function (l) {
      if (l.excluded || !l.date || l.date > today) return;
      if (l.date > last) last = l.date;
      if (l.date === today) today1 = true;
      if (l.date >= ws) { moved = true; week += Number(l.minutes) || 0; }
    });
    t.registered++;
    if (today1) t.loggedToday++;
    if (moved) t.movedWeek++;
    t.weekMinutes += week;
    var g = grades[st.grade] || (grades[st.grade] = { grade: st.grade, registered: 0, moved: 0 });
    var r = rooms[st.classId] || (rooms[st.classId] = { classId: st.classId, grade: st.grade, room: st.room, registered: 0, moved: 0, minutes: 0, missing: 0 });
    g.registered++; r.registered++;
    if (moved) { g.moved++; r.moved++; }
    r.minutes += week;
    var ref = last || st.created || '';
    var days = ref ? FQ.dayNum(today) - FQ.dayNum(ref) : s.missingDays;
    if (days >= s.missingDays) {
      r.missing++;
      missing.push({ name: st.name, nick: st.nick || '', classId: st.classId, no: st.no || 0, last: last, days: days, never: !last });
    }
  });
  var pct = function (a, b) { return b ? Math.round(a * 100 / b) : 0; };
  var gl = Object.keys(grades).map(function (k) { var g = grades[k]; g.pct = pct(g.moved, g.registered); return g; })
    .sort(function (a, b) { return a.grade - b.grade; });
  var rl = Object.keys(rooms).map(function (k) { var r = rooms[k]; r.pct = pct(r.moved, r.registered); return r; })
    .sort(function (a, b) { return a.grade - b.grade || a.room - b.room; });
  missing.sort(function (a, b) {
    var ra = rooms[a.classId], rb = rooms[b.classId];
    return ra.grade - rb.grade || ra.room - rb.room || b.days - a.days || a.no - b.no;
  });
  return {
    updated: now, today: today, week: ws, missingDays: s.missingDays,
    totals: {
      registered: t.registered, loggedToday: t.loggedToday, movedWeek: t.movedWeek, movedPct: pct(t.movedWeek, t.registered),
      avgWeekMinutes: t.registered ? Math.round(t.weekMinutes / t.registered) : 0, whoWeek: 420, clipsToday: t.clipsToday,
      photosPending: t.photosPending
    },
    grades: gl, rooms: rl, missingCount: missing.length, missing: missing.slice(0, 400)
  };
}

/* รูปโปรไฟล์ที่รอครูอนุมัติ */
function teacherPhotos_() {
  var list = readRoster_().filter(function (st) { return st.active && st.photo && st.photoOk !== 'อนุมัติ' && st.photoOk !== 'ไม่อนุมัติ'; });
  return {
    left: list.length,
    items: list.slice(0, 12).map(function (st) {
      return { sid: st.sid, name: st.name, classId: st.classId, no: st.no, data: photoData_(st.photo) };
    })
  };
}
/* อนุมัติ / ไม่อนุมัติ (ไม่อนุมัติ = ลบรูปทิ้ง) */
function teacherPhoto_(req) {
  var sid = normSid_(req.sid), yes = req.approve === true || req.approve === 'true';
  return withLock_(function () {
    var t = table_(TAB.roster, H.roster, H.rosterOpt), miss = needProfileCols_(t);
    if (miss) return miss;
    var st = findStudentRow_(t, sid);
    if (!st || !st.photo) return FQ.fail('ไม่พบรูปนี้', 'NOT_FOUND');
    if (yes) setCells_(t, st.row, [[SC.photoOk, 'อนุมัติ']]);
    else { trashFile_(st.photo); setCells_(t, st.row, [[SC.photo, ''], [SC.photoOk, 'ไม่อนุมัติ']]); }
    return { sid: sid, approved: yes };
  });
}
/* ---------- ชื่อน้องคู่หูที่เด็กพิมพ์เอง (ครูตรวจในแอป) ----------
 * ชื่อที่เลือกจากรายชื่อไม่ต้องตรวจ · ผ่าน = จำชื่อนั้นไว้ (เด็กเปลี่ยนชื่อใหม่ = กลับมารอตรวจ)
 * ลบชื่อ = น้องใช้ชื่อตามชนิด แล้วเด็กตั้งใหม่ได้  all = ดูที่ผ่านแล้วด้วย */
function teacherPetNames_(req) {
  var sh = gameSheet_(false), all = req.all === true || req.all === 'true', items = [], left = 0;
  if (sh && sh.getLastRow() >= 2) {
    var rows = sh.getRange(2, 1, sh.getLastRow() - 1, H.game.length).getValues(), who = {};
    readRoster_().forEach(function (st) { who[st.sid] = st; });
    rows.forEach(function (v) {
      var sid = normSid_(v[GC.sid - 1]), pet = FQ.petParse(v[GC.pet - 1], v[GC.pname - 1], String(v[GC.pdata - 1] || ''));
      if (!pet || !pet.name || FQ.PETS.names.indexOf(pet.name) >= 0) return;
      var ok = pet.nameOk === pet.name, st = who[sid] || {};
      if (!ok) left++;
      if (ok && !all) return;
      items.push({ sid: sid, name: st.name || '', classId: st.classId || '', no: Number(st.no) || 0, pet: pet.name, sp: pet.sp, ok: ok });
    });
  }
  items.sort(function (a, b) { return (a.ok ? 1 : 0) - (b.ok ? 1 : 0) || (a.classId < b.classId ? -1 : a.classId > b.classId ? 1 : 0) || a.no - b.no; });
  return { items: items.slice(0, 200), left: left };
}
function teacherPetName_(req) {
  var sid = normSid_(req.sid), yes = req.approve === true || req.approve === 'true';
  return withLock_(function () {
    var sh = gameSheet_(false), r = gameRowOf_(sh, sid);
    if (!r || !r.pet || !r.pet.name) return FQ.fail('ไม่พบชื่อนี้ (เด็กอาจเปลี่ยนแล้ว) ลองโหลดใหม่', 'NOT_FOUND');
    if (req.name !== undefined && String(req.name) !== r.pet.name) return FQ.fail('เด็กเพิ่งเปลี่ยนชื่อน้อง ลองโหลดใหม่', 'CHANGED');
    if (yes) { r.pet.nameOk = r.pet.name; sh.getRange(r.row, GC.pdata).setValue(FQ.petData(r.pet)); }
    else { r.pet.nameOk = ''; sh.getRange(r.row, GC.pname).setValue(''); sh.getRange(r.row, GC.pdata).setValue(FQ.petData(r.pet)); }
    try { CacheService.getScriptCache().remove('game_people'); } catch (e) {}
    return { sid: sid, approved: yes };
  });
}

/* ครูเลือก ไม่อนุมัติ ในชีตเอง: ลบไฟล์ให้ตอนระบบทำงานรายชั่วโมง */
function cleanupPhotos_() {
  if (!SpreadsheetApp.getActive().getSheetByName(TAB.roster)) return 0;
  var t = table_(TAB.roster, H.roster, H.rosterOpt), n = 0;
  if (needProfileCols_(t)) return 0;
  t.data.forEach(function (r, i) {
    var st = studentFromRow_(t, r, i + 2);
    if (st.photo && st.photoOk === 'ไม่อนุมัติ') { trashFile_(st.photo); setCells_(t, st.row, [[SC.photo, '']]); n++; }
  });
  return n;
}

/* ---------- ศูนย์ฝึกต้นแบบของครู ---------- */
function readModel_() { return FQ.centerModel(PropertiesService.getScriptProperties().getProperty('TCENTER') || ''); }
function modelBrief_() {
  var m = readModel_();
  return m.show && m.level ? { k: 'model', s: m.level, t: m.r } : null;
}
function visitModel_(a, like) {
  if (like) return FQ.fail('ศูนย์ฝึกต้นแบบกดถูกใจไม่ได้ ไปกดให้เพื่อนแทนนะ', 'MODEL');
  var m = readModel_();
  if (!m.show || !m.level) return FQ.fail('ตอนนี้ครูปิดศูนย์ฝึกต้นแบบอยู่', 'NOT_FOUND');
  var mr = gameRowOf_(gameSheet_(false), a.student.sid), given = FQ.likesGiven(mr ? mr.given : '', todayKey_());
  return {
    ok: true,
    center: { k: 'model', model: true, n: 'ศูนย์ฝึกต้นแบบ', r: 'จากคุณครู', me: false, lv: 1, pet: null, c: { r: m.r, s: m.s }, level: m.level, done: m.done, trophies: m.r, likes: 0, liked: false },
    likesLeft: Math.max(0, FQ.CENTER.likesPerDay - given.length), result: null
  };
}
/* 6B-23: ฉากของครู กด + / − ระดับได้ตามสะดวก (ไม่ใช้เหรียญ) */
function teacherCenter_(req) {
  var sc = null;
  try { sc = schoolGoal_(); } catch (e) {}
  return { center: readModel_(), perRound: FQ.CENTER.steps * FQ.CENTER.parts.length, max: FQ.CENTER.maxRound * FQ.CENTER.steps * FQ.CENTER.parts.length, school: sc };
}
function teacherCenterSave_(req) {
  var m = FQ.centerModel({ lv: req.lv, show: req.show === true || req.show === 'true' });
  var at = Utilities.formatDate(new Date(), TZ, 'yyyy-MM-dd HH:mm');
  return withLock_(function () {
    PropertiesService.getScriptProperties().setProperty('TCENTER', JSON.stringify({ v: 3, lv: m.level, show: m.show, at: at }));
    m.at = at;
    return { center: m };
  });
}

/* ---------- ค้นหานักเรียน + แก้เลขประจำตัว (โหมดครู) ---------- */
function teacherStudents_(req, s) {
  var t = table_(TAB.roster, H.roster, H.rosterOpt), I = t.idx, out = [];
  t.data.forEach(function (r, i) {
    var st = studentFromRow_(t, r, i + 2);
    if (!st.sid) return;
    var last = r[I[SC.last]];
    out.push({
      sid: st.sid, name: st.name, grade: st.grade, room: st.room, no: st.no, classId: st.classId,
      active: st.active, hasPin: !!st.pinHash, created: st.created || '',
      last: Object.prototype.toString.call(last) === '[object Date]' ? Utilities.formatDate(last, TZ, 'yyyy-MM-dd HH:mm') : String(last || '').replace(/^'/, '').slice(0, 16)
    });
  });
  return { students: out, sidLen: s.sidLen };
}

/* ข้อมูลนักเรียน 1 คนสำหรับครู: สรุป + 14 วันล่าสุด (บันทึก ภารกิจ คำถาม คลิป) */
function teacherStudent_(req, s) {
  var sid = normSid_(req.sid);
  if (!sid) return FQ.fail('ไม่พบนักเรียนคนนี้', 'INPUT');
  var t = table_(TAB.roster, H.roster, H.rosterOpt), st = findStudentRow_(t, sid);
  if (!st) return FQ.fail('ไม่พบนักเรียนคนนี้ ลองโหลดใหม่', 'NOT_FOUND');
  var last = t.data[st.row - 2][t.idx[SC.last]], now = new Date();
  var info = {
    sid: st.sid, name: st.name, grade: st.grade, room: st.room, no: st.no, classId: st.classId, nick: st.nick,
    active: st.active, hasPin: !!st.pinHash, fails: st.fails, locked: !!(st.lockUntil && st.lockUntil.getTime() > now.getTime()),
    created: st.created || '',
    last: Object.prototype.toString.call(last) === '[object Date]' ? Utilities.formatDate(last, TZ, 'yyyy-MM-dd HH:mm') : String(last || '').replace(/^'/, '').slice(0, 16)
  };
  if (!st.classId) return { student: info, summary: null, days: [] };
  var c = loadApi_(), a = { ok: true, klass: klassOf_(c, st), student: st }, mine = loadMine_(c, a), sv = status_(c, a, mine);
  var today = todayKey_(), from = FQ.addDays(today, -13), map = {}, days = [];
  for (var i = 0; i < 14; i++) { var d = FQ.addDays(today, -i), o = { date: d, minutes: 0, logs: [], missions: [], quiz: '', clips: 0 }; map[d] = o; days.push(o); }
  (mine.logs || []).forEach(function (l) {
    var o = map[l.date];
    if (!o) return;
    o.logs.push({ act: l.activity, min: Number(l.minutes) || 0, feel: l.feeling, x: !!l.excluded });
    if (!l.excluded) o.minutes += Number(l.minutes) || 0;
  });
  (mine.done || []).forEach(function (m) {
    var o = map[m.date];
    if (o && m.check !== 'ไม่นับ') o.missions.push({ type: m.type, text: m.text || '' });
  });
  (mine.extra || []).forEach(function (x) {
    var o = map[x.date];
    if (!o || x.check === 'ไม่นับ') return;
    if (x.kind === 'quiz') o.quiz = x.ok ? 'ถูก' : 'ผิด';
    else if (x.kind === 'clip') o.clips++;
  });
  var xp = sv.xp || {}, lv = xp.level || {}, g = sv.game || {}, pet = g.pet || null;
  return {
    student: info,
    summary: {
      lv: lv.lv || 1, icon: lv.icon || '', title: lv.title || '', total: xp.total || 0, week: xp.week || 0,
      streak: xp.streak ? xp.streak.current : 0, best: xp.streak ? xp.streak.best : 0, activeDays: xp.activeDays || 0,
      programMinutes: sv.programMinutes || 0, stars: sv.totalStars || 0, coins: g.coins || 0,
      pet: pet ? { label: pet.label || '', name: pet.name || '', tier: pet.tier || 1 } : null,
      weeks: (sv.history || []).filter(function (w) { return w.start <= today; }).map(function (w) { return { no: w.no, minutes: w.minutes, stars: w.stars, days: w.qualifiedDays }; })
    },
    days: days
  };
}

/* ครูทำกับบัญชีนักเรียน: ตรวจชื่อให้ตรงกับแถวก่อนแก้ (กันแก้ผิดคนตอนข้อมูลเพิ่งเปลี่ยน) */
function withStudent_(req, fn) {
  var sid = normSid_(req.sid);
  if (!sid) return FQ.fail('ไม่พบนักเรียนคนนี้', 'INPUT');
  return withLock_(function () {
    var t = table_(TAB.roster, H.roster, H.rosterOpt), st = findStudentRow_(t, sid);
    if (!st) return FQ.fail('ไม่พบนักเรียนคนนี้ (อาจถูกแก้ไปแล้ว) ลองโหลดใหม่', 'NOT_FOUND');
    if (req.name !== undefined && String(req.name).trim() !== st.name) return FQ.fail('ข้อมูลนักเรียนเพิ่งเปลี่ยน ลองโหลดใหม่', 'CHANGED');
    var res = fn(t, st);
    if (res && res.ok !== false) { try { CacheService.getScriptCache().remove('game_people'); } catch (e) {} }
    return res;
  });
}
/* ล้าง PIN (และปลดล็อกที่ใส่ PIN ผิด): เด็กกด สมัครครั้งแรก ด้วยเลขเดิม ตั้ง PIN ใหม่ บันทึกเดิมอยู่ครบ */
function teacherPin_(req) {
  return withStudent_(req, function (t, st) {
    setCells_(t, st.row, [[SC.pin, ''], [SC.fails, 0], [SC.lockUntil, '']]);
    return { sid: st.sid, name: st.name };
  });
}
/* ปิด / เปิดบัญชี: ปิดแล้วเข้าไม่ได้ ไม่ขึ้นอันดับ เพื่อนไม่เห็น บันทึกเดิมยังอยู่ในชีต */
function teacherActive_(req) {
  var on = req.active === true || req.active === 'true';
  return withStudent_(req, function (t, st) {
    setCells_(t, st.row, [[SC.active, on ? 'ใช่' : 'ไม่']]);
    return { sid: st.sid, name: st.name, active: on };
  });
}
/* แก้ชื่อ ชั้น ห้อง เลขที่ (บันทึกเก่ายังเป็นห้องเดิม อันดับห้องใช้ห้องใหม่ตั้งแต่ระบบอัปเดตรอบถัดไป) */
function teacherEdit_(req) {
  var name = cleanText_(String(req.newName || '').replace(/\s+/g, ' ').trim(), 60);
  var grade = normGrade_(req.grade), room = normRoom_(req.room), no = normNo_(req.no);
  if (name.replace(/^'/, '').length < 4 || name.indexOf(' ') < 0) return FQ.fail('ใส่ชื่อและนามสกุล (เว้นวรรคระหว่างชื่อกับนามสกุล)', 'INPUT');
  if (!grade) return FQ.fail('เลือกชั้น ป.1–ป.6', 'INPUT');
  if (!room) return FQ.fail('ห้องต้องเป็นตัวเลข 1–30', 'INPUT');
  if (!no) return FQ.fail('เลขที่ต้องเป็นตัวเลข 1–99', 'INPUT');
  return withStudent_(req, function (t, st) {
    setCells_(t, st.row, [[SC.name, name], [SC.grade, 'ป.' + grade], [SC.room, room], [SC.no, no]]);
    return { sid: st.sid, name: name.replace(/^'/, ''), grade: grade, room: room, no: no, classId: classIdOf_(grade, room) };
  });
}

/* เปลี่ยนเลขประจำตัวของนักเรียน 1 คน: แก้ในแท็บนักเรียน ล้าง PIN (PIN ผูกกับเลข)
 * แล้วย้ายเลขในทุกแท็บที่มีคอลัมน์ เลขประจำตัว ให้บันทึกเดิมตามมาครบ */
function teacherSid_(req, s) {
  var from = normSid_(req.sid), to = normSid_(req.newSid);
  if (!from) return FQ.fail('ไม่พบนักเรียนคนนี้ ลองโหลดใหม่', 'INPUT');
  if (!to) return FQ.fail('ใส่เลขประจำตัวใหม่เป็นตัวเลข', 'INPUT');
  if (s.sidLen && to.length !== s.sidLen) return FQ.fail('เลขประจำตัวใหม่ต้องมี ' + s.sidLen + ' หลัก', 'SID_LEN');
  if (from === to) return FQ.fail('เลขใหม่เหมือนเลขเดิม', 'SAME');
  return withLock_(function () {
    var t = table_(TAB.roster, H.roster, H.rosterOpt), st = findStudentRow_(t, from);
    if (!st) return FQ.fail('ไม่พบนักเรียนคนนี้ (อาจถูกแก้ไปแล้ว) ลองโหลดใหม่', 'NOT_FOUND');
    if (req.name !== undefined && String(req.name).trim() !== st.name) return FQ.fail('ข้อมูลนักเรียนเพิ่งเปลี่ยน ลองโหลดใหม่', 'CHANGED');
    var other = findStudentRow_(t, to);
    if (other) return FQ.fail('เลข ' + to + ' มีนักเรียนใช้อยู่แล้ว: ' + other.name + (other.classId ? ' (ป.' + other.grade + '/' + other.room + ' เลขที่ ' + (other.no || '-') + ')' : ''), 'TAKEN');
    setCells_(t, st.row, [[SC.sid, "'" + to], [SC.pin, ''], [SC.fails, 0], [SC.lockUntil, '']]);
    var moved = renameSidAll_(from, to, TAB.roster);
    try { CacheService.getScriptCache().remove('game_people'); } catch (e) {}
    return { oldSid: from, sid: to, name: st.name, moved: moved };
  });
}

/* แทนเลขประจำตัวเก่าด้วยเลขใหม่ ในทุกแท็บที่หัวคอลัมน์แถวแรกเป็น เลขประจำตัว (เทียบทั้งช่อง) */
function renameSidAll_(from, to, skip) {
  var moved = {};
  SpreadsheetApp.getActive().getSheets().forEach(function (sh) {
    var name = sh.getName(), last = sh.getLastRow();
    if (name === skip || last < 2) return;
    var width = Math.max(1, sh.getLastColumn());
    var head = sh.getRange(1, 1, 1, width).getValues()[0].map(function (v) { return String(v).trim(); });
    var col = head.indexOf(SC.sid);
    if (col < 0) return;
    var vals = sh.getRange(2, col + 1, last - 1, 1).getValues(), n = 0;
    for (var i = 0; i < vals.length; i++) {
      if (normSid_(vals[i][0]) === from) { sh.getRange(i + 2, col + 1).setValue("'" + to); n++; }
    }
    if (n) moved[name] = n;
  });
  return moved;
}

/* ---------- ผลสมรรถภาพ ---------- */
function termOf_(v) {
  if (Object.prototype.toString.call(v) === '[object Date]') return (v.getMonth() + 1) + '/' + v.getFullYear();
  var t = String(v === null || v === undefined ? '' : v).trim().replace(/^'/, '');
  return /^[12]\/\d{4}$/.test(t) ? t : '';
}
function termSort_(a, b) {
  var pa = a.split('/'), pb = b.split('/');
  return (+pa[1] * 10 + +pa[0]) - (+pb[1] * 10 + +pb[0]);
}
/* ค่าผลทดสอบ: ว่าง = ยังไม่ได้ทดสอบ, ตัวเลขนอกช่วง = ผิด */
function fitValue_(v, test) {
  if (v === '' || v === null || v === undefined) return { ok: true, value: '' };
  var n = Number(String(v).replace(',', '.'));
  if (!isFinite(n) || n < test.min || n > test.max) return { ok: false };
  return { ok: true, value: Math.round(n * 10) / 10 };
}
function fitnessRows_(t) {
  var I = t.idx, base = t.base || 2;
  return t.data.map(function (r, i) {
    var o = { row: i + base, sid: normSid_(r[I[SC.sid]]), term: termOf_(r[I['ภาคเรียน']]) };
    FITNESS_TESTS.forEach(function (k) { var f = fitValue_(r[I[k.head]], k); o[k.key] = f.ok ? f.value : ''; });
    return o;
  }).filter(function (o) { return o.sid && o.term; });
}
/* ผลของเด็ก 1 คน เทียบกับตัวเองเท่านั้น (ไม่มีอันดับ) */
function fitnessOf_(sid) {
  var tests = FITNESS_TESTS.map(function (k) { return { key: k.key, label: k.label, unit: k.unit }; });
  var sh = SpreadsheetApp.getActive().getSheetByName(TAB.fitness);
  if (!sh || sh.getLastRow() < 2 || !sid) return { tests: tests, terms: [] };
  var I = headIdx_(sh, TAB.fitness, H.fitness).idx, width = Math.max(sh.getLastColumn(), H.fitness.length);
  var hits = sh.getRange(2, I[SC.sid] + 1, sh.getLastRow() - 1, 1).createTextFinder(sid).matchEntireCell(true).findAll().slice(0, 12);
  var rows = hits.map(function (h) { return sh.getRange(h.getRow(), 1, 1, width).getValues()[0]; });
  var list = fitnessRows_({ idx: I, data: rows, base: 0 }).filter(function (o) { return o.sid === sid; });
  var by = {};
  list.forEach(function (o) { by[o.term] = o; });
  var terms = Object.keys(by).sort(termSort_).map(function (k) {
    var o = { term: k };
    FITNESS_TESTS.forEach(function (x) { o[x.key] = by[k][x.key]; });
    return o;
  });
  return { tests: tests, terms: terms };
}

/* ครูเปิดห้อง: รายชื่อตามเลขที่ + ผลของภาคเรียนที่เลือก */
function teacherFitness_(req, s) {
  var term = termOf_(req.term) || s.termNow;
  if (!term) return FQ.fail('ใส่ภาคเรียนปัจจุบันในแท็บตั้งค่าก่อน เช่น 2/2569', 'NO_TERM');
  var roster = readRoster_().filter(function (st) { return st.active && st.classId; });
  var rooms = {};
  roster.forEach(function (st) { rooms[st.classId] = { grade: st.grade, room: st.room }; });
  var classId = String(req.classId || '').trim();
  var list = Object.keys(rooms).sort(function (a, b) { return rooms[a].grade - rooms[b].grade || rooms[a].room - rooms[b].room; });
  if (!classId) return { term: term, rooms: list, students: [], tests: FITNESS_TESTS.map(function (k) { return { key: k.key, label: k.label, unit: k.unit, min: k.min, max: k.max }; }) };
  if (!rooms[classId]) return FQ.fail('ไม่พบห้องนี้', 'INPUT');
  var have = {};
  if (SpreadsheetApp.getActive().getSheetByName(TAB.fitness)) {
    fitnessRows_(table_(TAB.fitness, H.fitness)).forEach(function (o) { if (o.term === term) have[o.sid] = o; });
  }
  return {
    term: term, classId: classId, rooms: list,
    tests: FITNESS_TESTS.map(function (k) { return { key: k.key, label: k.label, unit: k.unit, min: k.min, max: k.max }; }),
    students: roster.filter(function (st) { return st.classId === classId; })
      .sort(function (a, b) { return (a.no || 999) - (b.no || 999); })
      .map(function (st) {
        var o = { sid: st.sid, no: st.no, name: st.name }, h = have[st.sid] || {};
        FITNESS_TESTS.forEach(function (k) { o[k.key] = h[k.key] === undefined ? '' : h[k.key]; });
        return o;
      })
  };
}

/* บันทึกผลทั้งห้อง: ช่องว่าง = ไม่แก้ค่าเดิม, แถวเดิม (เลขประจำตัว + ภาคเรียน) แก้ทับ ไม่มีก็เพิ่มแถวใหม่ */
function teacherFitnessSave_(req, s) {
  var term = termOf_(req.term) || s.termNow;
  if (!term) return FQ.fail('ใส่ภาคเรียนก่อน เช่น 2/2569', 'NO_TERM');
  sheet_(TAB.fitness);
  var classId = String(req.classId || '').trim();
  var roster = {};
  readRoster_().forEach(function (st) { if (st.active && st.classId === classId) roster[st.sid] = st; });
  var rows = Array.isArray(req.rows) ? req.rows.slice(0, 80) : [];
  var bad = [], clean = [];
  rows.forEach(function (r) {
    var sid = normSid_(r && r.sid), st = roster[sid];
    if (!st) return;
    var o = { sid: sid, st: st }, any = false;
    FITNESS_TESTS.forEach(function (k) {
      var f = fitValue_(r[k.key], k);
      if (!f.ok) bad.push('เลขที่ ' + (st.no || '?') + ' ' + k.label);
      o[k.key] = f.ok ? f.value : '';
      if (o[k.key] !== '') any = true;
    });
    if (any) clean.push(o);
  });
  if (bad.length) return FQ.fail('ตัวเลขผิดช่วง: ' + bad.slice(0, 5).join(', '), 'INPUT');
  var saved = withLock_(function () {
    var t = table_(TAB.fitness, H.fitness), I = t.idx, at = {}, now = timeText_(new Date()), n = 0;
    fitnessRows_(t).forEach(function (o) { if (o.term === term) at[o.sid] = o.row; });
    clean.forEach(function (o) {
      var row = at[o.sid];
      if (row) {
        var vals = t.sheet.getRange(row, 1, 1, t.width).getValues()[0];
        FITNESS_TESTS.forEach(function (k) { if (o[k.key] !== '') vals[I[k.head]] = o[k.key]; });
        vals[I['ห้อง']] = classId; vals[I['เลขที่']] = o.st.no || ''; vals[I['บันทึกเมื่อ']] = now;
        vals[I[SC.sid]] = "'" + o.sid; vals[I['ภาคเรียน']] = "'" + term;
        t.sheet.getRange(row, 1, 1, t.width).setValues([vals]);
      } else {
        var r = [];
        for (var i = 0; i < t.width; i++) r.push('');
        r[I[SC.sid]] = "'" + o.sid; r[I['ห้อง']] = classId; r[I['เลขที่']] = o.st.no || ''; r[I['ภาคเรียน']] = "'" + term;
        FITNESS_TESTS.forEach(function (k) { r[I[k.head]] = o[k.key]; });
        r[I['บันทึกเมื่อ']] = now;
        t.sheet.appendRow(r);
      }
      n++;
    });
    return n;
  });
  return { saved: saved, term: term, classId: classId };
}

/* ---------- สมัคร / เข้าสู่ระบบ (แบบโปรแกรมกระโดดเชือก) ----------
 * นักเรียนสมัครเองด้วยเลขประจำตัว ชื่อ-สกุล ชั้น ห้อง เลขที่ และตั้ง PIN 4–6 หลัก
 * PIN เก็บแบบเข้ารหัส ครูรีเซ็ตได้โดยลบช่อง PIN แล้วให้นักเรียนกด สมัครครั้งแรก อีกครั้ง
 * ฟังก์ชันในส่วนนี้ให้ผู้เรียกถือ LockService ไว้ก่อน */
function register_(req) {
  req = req || {};
  var sid = normSid_(req.studentId);
  var name = cleanText_(String(req.name || '').replace(/\s+/g, ' ').trim(), 60);
  var grade = normGrade_(req.grade), room = normRoom_(req.room), no = normNo_(req.no);
  var pin = String(req.pin === null || req.pin === undefined ? '' : req.pin).trim();
  if (!sid) return FQ.fail('เลขประจำตัวต้องเป็นตัวเลข 1–10 หลัก', 'INPUT');
  if (!/^\d{4,6}$/.test(pin)) return FQ.fail('PIN ต้องเป็นตัวเลข 4–6 หลัก', 'INPUT');
  var t = table_(TAB.roster, H.roster, H.rosterOpt);
  var s = findStudentRow_(t, sid);
  var now = new Date();
  var ph = pinHash_(sid, pin);

  if (s) {
    if (s.pinHash) return FQ.fail('เลขประจำตัวนี้สมัครไว้แล้ว ให้กด เข้าสู่ระบบ ถ้าลืม PIN ให้บอกครู', 'TAKEN');
    if (!s.active) return FQ.fail('บัญชีนี้ถูกปิดอยู่ ให้บอกครู', 'INACTIVE');
    /* ครูลบ PIN ให้ตั้งใหม่: ข้อมูลเดิมยังอยู่ เติมเฉพาะช่องที่ว่าง */
    var cells = [[SC.pin, ph], [SC.last, timeText_(now)], [SC.fails, 0], [SC.lockUntil, '']];
    if (!s.name && name) { cells.push([SC.name, name]); s.name = name.replace(/^'/, ''); }
    if (!s.grade && grade) { cells.push([SC.grade, 'ป.' + grade]); s.grade = grade; }
    if (!s.room && room) { cells.push([SC.room, room]); s.room = room; }
    if (!s.no && no) { cells.push([SC.no, no]); s.no = no; }
    setCells_(t, s.row, cells);
    s.pinHash = ph;
    s.classId = s.grade && s.room ? classIdOf_(s.grade, s.room) : '';
    return session_(s);
  }

  var need = readSettings_().sidLen;
  if (need && sid.length !== need) return FQ.fail('เลขประจำตัวต้องมี ' + need + ' หลัก ดูจากบัตรนักเรียนนะ', 'SID_LEN');
  if (!name) return FQ.fail('ใส่ชื่อ-นามสกุลก่อนนะ', 'INPUT');
  if (!grade) return FQ.fail('เลือกชั้น ป.1–ป.6 ก่อนนะ', 'INPUT');
  if (!room) return FQ.fail('ใส่ห้องเป็นตัวเลข เช่น 1', 'INPUT');
  if (!no) return FQ.fail('ใส่เลขที่เป็นตัวเลข 1–99', 'INPUT');
  var I = t.idx, row = [];
  for (var i = 0; i < t.width; i++) row.push('');
  row[I[SC.sid]] = "'" + sid;
  row[I[SC.name]] = name;
  row[I[SC.grade]] = 'ป.' + grade;
  row[I[SC.room]] = room;
  row[I[SC.no]] = no;
  row[I[SC.pin]] = ph;
  row[I[SC.created]] = timeText_(now);
  row[I[SC.last]] = timeText_(now);
  row[I[SC.fails]] = 0;
  row[I[SC.active]] = 'ใช่';
  t.sheet.appendRow(row);
  return session_({
    sid: sid, name: name.replace(/^'/, ''), grade: grade, room: room, no: no,
    classId: classIdOf_(grade, room), pinHash: ph
  });
}

function login_(req) {
  req = req || {};
  var sid = normSid_(req.studentId);
  var pin = String(req.pin === null || req.pin === undefined ? '' : req.pin).trim();
  if (!sid || !pin) return FQ.fail('ใส่เลขประจำตัวและ PIN ก่อนนะ', 'INPUT');
  var t = table_(TAB.roster, H.roster, H.rosterOpt);
  var s = findStudentRow_(t, sid);
  if (!s) return FQ.fail('ไม่พบเลขประจำตัวนี้ ถ้าใช้ครั้งแรกให้กด สมัครครั้งแรก', 'NOT_FOUND');
  if (!s.active) return FQ.fail('บัญชีนี้ถูกปิดอยู่ ให้บอกครู', 'INACTIVE');
  if (!s.pinHash) return FQ.fail('ยังไม่ได้ตั้ง PIN ให้กด สมัครครั้งแรก เพื่อตั้ง PIN', 'NO_PIN');
  var now = new Date();
  if (s.lockUntil && s.lockUntil.getTime() > now.getTime()) {
    var mins = Math.ceil((s.lockUntil.getTime() - now.getTime()) / 60000);
    return FQ.fail('ใส่ PIN ผิดหลายครั้ง ลองใหม่ในอีก ' + mins + ' นาที หรือให้ครูลบ PIN', 'LOCKED');
  }
  if (pinHash_(sid, pin) !== s.pinHash) {
    var fails = s.fails + 1, locked = fails >= MAX_STRIKES;
    setCells_(t, s.row, [
      [SC.fails, locked ? 0 : fails],
      [SC.lockUntil, locked ? timeText_(new Date(now.getTime() + LOCK_SECONDS * 1000)) : '']
    ]);
    return locked
      ? FQ.fail('ใส่ PIN ผิดหลายครั้ง ล็อก ' + (LOCK_SECONDS / 60) + ' นาที', 'LOCKED')
      : FQ.fail('PIN ไม่ถูกต้อง ลองใหม่อีกครั้ง', 'BAD_PIN');
  }
  setCells_(t, s.row, [[SC.fails, 0], [SC.lockUntil, ''], [SC.last, timeText_(now)]]);
  return session_(s);
}

/* ผลที่ส่งกลับหลังสมัครหรือเข้าสู่ระบบ: หน้าเว็บจำตั๋วไว้ ไม่ต้องใส่ PIN ทุกครั้ง */
function session_(s) {
  return { ok: true, token: makeToken_(s.sid, s.pinHash), profile: profileOf_(s) };
}
function profileOf_(s) {
  return { studentId: s.sid, name: s.name, grade: s.grade, room: s.room, no: s.no, classId: s.classId };
}

/* ตรวจตั๋วที่หน้าเว็บจำไว้ ตั๋วใช้ไม่ได้ทันทีเมื่อครูลบหรือเปลี่ยน PIN */
function authToken_(token) {
  var parts = String(token || '').split('.');
  var sid = parts.length === 2 ? normSid_(parts[0]) : '';
  if (!sid || !parts[1]) return FQ.fail('กรุณาเข้าสู่ระบบใหม่', 'AUTH');
  var t = table_(TAB.roster, H.roster, H.rosterOpt);
  var s = findStudentRow_(t, sid);
  if (!s || !s.pinHash || makeToken_(sid, s.pinHash) !== String(token)) return FQ.fail('กรุณาเข้าสู่ระบบใหม่', 'AUTH');
  if (!s.active) return FQ.fail('บัญชีนี้ถูกปิดอยู่ ให้บอกครู', 'INACTIVE');
  return { ok: true, student: s, table: t };
}

function makeToken_(sid, ph) { return sid + '.' + hmac_(sid + '|' + ph).slice(0, 40); }
function pinHash_(sid, pin) { return 'h1:' + sha256_(secret_() + '|' + sid + '|' + pin); }
function secret_() {
  var props = PropertiesService.getScriptProperties();
  var s = props.getProperty('SECRET');
  if (!s) {
    s = Utilities.getUuid() + Utilities.getUuid();
    props.setProperty('SECRET', s);
  }
  return s;
}
function sha256_(text) {
  return hex_(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, text, Utilities.Charset.UTF_8));
}
function hmac_(text) {
  return hex_(Utilities.computeHmacSha256Signature(text, secret_(), Utilities.Charset.UTF_8));
}
function hex_(bytes) {
  return bytes.map(function (b) { var v = (b + 256) % 256; return (v < 16 ? '0' : '') + v.toString(16); }).join('');
}

/* ---------- ตรวจสิทธิ์: ใช้ตั๋วที่ได้ตอนสมัครหรือเข้าสู่ระบบ ---------- */
function auth_(c, req) {
  var a = authToken_(req && req.token);
  if (!a.ok) return a;
  var s = a.student;
  if (!s.classId) return FQ.fail('ข้อมูลชั้นหรือห้องไม่ครบ ให้บอกครู', 'NO_CLASS');
  return { ok: true, klass: klassOf_(c, s), student: s };
}

/* ห้องของนักเรียนมาจากชั้นกับห้องที่กรอกตอนสมัคร วันเริ่มกับจำนวนสัปดาห์ใช้ค่าเดียวทั้งโรงเรียน */
function klassOf_(c, s) {
  return { id: s.classId, grade: s.grade, start: c.settings.programStart, weeks: c.settings.programWeeks };
}

/* ---------- อ่านและเขียนชีต ---------- */
function load_() {
  return { settings: readSettings_(), roster: readRoster_(), quests: readQuests_(), events: readEvents_() };
}

function sheet_(name) {
  var sh = SpreadsheetApp.getActive().getSheetByName(name);
  if (!sh) throw new Error('ไม่พบแท็บ "' + name + '" ให้ครูกดเมนู ' + APP_NAME + ' → 1) ตั้งค่าครั้งแรก');
  return sh;
}

function headIdx_(sh, name, headers, optional) {
  var width = Math.max(sh.getLastColumn(), headers.length);
  var head = sh.getLastRow() >= 1 ? sh.getRange(1, 1, 1, width).getValues()[0].map(function (v) { return String(v).trim(); }) : [];
  var idx = {};
  headers.forEach(function (h) {
    var i = head.indexOf(h);
    if (i < 0) throw new Error('แท็บ "' + name + '" ไม่มีหัวคอลัมน์ "' + h + '" อย่าเปลี่ยนชื่อหัวคอลัมน์');
    idx[h] = i;
  });
  (optional || []).forEach(function (h) { var i = head.indexOf(h); if (i >= 0) idx[h] = i; });
  return { idx: idx, width: width };
}

/* อ่านทั้งแท็บ: data[i] คือแถวที่ base + i */
function table_(name, headers, optional) {
  var sh = sheet_(name);
  var lastRow = sh.getLastRow();
  var h = headIdx_(sh, name, headers, optional);
  var data = lastRow >= 2 ? sh.getRange(2, 1, lastRow - 1, h.width).getValues() : [];
  return { sheet: sh, idx: h.idx, data: data, width: h.width, base: 2 };
}

/* อ่านเฉพาะท้ายแท็บ: แถวที่ส่งตั้งแต่วันที่ from เป็นต้นไป (from ว่าง = อ่านทั้งแท็บ)
 * ระบบเขียนต่อท้ายเสมอ แถวจึงเรียงตามเวลาที่ส่ง อ่านจากล่างขึ้นบนทีละก้อน
 * หยุดเมื่อแถวบนสุดของก้อนที่มีเวลา ส่งก่อนวันตัดเกิน 1 วัน (แถวที่วันที่ทำ ≥ from ต้องส่งตั้งแต่ from) */
var TAIL_CHUNK = 1000;
function tail_(name, headers, from) {
  if (!from) return table_(name, headers);
  var sh = sheet_(name);
  var h = headIdx_(sh, name, headers), col = h.idx['เวลาที่ส่ง'];
  var stop = FQ.addDays(from, -1), top = sh.getLastRow() + 1, data = [];
  while (top > 2) {
    var n = Math.min(TAIL_CHUNK, top - 2), start = top - n;
    var block = sh.getRange(start, 1, n, h.width).getValues();
    data = block.concat(data);
    top = start;
    var old = false;
    for (var i = 0; i < block.length; i++) {
      var k = sentDay_(block[i][col]);
      if (k) { old = k < stop; break; }
    }
    if (old) break;
  }
  return { sheet: sh, idx: h.idx, data: data, width: h.width, base: top };
}
/* วันที่จากช่องเวลาที่ส่ง (ข้อความ yyyy-MM-dd HH:mm:ss หรือวันที่ที่ครูพิมพ์) */
function sentDay_(v) {
  if (v === '' || v === null || v === undefined) return '';
  return keyOf_(typeof v === 'string' ? v.replace(/^'/, '').trim() : v, TZ);
}

function sheetTz_() {
  try { return SpreadsheetApp.getActive().getSpreadsheetTimeZone() || TZ; } catch (e) { return TZ; }
}
function keyOf_(v, tz) {
  if (Object.prototype.toString.call(v) === '[object Date]') {
    if (isNaN(v.getTime())) return '';
    return FQ.toKey(Utilities.formatDate(v, tz || sheetTz_(), 'yyyy-MM-dd'));
  }
  return FQ.toKey(v);
}
function todayKey_() { return Utilities.formatDate(new Date(), TZ, 'yyyy-MM-dd'); }
function nowText_() { return Utilities.formatDate(new Date(), TZ, 'yyyy-MM-dd HH:mm:ss'); }
function newId_() { return Utilities.getUuid().replace(/-/g, '').slice(0, 10); }
/* เลขประจำตัว: ตัวเลข 1–10 หลัก เก็บเป็นข้อความเพื่อให้เลข 0 หน้าสุดไม่หาย */
function normSid_(v) {
  var s = String(v === null || v === undefined ? '' : v).trim().replace(/^'/, '').replace(/\s+/g, '');
  return /^\d{1,10}$/.test(s) ? s : '';
}
function intIn_(v, lo, hi) {
  var n = parseInt(String(v === null || v === undefined ? '' : v).replace(/[^\d]/g, ''), 10);
  return n >= lo && n <= hi ? n : 0;
}
function normGrade_(v) { return intIn_(v, 1, 6); }   /* 'ป.4' หรือ 4 → 4 */
function normRoom_(v) { return intIn_(v, 1, 30); }
function normNo_(v) { return intIn_(v, 1, 99); }
function classIdOf_(grade, room) { return 'ป.' + grade + '/' + room; }
/* เวลาเก็บในชีตเป็นข้อความ yyyy-MM-dd HH:mm:ss เวลาไทย */
function timeText_(d) { return "'" + Utilities.formatDate(d, TZ, 'yyyy-MM-dd HH:mm:ss'); }
function timeOf_(v) {
  if (Object.prototype.toString.call(v) === '[object Date]') return isNaN(v.getTime()) ? null : v;
  var m = String(v === null || v === undefined ? '' : v).trim().replace(/^'/, '')
    .match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?$/);
  if (!m) return null;
  return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4] - 7, +m[5], +(m[6] || 0)));
}
/* กันข้อความที่ขึ้นต้นด้วย = + - @ ถูกตีความเป็นสูตรในชีต */
function cleanText_(s, max) {
  var t = String(s === null || s === undefined ? '' : s).slice(0, max);
  return /^[=+\-@]/.test(t) ? "'" + t : t;
}

function readSettings_() {
  var raw = {};
  var sh = SpreadsheetApp.getActive().getSheetByName(TAB.settings);
  if (sh && sh.getLastRow() >= 2) {
    sh.getRange(2, 1, sh.getLastRow() - 1, 2).getValues().forEach(function (r) {
      var label = String(r[0]).trim(), alias = SETTING_ALIASES[label] || '';
      SETTING_ROWS.forEach(function (d) {
        if (d[0] !== label && d[1] !== alias) return;
        var v = r[1];
        if (d[1] === 'programStart') v = keyOf_(v);
        else if (d[1] === 'termNow' && Object.prototype.toString.call(v) === '[object Date]') v = (v.getMonth() + 1) + '/' + v.getFullYear();
        raw[d[1]] = v;
      });
      if (alias && !SETTING_ROWS.some(function (d) { return d[1] === alias; })) raw[alias] = r[1];
    });
  }
  return FQ.normSettings(raw);
}

function readRoster_() {
  var t = table_(TAB.roster, H.roster, H.rosterOpt);
  return t.data.map(function (r, i) { return studentFromRow_(t, r, i + 2); })
    .filter(function (s) { return s.sid; });
}

/* แถวในแท็บนักเรียน → ข้อมูลนักเรียน 1 คน */
function studentFromRow_(t, r, row) {
  var I = t.idx;
  var sid = normSid_(r[I[SC.sid]]);
  var grade = normGrade_(r[I[SC.grade]]), room = normRoom_(r[I[SC.room]]);
  return {
    row: row,
    sid: sid,
    code: sid, /* บันทึกในแท็บบันทึกอ้างถึงนักเรียนด้วยเลขประจำตัว */
    name: String(r[I[SC.name]] || '').trim(),
    grade: grade,
    room: room,
    no: normNo_(r[I[SC.no]]),
    classId: grade && room ? classIdOf_(grade, room) : '',
    pinHash: String(r[I[SC.pin]] || '').trim(),
    fails: Number(r[I[SC.fails]]) || 0,
    lockUntil: timeOf_(r[I[SC.lockUntil]]),
    active: String(r[I[SC.active]]).trim() !== 'ไม่',
    created: keyOf_(typeof r[I[SC.created]] === 'string' ? String(r[I[SC.created]]).replace(/^'/, '') : r[I[SC.created]], TZ),
    nick: opt(SC.nick).replace(/^'/, '').slice(0, 20),
    nickAt: keyOf_(opt(SC.nickAt).replace(/^'/, ''), TZ), nickLock: opt(SC.nickLock) === 'ใช่',
    outfit: opt(SC.outfit), color: opt(SC.color), sports: opt(SC.sports), goal: opt(SC.goal), motto: opt(SC.motto), pins: opt(SC.pins),
    photo: opt(SC.photo), photoOk: opt(SC.photoOk)
  };
  function opt(h) {
    var v = I[h] === undefined ? '' : r[I[h]];
    if (Object.prototype.toString.call(v) === '[object Date]') return Utilities.formatDate(v, TZ, 'yyyy-MM-dd');
    return String(v === null || v === undefined ? '' : v).trim();
  }
}

function findStudentRow_(t, sid) {
  for (var i = 0; i < t.data.length; i++) {
    if (normSid_(t.data[i][t.idx[SC.sid]]) === sid) return studentFromRow_(t, t.data[i], i + 2);
  }
  return null;
}

function setCells_(t, row, pairs) {
  pairs.forEach(function (p) { t.sheet.getRange(row, t.idx[p[0]] + 1).setValue(p[1]); });
}

/* ภารกิจประจำวันที่ครูตั้งไว้ ถ้ายังไม่มีแท็บ (ยังไม่ได้กดเมนู 1 หลังอัปเดตโค้ด) ใช้ชุดตั้งต้น */
var TYPE_BY_SHEET = { 'ขยับ': 'move', 'สุขนิสัย': 'habit', 'เควสบ้าน': 'quest' };
var SHEET_BY_TYPE = { move: 'ขยับ', habit: 'สุขนิสัย', quest: 'เควสบ้าน' };
function readMissionPool_() {
  var sh = SpreadsheetApp.getActive().getSheetByName(TAB.missions);
  if (!sh) return FQ.DEFAULT_MISSIONS;
  var t;
  try { t = table_(TAB.missions, H.missions, [CLIP_HEAD, OUTDOOR_HEAD]); } catch (e) { return FQ.DEFAULT_MISSIONS; }
  var I = t.idx;
  return t.data.map(function (r) {
    var steps = ['ขั้น 1', 'ขั้น 2', 'ขั้น 3', 'ขั้น 4'].map(function (h) { return String(r[I[h]] || '').trim(); });
    var out = I[OUTDOOR_HEAD] === undefined ? '' : String(r[I[OUTDOOR_HEAD]] || '').trim();
    return {
      type: TYPE_BY_SHEET[String(r[I['ประเภท']]).trim()] || '',
      steps: steps,
      clip: I[CLIP_HEAD] === undefined ? '' : safeClip_(r[I[CLIP_HEAD]]),
      active: String(r[I['ใช้งาน']]).trim() !== 'ไม่',
      /* กลางแจ้ง: ใช่ / ไม่ / ว่าง = เดาจากข้อความ */
      outdoor: out === 'ใช่' ? true : out === 'ไม่' ? false : OUTDOOR_RX.test(steps.join(' '))
    };
  }).filter(function (m) { return m.type && m.steps.some(function (x) { return !!x; }); });
}

function readDone_() {
  if (!SpreadsheetApp.getActive().getSheetByName(TAB.done)) return [];
  return doneFromTable_(table_(TAB.done, H.done));
}

function doneFromTable_(t) {
  var I = t.idx, tz = sheetTz_(), out = [], base = t.base || 2;
  t.data.forEach(function (r, i) {
    var code = normSid_(r[I[SC.sid]]), type = TYPE_BY_SHEET[String(r[I['ประเภท']]).trim()];
    var date = keyOf_(r[I['วันที่ทำ']], tz);
    if (!code || !type || !date) return;
    var proof = String(r[I['หลักฐาน']] || '').trim(), text = String(r[I['ภารกิจ']] || '').trim();
    out.push({
      row: i + base,
      id: String(r[I['รหัส']] || '').trim(),
      date: date,
      classId: String(r[I['ห้อง']]).trim(),
      code: code,
      type: type,
      text: text,
      tag: FQ.tagOf(text),
      diff: Math.min(3, Math.max(1, (String(r[I['ความยาก']] || '').match(/⭐/g) || []).length || parseInt(r[I['ความยาก']], 10) || 1)),
      proof: proof === 'ไม่มี' ? '' : proof,
      file: String(r[I['ไฟล์']] || '').trim(),
      gesture: String(r[I['ท่าลับ']] || '').trim(),
      check: String(r[I['ครูตรวจ']] || '').trim()
    });
  });
  return out;
}

function writeDone_(t, rec, now) {
  var I = t.idx, row = [];
  for (var i = 0; i < t.width; i++) row.push('');
  row[I['รหัส']] = rec.id;
  row[I['เวลาที่ส่ง']] = "'" + now;
  row[I['วันที่ทำ']] = "'" + rec.date;
  row[I['ห้อง']] = rec.classId;
  row[I[SC.sid]] = "'" + rec.code;
  row[I['ประเภท']] = SHEET_BY_TYPE[rec.type];
  row[I['ภารกิจ']] = cleanText_(rec.text, 200);
  row[I['ความยาก']] = rec.type === 'quest' ? '' : FQ.DIFF_STARS[rec.diff || 1];
  row[I['หลักฐาน']] = rec.proof || 'ไม่มี';
  row[I['ไฟล์']] = rec.file || '';
  row[I['ท่าลับ']] = rec.gesture || '';
  t.sheet.appendRow(row);
}

/* ลิงก์คลิปสาธิต: รับเฉพาะ YouTube หรือ Google Drive (https) */
function safeClip_(v) {
  var u = String(v === null || v === undefined ? '' : v).trim();
  return /^https:\/\/((www|m)\.)?(youtube\.com|youtu\.be|drive\.google\.com)\/[^\s"'<>]*$/.test(u) ? u.slice(0, 300) : '';
}

/* คำถามสุขภาพ: ตำแหน่งคำตอบที่ถูกสลับให้ ก ข ค ง วนกันไป */
function questionRows_() {
  return DEFAULT_QUESTIONS.map(function (x, i) {
    var pos = (i * 3 + 1) % 4, wrong = [x[3], x[4], x[5]], ch = [];
    for (var k = 0, w = 0; k < 4; k++) ch.push(k === pos ? x[2] : wrong[w++]);
    return [x[0] === 'low' ? 'ป.1–3' : 'ป.4–6', x[1]].concat(ch, [LETTERS[pos], x[6], 'ใช่']);
  });
}
function questionOf_(r, I) {
  var lv = String(r[I['ช่วงชั้น']]).trim();
  var level = /1\s*[–\-]\s*3/.test(lv) ? 'low' : /4\s*[–\-]\s*6/.test(lv) ? 'high' : /ทุก|ทั้งหมด/.test(lv) ? 'all' : '';
  var q = String(r[I['คำถาม']] || '').trim();
  return {
    level: level, q: q, ref: q.slice(0, 120),
    choices: ['ตัวเลือก ก', 'ตัวเลือก ข', 'ตัวเลือก ค', 'ตัวเลือก ง'].map(function (h) { return String(r[I[h]] === undefined ? '' : r[I[h]]).trim(); }),
    answer: LETTERS.indexOf(String(r[I['เฉลย']] || '').trim().replace(/^ข้อ\s*/, '').charAt(0)),
    why: String(r[I['อธิบาย']] || '').trim(),
    active: String(r[I['ใช้งาน']]).trim() !== 'ไม่'
  };
}
function readQuestions_() {
  var I = {};
  H.questions.forEach(function (h, i) { I[h] = i; });
  var fallback = function () { return questionRows_().map(function (r) { return questionOf_(r, I); }); };
  if (!SpreadsheetApp.getActive().getSheetByName(TAB.questions)) return fallback();
  var t;
  try { t = table_(TAB.questions, H.questions); } catch (e) { return fallback(); }
  return t.data.map(function (r) { return questionOf_(r, t.idx); }).filter(function (q) { return q.level && q.q; });
}

/* อีเวนต์: เฉพาะแถวที่มีชื่อ วันเริ่ม วันจบ และภารกิจอย่างน้อย 1 ข้อ */
function readEvents_() {
  if (!SpreadsheetApp.getActive().getSheetByName(TAB.events)) return [];
  var t;
  try { t = table_(TAB.events, H.events); } catch (e) { return []; }
  var I = t.idx, tz = sheetTz_(), out = [], seen = {};
  t.data.forEach(function (r, i) {
    if (String(r[I['ใช้งาน']]).trim() === 'ไม่') return;
    var name = String(r[I['ชื่ออีเวนต์']] || '').trim(), start = keyOf_(r[I['เริ่ม']], tz), end = keyOf_(r[I['จบ']], tz);
    if (!name || !start || !end || end < start) return;
    var id = String(r[I['รหัส']] || '').trim().replace(/[^\w\-]/g, '').slice(0, 30) || ('ev' + (i + 2));
    if (seen[id]) id += '_' + (i + 2);
    seen[id] = 1;
    var tasks = [];
    for (var k = 1; k <= 3; k++) {
      var text = String(r[I['ภารกิจ ' + k]] || '').trim(), kind = FQ.eventKind(r[I['นับจาก ' + k]]);
      if (!text || !kind) continue;
      var need = kind === 'check' ? 1 : Math.max(1, Math.min(9999, parseInt(r[I['เป้า ' + k]], 10) || 1));
      tasks.push({ n: k, text: text.slice(0, 120), kind: kind, need: need });
    }
    if (!tasks.length) return;
    out.push({
      id: id, name: name.slice(0, 60), start: start, end: end, invite: String(r[I['คำชวน']] || '').trim().slice(0, 160),
      tasks: tasks, sticker: String(r[I['สติกเกอร์']] || '').trim().slice(0, 60)
    });
  });
  return out;
}

var KIND_BY_SHEET = { 'คำถาม': 'quiz', 'อีเวนต์': 'event', 'กำลังใจ': 'cheer', 'คลิป': 'clip', 'นักสู้ฝุ่น': 'dust' };
var SHEET_BY_KIND = { quiz: 'คำถาม', event: 'อีเวนต์', cheer: 'กำลังใจ', clip: 'คลิป', dust: 'นักสู้ฝุ่น' };
function extrasFromTable_(t) {
  var I = t.idx, tz = sheetTz_(), base = t.base || 2, out = [];
  t.data.forEach(function (r, i) {
    var code = normSid_(r[I[SC.sid]]), kind = KIND_BY_SHEET[String(r[I['ประเภท']]).trim()], date = keyOf_(r[I['วันที่ทำ']], tz);
    if (!code || !kind || !date) return;
    var ref = String(r[I['เรื่อง']] || '').trim();
    if (kind === 'event') { var m = /^[\w\-]+#\d+/.exec(ref); ref = m ? m[0] : ref; }
    if (kind === 'cheer') { var c = /\d{1,10}/.exec(ref); ref = c ? c[0] : ''; }
    if (kind === 'clip') ref = TYPE_BY_SHEET[ref.split(/[\s:]/)[0]] || '';
    out.push({
      row: i + base, id: String(r[I['รหัส']] || '').trim(), date: date, classId: String(r[I['ห้อง']]).trim(), code: code,
      kind: kind, ref: ref, answer: LETTERS.indexOf(String(r[I['คำตอบ']] || '').trim().charAt(0)),
      ok: kind === 'event' || String(r[I['ผล']]).trim() === 'ถูก', check: String(r[I['ครูตรวจ']] || '').trim()
    });
  });
  return out;
}
function readExtra_() {
  if (!SpreadsheetApp.getActive().getSheetByName(TAB.extra)) return [];
  return extrasFromTable_(table_(TAB.extra, H.extra));
}
function writeExtra_(t, rec, now) {
  var I = t.idx, row = [];
  for (var i = 0; i < t.width; i++) row.push('');
  row[I['รหัส']] = rec.id;
  row[I['เวลาที่ส่ง']] = "'" + now;
  row[I['วันที่ทำ']] = "'" + rec.date;
  row[I['ห้อง']] = rec.classId;
  row[I[SC.sid]] = "'" + rec.code;
  row[I['ประเภท']] = SHEET_BY_KIND[rec.kind];
  row[I['เรื่อง']] = cleanText_(rec.kind === 'event' ? rec.ref + ' ' + (rec.text || '') : rec.kind === 'cheer' ? 'ให้กำลังใจ ' + rec.ref :
    rec.kind === 'clip' ? SHEET_BY_TYPE[rec.ref] + ' ' + (rec.text || '') : rec.kind === 'dust' ? rec.ref + ' ' + (rec.text || '') : rec.ref, 160);
  row[I['คำตอบ']] = rec.kind === 'quiz' ? LETTERS[rec.answer] || '' : rec.kind === 'cheer' ? '👏' : rec.kind === 'clip' ? '▶ ดูครบ' : 'ทำแล้ว';
  row[I['ผล']] = rec.kind === 'quiz' ? (rec.ok ? 'ถูก' : 'ผิด') : rec.kind === 'clip' ? 'ดูครบ' : 'ทำแล้ว';
  t.sheet.appendRow(row);
}

function readQuests_() {
  var out = {};
  if (!SpreadsheetApp.getActive().getSheetByName(TAB.quests)) return out;
  var t = table_(TAB.quests, H.quests, [QUEST_CLIP_HEAD]), I = t.idx;
  t.data.forEach(function (r) {
    var w = parseInt(r[I['สัปดาห์']], 10);
    if (w >= 1) out[w] = {
      low: String(r[I['เควสบ้าน ป.1–3']] || '').trim(), high: String(r[I['เควสบ้าน ป.4–6']] || '').trim(),
      clip: I[QUEST_CLIP_HEAD] === undefined ? '' : safeClip_(r[I[QUEST_CLIP_HEAD]])
    };
  });
  return out;
}

/* ใส่คลิปตั้งต้นในแท็บภารกิจประจำวัน: เฉพาะช่องคลิปที่ว่าง และข้อความขั้น 1 ตรงกับภารกิจตั้งต้น (ครูแก้ข้อความไว้ = ไม่แตะ) */
function fillClips_() {
  var sh = SpreadsheetApp.getActive().getSheetByName(TAB.missions);
  if (!sh) return { noTab: true, n: 0 };
  var t = table_(TAB.missions, H.missions, [CLIP_HEAD]);
  if (t.idx[CLIP_HEAD] === undefined) {
    var c0 = sh.getLastColumn() + 1;
    sh.getRange(1, c0).setValue(CLIP_HEAD);
    t = table_(TAB.missions, H.missions, [CLIP_HEAD]);
  }
  var byStep = {}, n = 0;
  FQ.DEFAULT_MISSIONS.forEach(function (m) { if (m.clip) byStep[m.type + '|' + m.steps[0]] = m.clip; });
  t.data.forEach(function (r, i) {
    var type = TYPE_BY_SHEET[String(r[t.idx['ประเภท']]).trim()] || '';
    var clip = byStep[type + '|' + String(r[t.idx['ขั้น 1']] || '').trim()];
    if (!clip || String(r[t.idx[CLIP_HEAD]] || '').trim()) return;
    sh.getRange(i + 2, t.idx[CLIP_HEAD] + 1).setValue(clip);
    n++;
  });
  return { n: n };
}

function logsFromTable_(t) {
  var I = t.idx, tz = sheetTz_(), base = t.base || 2;
  var out = [];
  t.data.forEach(function (r, i) {
    var classId = String(r[I['ห้อง']]).trim(), code = normSid_(r[I[SC.sid]]);
    if (!code) return;
    out.push({
      row: i + base,
      id: String(r[I['รหัสบันทึก']] || '').trim(),
      date: keyOf_(r[I['วันที่ทำ']], tz),
      classId: classId,
      code: code,
      activity: String(r[I['กิจกรรม']] || '').trim(),
      minutes: Number(r[I['นาที']]) || 0,
      feeling: String(r[I['ความรู้สึก']] || '').trim(),
      excluded: String(r[I['ครูตรวจ']]).trim() === 'ไม่นับ',
      channel: String(r[I['ช่องทาง']] || '').trim()
    });
  });
  return out;
}

function writeLog_(t, rec, now) {
  var I = t.idx, row = [];
  for (var i = 0; i < t.width; i++) row.push('');
  row[I['รหัสบันทึก']] = rec.id;
  row[I['เวลาที่ส่ง']] = "'" + now;
  row[I['วันที่ทำ']] = "'" + rec.date;
  row[I['ห้อง']] = rec.classId;
  row[I[SC.sid]] = "'" + rec.code; /* ' นำหน้า กันเลข 0 หน้าสุดหาย */
  row[I['สัปดาห์']] = rec.week || '';
  row[I['กิจกรรม']] = rec.activity;
  row[I['นาที']] = rec.minutes;
  row[I['ความรู้สึก']] = rec.feeling;
  row[I['ช่องทาง']] = rec.channel;
  t.sheet.appendRow(row);
}

function status_(c, a, mine) {
  var st = FQ.buildStatus({
    settings: c.settings, klass: a.klass, student: a.student, logs: mine.logs, quests: c.quests,
    done: mine.done || [], pool: c.pool, todayKey: todayKey_(), extra: mine.extra || [], events: c.events || [], questions: c.questions || [],
    board: readBoard_(), rank: mine.snap ? mine.snap.rank : null, dust: c.dust
  });
  st.ok = true;
  st.profile = profileOf_(a.student);
  st.fitness = fitnessOf_(a.student.sid);
  st.me = FQ.profileView(a.student, st.xp, c.settings, todayKey_(), c.events);
  st.cheers = { week: cheersWeek_(mine) };
  st.game = myGame_(a.student.sid, st.xp);
  return st;
}

/* กำลังใจที่ได้สัปดาห์นี้ = ส่วนเก่าในแคช + ที่อ่านสดจากท้ายแท็บ */
function cheersWeek_(mine) {
  var ws = FQ.addDays(todayKey_(), -FQ.weekdayIdx(todayKey_())), snap = mine.snap || {};
  var old = snap.cheers && snap.cheers[0] === ws ? Number(snap.cheers[1]) || 0 : 0;
  return old + (mine.cheersIn || []).filter(function (x) { return x.date >= ws; }).length;
}

/* ---------- แคชรายคน: ทำให้เปิดแอปเร็วตลอดปี ----------
 * ทุกชั่วโมงระบบเก็บบันทึกและภารกิจ "ก่อนวันตัด" ของแต่ละคนไว้ในแท็บแคชระบบ (วันตัด = วันนี้ − วันที่บันทึกย้อนหลังได้)
 * ส่วนก่อนวันตัดเด็กแก้ไม่ได้แล้ว (บันทึก ลบ ทำภารกิจ ส่งรูป ทำได้เฉพาะวันที่ยังไม่ถึงวันตัด)
 * ตอนเด็กเปิดแอป: อ่านแคชของคนนั้น 1 แถว + อ่านสดเฉพาะท้ายแท็บตั้งแต่วันตัด
 * ครูแก้ส่วนเก่า (ไม่นับ / ผลตรวจ) เด็กเห็นหลังระบบอัปเดตรอบถัดไป ไม่เกิน 1 ชั่วโมง */
var CODE_TYPE = { move: 'm', habit: 'h', quest: 'q' }, TYPE_CODE = { m: 'move', h: 'habit', q: 'quest' };
var CODE_PROOF = { 'รูป': 'p', 'วิดีโอ': 'v', 'สาธิตในคาบ': 's' }, PROOF_CODE = { p: 'รูป', v: 'วิดีโอ', s: 'สาธิตในคาบ' };
var CODE_CHECK = { 'ผ่าน': 'y', 'ไม่ผ่าน': 'n', 'ไม่นับ': 'x' }, CHECK_CODE = { y: 'ผ่าน', n: 'ไม่ผ่าน', x: 'ไม่นับ' };

function packLogs_(list) {
  return JSON.stringify(list.map(function (l) {
    var a = FQ.findActivity(l.activity), f = FQ.findFeeling(l.feeling);
    return [FQ.dayNum(l.date), Number(l.minutes) || 0, a ? a.id : String(l.activity || '').slice(0, 30), f ? f.id : '', l.excluded ? 1 : 0];
  }));
}
function unpackLogs_(json, code) {
  return (JSON.parse(json || '[]') || []).map(function (x) {
    var a = FQ.findActivity(x[2]), f = FQ.findFeeling(x[3]);
    return {
      row: 0, id: '', date: FQ.fromDayNum(x[0]), classId: '', code: code,
      activity: a ? a.label : String(x[2] || ''), minutes: Number(x[1]) || 0, feeling: f ? f.label : '',
      excluded: x[4] === 1, channel: ''
    };
  });
}
function packDone_(list) {
  return JSON.stringify(list.map(function (m) {
    return [FQ.dayNum(m.date), CODE_TYPE[m.type] || 'm', m.diff || 0, CODE_PROOF[m.proof] || '', CODE_CHECK[m.check] || '', m.tag || ''];
  }));
}
function unpackDone_(json, code) {
  return (JSON.parse(json || '[]') || []).map(function (x) {
    return {
      row: 0, id: '', date: FQ.fromDayNum(x[0]), classId: '', code: code, type: TYPE_CODE[x[1]] || 'move', text: '',
      diff: Number(x[2]) || 0, proof: PROOF_CODE[x[3]] || '', file: '', gesture: '', check: CHECK_CODE[x[4]] || '', tag: x[5] || ''
    };
  });
}

function packExtra_(list) {
  return JSON.stringify(list.map(function (x) {
    return [FQ.dayNum(x.date), x.kind === 'event' ? 'e' : x.kind === 'clip' ? 'c' : x.kind === 'dust' ? 'd' : 'q', x.ok ? 1 : 0, x.kind === 'quiz' ? '' : x.ref, CODE_CHECK[x.check] || ''];
  }));
}
function unpackExtra_(json, code) {
  return (JSON.parse(json || '[]') || []).map(function (x) {
    return {
      row: 0, id: '', date: FQ.fromDayNum(x[0]), classId: '', code: code, kind: x[1] === 'e' ? 'event' : x[1] === 'c' ? 'clip' : x[1] === 'd' ? 'dust' : 'quiz',
      ref: x[3] || '', answer: -1, ok: x[2] === 1, check: CHECK_CODE[x[4]] || ''
    };
  });
}

/* แคชของนักเรียน 1 คน (ไม่มี = อ่านทั้งแท็บเหมือนเดิม ช้ากว่าแต่ถูกต้อง) */
function readSnap_(code) {
  var none = { logs: [], done: [], extra: [], cutoff: '', rank: null, cheers: null };
  var sh = SpreadsheetApp.getActive().getSheetByName(TAB.cache);
  if (!sh || sh.getLastRow() < 3 || !code) return none;
  var hit = sh.getRange(3, 1, sh.getLastRow() - 2, 1).createTextFinder(code).matchEntireCell(true).findNext();
  if (!hit) return none;
  var v = sh.getRange(hit.getRow(), 1, 1, H.cache.length).getValues()[0];
  var cutoff = keyOf_(v[3], TZ);
  if (normSid_(v[0]) !== code || !cutoff) return none;
  try {
    return {
      logs: unpackLogs_(v[1], code), done: unpackDone_(v[2], code), extra: unpackExtra_(v[6], code),
      cutoff: cutoff, rank: v[4] ? JSON.parse(v[4]) : null, cheers: v[7] ? JSON.parse(v[7]) : null
    };
  } catch (e) {
    return none;
  }
}
function readBoard_() {
  var sh = SpreadsheetApp.getActive().getSheetByName(TAB.cache);
  if (!sh || sh.getLastRow() < 2) return null;
  try { return JSON.parse(sh.getRange(2, 2).getValue() || 'null'); } catch (e) { return null; }
}

/* บันทึกและภารกิจทั้งหมดของเด็กคนนี้ = แคช (ก่อนวันตัด) + อ่านสดจากท้ายแท็บ (ตั้งแต่วันตัด)
 * lt/dt = ท้ายแท็บที่อ่านมา ใช้เขียนหรือลบแถวต่อ (เลขแถวถูกต้องเมื่ออ่านในล็อก) */
function loadMine_(c, a, snap) {
  var code = a.student.code;
  snap = snap || readSnap_(code);
  /* ถ้าครูเพิ่มวันบันทึกย้อนหลังหลังสร้างแคช ตัดให้เร็วขึ้นตาม ไม่มีรายการหายหรือซ้ำ */
  var cut = snap.cutoff, early = FQ.addDays(todayKey_(), -c.settings.backfillDays);
  if (cut && early < cut) cut = early;
  var old = function (x) { return !cut || x.date < cut; };
  var fresh = function (x) { return x.code === code && (!cut || x.date >= cut); };
  var lt = tail_(TAB.logs, H.logs, cut);
  var logs = snap.logs.filter(old).concat(logsFromTable_(lt).filter(fresh));
  var dt = null, done = snap.done.filter(old);
  if (SpreadsheetApp.getActive().getSheetByName(TAB.done)) {
    dt = tail_(TAB.done, H.done, cut);
    done = done.concat(doneFromTable_(dt).filter(fresh));
  }
  var xt = null, extra = (snap.extra || []).filter(old), cheersIn = [];
  if (SpreadsheetApp.getActive().getSheetByName(TAB.extra)) {
    xt = tail_(TAB.extra, H.extra, cut);
    var all = extrasFromTable_(xt);
    extra = extra.concat(all.filter(fresh));
    cheersIn = all.filter(function (x) { return x.kind === 'cheer' && x.ref === code && x.check !== 'ไม่นับ' && (!cut || x.date >= cut); });
    xt.all = all;
  }
  return { logs: logs, done: done, extra: extra, cheersIn: cheersIn, snap: snap, lt: lt, dt: dt, xt: xt };
}

function safe_(fn) {
  try {
    return fn();
  } catch (e) {
    console.error(e && e.stack ? e.stack : e);
    var msg = String(e && e.message ? e.message : e);
    if (/lock/i.test(msg)) return FQ.fail('ตอนนี้มีคนบันทึกพร้อมกันเยอะ กดส่งอีกครั้งนะ', 'BUSY');
    return FQ.fail('ระบบขัดข้อง ลองใหม่อีกครั้ง หรือแจ้งครู (' + msg + ')', 'ERROR');
  }
}

/* ---------- เมนูของครูในชีต ---------- */
function onOpen() {
  SpreadsheetApp.getUi().createMenu(APP_NAME)
    .addItem('1) ตั้งค่าครั้งแรก', 'menuSetup')
    .addItem('2) อัปเดตสรุปดาว + อันดับ', 'menuSummary')
    .addItem('3) ใส่คลิปตั้งต้นในภารกิจ (เฉพาะช่องที่ว่าง)', 'menuFillClips')
    .addItem('4) ตั้งรหัสครู (โหมดครูในแอป)', 'menuTeacherPass')
    .addItem('ดึงค่าฝุ่น PM2.5 ตอนนี้', 'menuDust')
    .addSeparator()
    .addItem('ให้ระบบทำงานเองทุกชั่วโมง (สรุปดาว + อันดับ + ลบไฟล์เก่า)', 'menuAutoSummary')
    .addItem('ลบไฟล์รูปและวิดีโอเก่าทั้งหมด', 'menuDeleteAllProof')
    .addToUi();
}

/* ฟังก์ชันที่ไม่ลงท้ายด้วย _ ถูกเรียกจากภายนอกได้ เมนูของครูจึงตรวจก่อนว่าเปิดจากชีตโดยครู */
function requireTeacher_() {
  var active = '', effective = '';
  try { active = Session.getActiveUser().getEmail(); } catch (e) {}
  try { effective = Session.getEffectiveUser().getEmail(); } catch (e) {}
  if (!active || active !== effective) throw new Error('คำสั่งนี้ใช้ได้เฉพาะครูที่เปิดจากเมนูในชีต');
}

function menu_(fn) {
  requireTeacher_();
  var ui = SpreadsheetApp.getUi();
  try {
    fn(ui);
  } catch (e) {
    ui.alert(APP_NAME, String(e && e.message ? e.message : e), ui.ButtonSet.OK);
  }
}

function menuSetup() {
  menu_(function (ui) {
    var made = setup_();
    ui.alert(APP_NAME, made.length
      ? 'สร้างแท็บแล้ว: ' + made.join(', ') + '\n\nขั้นต่อไป\n• ใส่วันเริ่มโปรแกรม (วันจันทร์) ในแท็บตั้งค่า\n• Deploy เป็นเว็บแอป (ดำเนินการในฐานะ: ฉัน / ผู้ที่มีสิทธิ์เข้าถึง: ทุกคน)\n• เชื่อมหน้าเว็บกับเว็บแอป แล้วส่งลิงก์หน้าเว็บให้นักเรียนสมัครเอง'
      : 'มีแท็บครบแล้ว ไม่ได้แก้ข้อมูลเดิม', ui.ButtonSet.OK);
  });
}

function menuSummary() {
  menu_(function () {
    var n = rebuildSummary_();
    SpreadsheetApp.getActive().toast('อัปเดตสรุปดาว อันดับ และแคชแล้ว ' + n + ' คน', APP_NAME, 5);
  });
}

function menuFillClips() {
  menu_(function (ui) {
    var r = fillClips_();
    if (r.noTab) { ui.alert(APP_NAME, 'ยังไม่มีแท็บภารกิจประจำวัน กดเมนู 1) ตั้งค่าครั้งแรก ก่อน', ui.ButtonSet.OK); return; }
    ui.alert(APP_NAME, r.n ? 'ใส่คลิปตั้งต้นแล้ว ' + r.n + ' ภารกิจ (เฉพาะช่องคลิปสาธิตที่ว่าง และข้อความขั้น 1 ตรงกับภารกิจตั้งต้น)\nคลิปเดิมที่ครูใส่ไว้ไม่ถูกแก้'
      : 'ไม่มีช่องที่ต้องเติม (ใส่คลิปครบแล้ว หรือข้อความภารกิจถูกแก้ไว้)', ui.ButtonSet.OK);
  });
}

function menuDust() {
  var r = refreshDust_(), ui = SpreadsheetApp.getUi();
  if (!r.ok) { ui.alert(r.error || 'ดึงค่าฝุ่นไม่สำเร็จ'); return; }
  var d = r.dust, L = FQ.DUST[d.lv] || {};
  ui.alert('ค่าฝุ่น PM2.5 ล่าสุด\n' + d.st + '\n' + d.v + ' มคก./ลบ.ม. (สี' + (L.label || '-') + ') เวลา ' + d.at);
}
function menuAutoSummary() {
  menu_(function () {
    ScriptApp.getProjectTriggers().forEach(function (t) {
      if (t.getHandlerFunction() === 'autoSummary') ScriptApp.deleteTrigger(t);
    });
    ScriptApp.newTrigger('autoSummary').timeBased().everyHours(1).create();
    rebuildSummary_();
    SpreadsheetApp.getActive().toast('ตั้งแล้ว: อัปเดตสรุปดาว อันดับ และแคชทุกชั่วโมง ลบไฟล์รูปเก่าวันละครั้ง', APP_NAME, 5);
  });
}

function menuTeacherPass() {
  menu_(function (ui) {
    var r = ui.prompt(APP_NAME, 'ตั้งรหัสครูสำหรับเข้าโหมดครูในแอป (อย่างน้อย 6 ตัวอักษร)\nตั้งใหม่แล้ว เครื่องที่เคยเข้าโหมดครูไว้ต้องใส่รหัสใหม่', ui.ButtonSet.OK_CANCEL);
    if (r.getSelectedButton() !== ui.Button.OK) return;
    var pass = String(r.getResponseText() || '').trim();
    if (pass.length < 6 || pass.length > 40) { ui.alert(APP_NAME, 'รหัสครูต้องยาว 6–40 ตัวอักษร', ui.ButtonSet.OK); return; }
    var props = PropertiesService.getScriptProperties();
    props.setProperty('TEACHER_HASH', teacherHash_(pass));
    props.setProperty('T_FAILS', '0');
    props.setProperty('T_LOCK', '0');
    ui.alert(APP_NAME, 'ตั้งรหัสครูแล้ว ในแอปกดปุ่ม "สำหรับครู" ที่หน้าเข้าสู่ระบบ แล้วใส่รหัสนี้', ui.ButtonSet.OK);
  });
}

function menuDeleteAllProof() {
  menu_(function (ui) {
    var ok = ui.alert(APP_NAME, 'ลบไฟล์รูปและวิดีโอหลักฐานแบบเก่าทั้งหมดไปที่ถังขยะของ Drive?\nแต้มของเด็กไม่หาย และแถวในแท็บภารกิจที่ทำยังอยู่ (รูปจริงในโปรไฟล์ไม่ถูกลบ)', ui.ButtonSet.YES_NO);
    if (ok !== ui.Button.YES) return;
    var n = cleanupProof_(true);
    ui.alert(APP_NAME, 'ลบไฟล์แล้ว ' + n + ' ไฟล์', ui.ButtonSet.OK);
  });
}

/* ตัวจับเวลาเรียกฟังก์ชันนี้ ถ้าไม่ได้มาจากตัวจับเวลาของโครงการจะไม่ทำอะไร */
function autoSummary(e) {
  var uid = e && e.triggerUid ? String(e.triggerUid) : '';
  if (!uid) return;
  var mine = ScriptApp.getProjectTriggers().some(function (t) { return String(t.getUniqueId()) === uid; });
  if (!mine) return;
  try { refreshDust_(); } catch (err) { console.error(err); }
  rebuildSummary_();
  cleanupPhotos_();
  /* ลบไฟล์หลักฐานเก่าวันละครั้ง */
  var props = PropertiesService.getScriptProperties(), today = todayKey_();
  if (props.getProperty('CLEANUP_DAY') !== today) {
    cleanupProof_(false);
    props.setProperty('CLEANUP_DAY', today);
  }
}

/* ---------- งานของเมนู ---------- */
function header_(sh, n) {
  sh.getRange(1, 1, 1, n).setFontWeight('bold').setBackground('#E8ECF6').setWrap(true).setVerticalAlignment('middle');
  sh.setFrozenRows(1);
}
function list_(range, values) {
  range.setDataValidation(SpreadsheetApp.newDataValidation().requireValueInList(values, true).setAllowInvalid(false).build());
}
function setup_() {
  var ss = SpreadsheetApp.getActive();
  try { ss.setSpreadsheetTimeZone(TZ); } catch (e) {}
  var made = [];
  function ensure(name, build) {
    if (ss.getSheetByName(name)) return;
    build(ss.insertSheet(name));
    made.push(name);
  }

  /* ชีตที่ตั้งค่าไว้แล้ว: เติมเฉพาะแถวตั้งค่าที่ยังไม่มี ค่าเดิมไม่ถูกแก้ */
  var setSh = ss.getSheetByName(TAB.settings);
  if (setSh) {
    var have = setSh.getLastRow() >= 1 ? setSh.getRange(1, 1, setSh.getLastRow(), 1).getValues().map(function (r) { return String(r[0]).trim(); }) : [];
    var added = 0;
    /* ป้ายเก่าที่ใช้ค่าเดิมต่อได้ ไม่ต้องเพิ่มแถวใหม่ซ้ำ และเปลี่ยนคำอธิบายของแถวที่ไม่ใช้แล้ว */
    have.forEach(function (label, i) {
      if (SETTING_OLD_NOTES[label]) setSh.getRange(i + 1, 3).setValue(SETTING_OLD_NOTES[label]);
    });
    SETTING_ROWS.forEach(function (d) {
      if (have.indexOf(d[0]) >= 0) return;
      if (have.some(function (l) { return SETTING_ALIASES[l] === d[1]; })) return;
      var r = setSh.getLastRow() + 1;
      if (TEXT_SETTINGS.indexOf(d[1]) >= 0) setSh.getRange(r, 2).setNumberFormat('@');
      setSh.getRange(r, 1, 1, 3).setValues([[d[0], d[2], d[3]]]);
      added++;
    });
    if (added) made.push(TAB.settings + ' (เพิ่ม ' + added + ' แถว)');
  }

  /* แท็บภารกิจแบบเก่า (ไม่มีคอลัมน์ ขั้น 1–4): เก็บไว้เป็นชื่อใหม่ แล้วสร้างแท็บแบบใหม่ */
  var oldPool = ss.getSheetByName(TAB.missions);
  if (oldPool && oldPool.getLastRow() >= 1) {
    var ph = oldPool.getRange(1, 1, 1, Math.max(1, oldPool.getLastColumn())).getValues()[0].map(function (v) { return String(v).trim(); });
    if (ph.indexOf('ขั้น 1') < 0) {
      oldPool.setName(TAB.missions + ' (แบบเก่า ' + todayKey_() + ')');
      made.push('เก็บแท็บภารกิจแบบเก่าไว้');
    }
  }
  /* แท็บที่มีอยู่แล้ว: เติมหัวคอลัมน์ที่โค้ดรุ่นใหม่ต้องใช้ ต่อท้ายคอลัมน์เดิม */
  [[TAB.roster, H.roster.concat(H.rosterOpt)], [TAB.logs, H.logs], [TAB.done, H.done], [TAB.quests, H.quests.concat([QUEST_CLIP_HEAD])], [TAB.extra, H.extra],
    [TAB.missions, H.missions.concat([CLIP_HEAD, OUTDOOR_HEAD])]].forEach(function (x) {
    var sh = ss.getSheetByName(x[0]);
    if (!sh || sh.getLastRow() < 1) return;
    var head = sh.getRange(1, 1, 1, Math.max(1, sh.getLastColumn())).getValues()[0].map(function (v) { return String(v).trim(); });
    var miss = x[1].filter(function (h) { return head.indexOf(h) < 0; });
    if (!miss.length) return;
    var c0 = sh.getLastColumn() + 1;
    sh.getRange(1, c0, 1, miss.length).setValues([miss]);
    header_(sh, c0 + miss.length - 1);
    made.push(x[0] + ' (เพิ่มคอลัมน์ ' + miss.join(', ') + ')');
  });

  ensure(TAB.settings, function (sh) {
    var rows = [['ค่าที่ตั้ง', 'ค่า', 'คำอธิบาย']].concat(SETTING_ROWS.map(function (d) { return [d[0], d[2], d[3]]; }));
    sh.getRange(1, 1, rows.length, 3).setValues(rows);
    header_(sh, 3);
    sh.setColumnWidth(1, 230); sh.setColumnWidth(2, 200); sh.setColumnWidth(3, 400);
    for (var i = 0; i < SETTING_ROWS.length; i++) {
      if (TEXT_SETTINGS.indexOf(SETTING_ROWS[i][1]) >= 0) sh.getRange(i + 2, 2).setNumberFormat('@').setValue(SETTING_ROWS[i][2]);
    }
  });

  ensure(TAB.roster, function (sh) {
    var all = H.roster.concat(H.rosterOpt);
    var col = function (h) { return all.indexOf(h) + 1; };
    sh.getRange(2, col(SC.sid), 1000, 1).setNumberFormat('@');
    sh.getRange(2, col(SC.pin), 1000, 1).setNumberFormat('@');
    sh.getRange(1, 1, 1, all.length).setValues([all]);
    header_(sh, all.length);
    list_(sh.getRange(2, col(SC.grade), 1000, 1), ['ป.1', 'ป.2', 'ป.3', 'ป.4', 'ป.5', 'ป.6']);
    list_(sh.getRange(2, col(SC.active), 1000, 1), ['ใช่', 'ไม่']);
    sh.getRange(1, col(SC.sid)).setNote('นักเรียนสมัครเองจากหน้าเว็บ ครูตรวจว่าเลขประจำตัว ชื่อ ชั้น ห้อง ถูกต้อง');
    sh.getRange(1, col(SC.pin)).setNote('PIN เก็บแบบเข้ารหัส ครูก็อ่านไม่ได้\nนักเรียนลืม PIN: ลบช่องนี้ แล้วให้นักเรียนกด สมัครครั้งแรก อีกครั้ง บันทึกเดิมยังอยู่ครบ');
    sh.getRange(1, col(SC.active)).setNote('ไม่ = ปิดบัญชีนี้ เข้าสู่ระบบไม่ได้ เช่น สมัครซ้ำหรือเลขประจำตัวไม่ถูกต้อง');
    [110, 200, 60, 60, 60, 170, 150, 150, 90, 150, 70, 110, 110, 80, 110, 80, 160, 110, 160, 160, 160, 110].forEach(function (w, i) { sh.setColumnWidth(i + 1, w); });
  });
  var rsh = ss.getSheetByName(TAB.roster);
  if (rsh) {
    try {
      var RI = headIdx_(rsh, TAB.roster, H.roster, H.rosterOpt).idx, rcol = function (h) { return RI[h] + 1; };
      rsh.getRange(1, rcol(SC.nick)).setNote('ชื่อที่โชว์ในตารางอันดับและการ์ดนักกีฬา เด็กตั้งเองได้ (มีตัวกรองคำไม่สุภาพ เปลี่ยนได้ทุก 7 วัน) ครูแก้ได้\nว่างไว้ = โชว์ "เลขที่ n" กับห้อง ไม่โชว์ชื่อจริง');
      rsh.getRange(1, rcol(SC.nickLock)).setNote('ใช่ = เด็กเปลี่ยนชื่อเล่นเองไม่ได้ (ครูตั้งให้)');
      rsh.getRange(1, rcol(SC.photo)).setNote('รูปจริงเห็นเฉพาะเด็กคนนั้นกับครู ไฟล์อยู่ในโฟลเดอร์ สมุดสุขภาพ-รูปโปรไฟล์ ใน Drive ของครู');
      rsh.getRange(1, rcol(SC.photoOk)).setNote('อนุมัติ / ไม่อนุมัติ (ระบบลบไฟล์ให้) หรือกดในโหมดครูในแอป');
      list_(rsh.getRange(2, rcol(SC.nickLock), 1000, 1), ['ใช่']);
      list_(rsh.getRange(2, rcol(SC.photoOk), 1000, 1), ['รอ', 'อนุมัติ', 'ไม่อนุมัติ']);
    } catch (e) {}
  }

  ensure(TAB.missions, function (sh) {
    var rows = [H.missions.concat([CLIP_HEAD, OUTDOOR_HEAD])].concat(FQ.DEFAULT_MISSIONS.map(function (m) {
      return [SHEET_BY_TYPE[m.type]].concat(m.steps, ['ใช่', m.clip || '', m.outdoor ? 'ใช่' : '']);
    }));
    sh.getRange(1, 1, rows.length, H.missions.length + 2).setValues(rows);
    header_(sh, H.missions.length + 2);
    sh.getRange(1, H.missions.length + 2).setNote('ใช่ = ภารกิจกลางแจ้ง วันฝุ่นเยอะระบบสลับไปใช้ภารกิจในบ้านอันถัดไปแทน\nว่าง = ระบบเดาจากข้อความ (เช่น นอกบ้าน เดินเร็วกับผู้ใหญ่) · ไม่ = ทำในบ้านได้เสมอ');
    list_(sh.getRange(2, H.missions.length + 2, 500, 1), ['ใช่', 'ไม่']);
    sh.getRange(1, H.missions.length + 1).setNote('ลิงก์คลิป YouTube หรือ Google Drive (แชร์แบบทุกคนที่มีลิงก์) เด็กกดดูในการ์ดภารกิจ ดูครบได้แต้ม\nภารกิจขยับ = คลิปออกกำลังกายให้ทำตาม ภารกิจสุขนิสัย = คลิปความรู้สุขภาพ\nตัดเฉพาะช่วงได้ เช่น ...watch?v=xxxx&t=90&end=300 (เริ่มวินาทีที่ 90 จบวินาทีที่ 300)\nไม่ใส่ = ภารกิจนั้นไม่มีคลิป');
    list_(sh.getRange(2, 1, 500, 1), ['ขยับ', 'สุขนิสัย']);
    list_(sh.getRange(2, H.missions.indexOf('ใช้งาน') + 1, 500, 1), ['ใช่', 'ไม่']);
    sh.getRange(1, 1).setNote('ระบบหมุนเลือกภารกิจขยับ 1 อัน และสุขนิสัย 1 อันต่อวัน ทั้งโรงเรียนได้เหมือนกัน\nเพิ่มแถวได้ ไม่ใช้แถวไหนให้ใส่ ไม่ ในช่องใช้งาน');
    sh.getRange(1, 2).setNote('ขั้น 1–4 จากง่ายไปยาก\nป.1–3: ⭐ = ขั้น 1, ⭐⭐ = ขั้น 2, ⭐⭐⭐ = ขั้น 3\nป.4–6: ⭐ = ขั้น 2, ⭐⭐ = ขั้น 3, ⭐⭐⭐ = ขั้น 4');
    sh.getRange(1, 6).setNote('ไม่ = ไม่ใช้ภารกิจนี้ (ระบบข้ามไป)');
    [80, 220, 230, 250, 270, 60, 330, 80].forEach(function (w, i) { sh.setColumnWidth(i + 1, w); });
  });

  ensure(TAB.done, function (sh) {
    sh.getRange(2, 1, 1000, 3).setNumberFormat('@');
    sh.getRange(1, 1, 1, H.done.length).setValues([H.done]);
    header_(sh, H.done.length);
    var col = function (h) { return H.done.indexOf(h) + 1; };
    sh.getRange(2, col(SC.sid), 1000, 1).setNumberFormat('@');
    list_(sh.getRange(2, col('ประเภท'), 1000, 1), ['ขยับ', 'สุขนิสัย', 'เควสบ้าน']);
    list_(sh.getRange(2, col('ความยาก'), 1000, 1), ['⭐', '⭐⭐', '⭐⭐⭐']);
    list_(sh.getRange(2, col('หลักฐาน'), 1000, 1), ['ไม่มี', 'รูป', 'วิดีโอ', 'สาธิตในคาบ']);
    list_(sh.getRange(2, col('ครูตรวจ'), 1000, 1), ['ผ่าน', 'ไม่ผ่าน', 'ไม่นับ']);
    sh.getRange(1, col('หลักฐาน')).setNote('เด็กที่ไม่มีมือถือ มาสาธิตภารกิจในคาบ ครูเพิ่มแถวเองแล้วเลือก สาธิตในคาบ ได้โบนัส +10\n(รูป / วิดีโอ = แถวเก่าก่อนเปลี่ยนเป็นดูคลิป)');
    sh.getRange(1, col('ครูตรวจ')).setNote('ไม่นับ = ไม่ได้แต้มรายการนี้ (ใช้กรณีกดทำโดยไม่ได้ทำจริง)\nผ่าน / ไม่ผ่าน = ใช้กับแถวเก่าที่เคยส่งรูป');
    sh.getRange(1, col('ท่าลับ')).setNote('ใช้กับแถวเก่าที่เคยส่งรูป (ตอนนี้เลิกใช้แล้ว)');
    [90, 140, 90, 60, 100, 80, 280, 70, 80, 160, 90, 80, 160].forEach(function (w, i) { sh.setColumnWidth(i + 1, w); });
  });

  ensure(TAB.quests, function (sh) {
    var rows = [H.quests.concat([QUEST_CLIP_HEAD])].concat(EXAMPLE_QUESTS.map(function (q) { return q.concat(['']); }));
    sh.getRange(1, 1, rows.length, 4).setValues(rows);
    header_(sh, 4);
    sh.getRange(2, 2, rows.length - 1, 2).setWrap(true);
    sh.getRange(1, 2).setNote('ตัวอย่าง ให้ครูและผู้เชี่ยวชาญตรวจก่อนใช้ ข้อความขึ้นบนหน้าเว็บของสัปดาห์นั้น เด็กทำกับคนในบ้านแล้วกดทำแล้ว');
    sh.getRange(1, 4).setNote('ลิงก์คลิป YouTube หรือ Google Drive (ไม่ใส่ก็ได้) เด็กดูครบได้แต้มเพิ่ม สัปดาห์ละครั้ง');
    [70, 360, 360, 300].forEach(function (w, i) { sh.setColumnWidth(i + 1, w); });
  });

  ensure(TAB.logs, function (sh) {
    sh.getRange(2, 1, 1000, 3).setNumberFormat('@');
    sh.getRange(1, 1, 1, H.logs.length).setValues([H.logs]);
    header_(sh, H.logs.length);
    var col = function (h) { return H.logs.indexOf(h) + 1; };
    sh.getRange(2, col(SC.sid), 1000, 1).setNumberFormat('@');
    list_(sh.getRange(2, col('กิจกรรม'), 1000, 1), FQ.ACTIVITIES.map(function (a) { return a.label; }));
    list_(sh.getRange(2, col('ความรู้สึก'), 1000, 1), FQ.FEELINGS.map(function (f) { return f.label; }));
    list_(sh.getRange(2, col('ช่องทาง'), 1000, 1), ['เว็บแอป', 'กระดาษ']);
    list_(sh.getRange(2, col('ครูตรวจ'), 1000, 1), ['ไม่นับ']);
    sh.getRange(1, col('วันที่ทำ')).setNote('วันที่เด็กออกกำลังกาย ครูพิมพ์เพิ่มจากพาสปอร์ตกระดาษได้ เช่น 16/11/2569 ใส่เลขประจำตัวของเด็ก แล้วเลือกช่องทาง กระดาษ');
    sh.getRange(1, col('ครูตรวจ')).setNote('เลือก ไม่นับ เมื่อบันทึกผิดหรือซ้ำ แล้วกดเมนู 2) อัปเดตสรุปดาว');
    sh.getRange(1, col('สัปดาห์')).setNote('คิดจากวันที่ทำกับวันเริ่มโปรแกรมตอนบันทึก สรุปดาวคิดใหม่จากวันที่ทุกครั้ง');
  });

  ensure(TAB.summary, function (sh) {
    sh.getRange(1, 1).setValue('กดเมนู ' + APP_NAME + ' → 2) อัปเดตสรุปดาว + อันดับ');
  });

  ensure(TAB.questions, function (sh) {
    var rows = [H.questions].concat(questionRows_());
    sh.getRange(1, 1, rows.length, H.questions.length).setValues(rows);
    header_(sh, H.questions.length);
    list_(sh.getRange(2, 1, 500, 1), ['ป.1–3', 'ป.4–6', 'ทุกชั้น']);
    list_(sh.getRange(2, 7, 500, 1), LETTERS);
    list_(sh.getRange(2, 9, 500, 1), ['ใช่', 'ไม่']);
    sh.getRange(2, 2, rows.length - 1, 7).setWrap(true);
    sh.getRange(1, 2).setNote('ตัวอย่าง 120 ข้อ ให้ครูและผู้เชี่ยวชาญตรวจก่อนใช้ แก้ เพิ่ม หรือใส่ ไม่ ในช่องใช้งานได้\nทุกคนในช่วงชั้นเดียวกันได้ข้อเดียวกันในวันเดียวกัน หมุนตามวัน ครบแล้ววนใหม่');
    sh.getRange(1, 7).setNote('ตัวอักษรของคำตอบที่ถูก ก ข ค หรือ ง');
    [70, 320, 170, 170, 170, 170, 50, 320, 60].forEach(function (w, i) { sh.setColumnWidth(i + 1, w); });
  });

  ensure(TAB.events, function (sh) {
    var col = function (h) { return H.events.indexOf(h) + 1; };
    sh.getRange(2, col('เริ่ม'), 200, 2).setNumberFormat('@');
    var rows = [H.events].concat(EXAMPLE_EVENTS);
    sh.getRange(1, 1, rows.length, H.events.length).setValues(rows);
    header_(sh, H.events.length);
    var kinds = FQ.EVENT_KINDS.map(function (k) { return k.label; });
    [1, 2, 3].forEach(function (k) { list_(sh.getRange(2, col('นับจาก ' + k), 200, 1), kinds); });
    list_(sh.getRange(2, col('ใช้งาน'), 200, 1), ['ใช่', 'ไม่']);
    sh.getRange(1, col('รหัส')).setNote('ตัวอักษรอังกฤษหรือตัวเลข ไม่ซ้ำกัน ห้ามแก้หลังเริ่มอีเวนต์แล้ว (ระบบใช้จำว่าใครทำอะไรไปแล้ว)');
    sh.getRange(1, col('เริ่ม')).setNote('วัน/เดือน/ปี พ.ศ. เช่น 14/12/2569');
    sh.getRange(1, col('นับจาก 1')).setNote('นาทีรวม / วันที่ขยับ / ภารกิจประจำวัน (ครั้ง) / ตอบคำถาม (ข้อ) = ระบบนับให้จากที่เด็กบันทึกในช่วงอีเวนต์\nกดทำเอง = เด็กกดปุ่ม ทำแล้ว ครูดูรายชื่อในแท็บกิจกรรมเสริม');
    sh.getRange(1, col('สติกเกอร์')).setNote('สติกเกอร์รุ่นพิเศษที่ได้เมื่อทำครบทุกภารกิจ ได้เฉพาะช่วงอีเวนต์');
    sh.getRange(2, col('คำชวน'), rows.length - 1, 1).setWrap(true);
  });

  ensure(TAB.extra, function (sh) {
    sh.getRange(2, 1, 1000, 3).setNumberFormat('@');
    sh.getRange(1, 1, 1, H.extra.length).setValues([H.extra]);
    header_(sh, H.extra.length);
    var col = function (h) { return H.extra.indexOf(h) + 1; };
    sh.getRange(2, col(SC.sid), 1000, 1).setNumberFormat('@');
    list_(sh.getRange(2, col('ประเภท'), 1000, 1), ['คำถาม', 'อีเวนต์', 'กำลังใจ']);
    list_(sh.getRange(2, col('ครูตรวจ'), 1000, 1), ['ไม่นับ']);
    sh.getRange(1, col('ครูตรวจ')).setNote('เลือก ไม่นับ = ไม่ได้แต้มรายการนี้ (เช่น กดทำเองแต่ไม่ได้ทำจริง)');
    [90, 140, 90, 60, 100, 70, 300, 80, 60, 70, 140].forEach(function (w, i) { sh.setColumnWidth(i + 1, w); });
  });

  ensure(TAB.fitness, function (sh) {
    var col = function (h) { return H.fitness.indexOf(h) + 1; };
    sh.getRange(2, col(SC.sid), 1000, 1).setNumberFormat('@');
    sh.getRange(2, col('ภาคเรียน'), 1000, 1).setNumberFormat('@');
    sh.getRange(1, 1, 1, H.fitness.length).setValues([H.fitness]);
    header_(sh, H.fitness.length);
    sh.getRange(1, col('ภาคเรียน')).setNote('รูปแบบ ภาคเรียน/ปี พ.ศ. เช่น 2/2569 (1 แถวต่อนักเรียน 1 คนต่อภาคเรียน)');
    sh.getRange(1, col('นั่งงอตัว (ซม.)')).setNote('กรอกในแอปโหมดครู หรือวางจาก Excel ก็ได้ ช่องว่าง = ยังไม่ได้ทดสอบ\nเด็กเห็นเฉพาะผลของตัวเอง เทียบกับตัวเองภาคเรียนก่อน ไม่มีการจัดอันดับ\nไม่เก็บน้ำหนักและส่วนสูง');
    [110, 60, 50, 80, 110, 120, 120, 140, 150].forEach(function (w, i) { sh.setColumnWidth(i + 1, w); });
  });

  ensure(TAB.game, setupGame_);

  ensure(TAB.cache, function (sh) {
    sh.getRange(1, 1, 1, H.cache.length).setValues([H.cache]);
    header_(sh, H.cache.length);
    sh.getRange(1, 1).setNote('ระบบสร้างแท็บนี้เองทุกชั่วโมง ใช้ให้แอปเปิดเร็ว ห้ามแก้ ลบได้ถ้ามีปัญหา (ระบบสร้างใหม่รอบถัดไป)');
    try { sh.hideSheet(); } catch (e) {}
  });

  ['Sheet1', 'ชีต1', 'แผ่นงาน1', 'แผ่น1'].forEach(function (n) {
    var sh = ss.getSheetByName(n);
    if (sh && sh.getLastRow() === 0 && ss.getSheets().length > 1) ss.deleteSheet(sh);
  });
  secret_(); /* สร้างกุญแจเข้ารหัส PIN ไว้ครั้งเดียว */
  return made;
}

/* แถวในแท็บบันทึก/ภารกิจที่ทำต้องเรียงตามเวลาที่ส่ง (แอปอ่านเฉพาะท้ายแท็บ)
 * ถ้าครูพิมพ์แถวเองโดยไม่ใส่เวลา ระบบเติมเวลาตอนนี้ให้ ถ้ามีคนกดเรียงข้อมูล ระบบเรียงกลับตามเวลาที่ส่ง
 * คืน 'stamp' / 'sort' / '' */
function timeKey_(v) {
  if (Object.prototype.toString.call(v) === '[object Date]') return isNaN(v.getTime()) ? '' : Utilities.formatDate(v, TZ, 'yyyy-MM-dd HH:mm:ss');
  var t = String(v === null || v === undefined ? '' : v).trim().replace(/^'/, '');
  var m = /^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?)?$/.exec(t);
  if (m) return m[1] + '-' + m[2] + '-' + m[3] + ' ' + (m[4] || '00') + ':' + (m[5] || '00') + ':' + (m[6] || '00');
  var k = FQ.toKey(t);
  return k ? k + ' 00:00:00' : '';
}
function fixOrder_(name, headers) {
  var sh = SpreadsheetApp.getActive().getSheetByName(name);
  if (!sh || sh.getLastRow() < 2) return '';
  return withLock_(function () {
    var t = table_(name, headers), col = t.idx['เวลาที่ส่ง'], sc = t.idx[SC.sid];
    var now = nowText_(), keys = [], change = false, sorted = true, prev = '';
    t.data.forEach(function (r) {
      var raw = r[col], k = timeKey_(raw);
      if (!k && normSid_(r[sc])) k = now;
      if (k && (typeof raw !== 'string' || raw.replace(/^'/, '') !== k)) change = true;
      if (k && prev && k < prev) sorted = false;
      if (k) prev = k;
      keys.push([k ? "'" + k : raw]);
    });
    if (!change && sorted) return '';
    if (change) sh.getRange(2, col + 1, keys.length, 1).setValues(keys);
    if (!sorted) sh.getRange(2, 1, t.data.length, t.width).sort({ column: col + 1, ascending: true });
    return sorted ? 'stamp' : 'sort';
  });
}

/* สรุปดาว: 1 แถวต่อนักเรียน 1 คน เรียงตามชั้น ห้อง เลขที่ (ไม่รวมบัญชีที่ครูปิดไว้)
 * รอบเดียวกันสร้างแคชรายคนและอันดับ (ลีกตามภาค + ห้องแข่งห้อง) ด้วย */
function rebuildSummary_() {
  var c = load_();
  fixOrder_(TAB.logs, H.logs);
  fixOrder_(TAB.done, H.done);
  fixOrder_(TAB.extra, H.extra);
  var logs = logsFromTable_(table_(TAB.logs, H.logs));
  var today = todayKey_();
  var start = c.settings.programStart, weeks = c.settings.programWeeks, w;
  var head = ['ห้อง', 'เลขที่', SC.sid, SC.name];
  for (w = 1; w <= weeks; w++) head.push('ดาว ส.' + w);
  head.push('ดาวรวม');
  for (w = 1; w <= weeks; w++) head.push('นาที ส.' + w);
  head.push('นาทีรวม', 'บันทึกล่าสุด');
  head.push('แต้มรวม', 'ระดับ', 'ฉายา', 'ภารกิจ (ครั้ง)', 'วันที่บันทึกสะสม', 'แต้มสัปดาห์นี้', 'เป้าสัปดาห์ (นาที)', 'สติกเกอร์', 'คำถาม (ถูก/ตอบ)', 'ดูคลิปครบ (ครั้ง)');
  var bySid = {}, doneBy = {}, extraBy = {}, people = [], snaps = [];
  var cheerTo = {}, ws0 = FQ.addDays(today, -FQ.weekdayIdx(today)), cut0 = FQ.addDays(today, -c.settings.backfillDays);
  readExtra_().forEach(function (x) {
    (extraBy[x.code] = extraBy[x.code] || []).push(x);
    if (x.kind === 'cheer' && x.check !== 'ไม่นับ' && x.date >= ws0 && x.date < cut0) cheerTo[x.ref] = (cheerTo[x.ref] || 0) + 1;
  });
  var cut = FQ.addDays(today, -c.settings.backfillDays), ws = ws0;
  logs.forEach(function (l) { (bySid[l.code] = bySid[l.code] || []).push(l); });
  readDone_().forEach(function (m) { (doneBy[m.code] = doneBy[m.code] || []).push(m); });
  var order = function (a, b) {
    return (a.grade || 99) - (b.grade || 99) || (a.room || 99) - (b.room || 99) ||
      (a.no || 999) - (b.no || 999) || (a.sid < b.sid ? -1 : a.sid > b.sid ? 1 : 0);
  };
  var tlist = [];
  var rows = c.roster.filter(function (s) { return s.active; }).sort(order).map(function (s) {
    var mine = bySid[s.sid] || [];
    tlist.push({ s: s, logs: mine, done: doneBy[s.sid] || [], extra: extraBy[s.sid] || [] });
    var sum = FQ.summarize(mine, { start: start, weeks: weeks }, c.settings, today);
    var r = [s.classId, s.no || '', "'" + s.sid, cleanText_(s.name, 60)], x;
    for (x = 1; x <= weeks; x++) r.push(start ? sum.history[x - 1].stars : '');
    r.push(start ? sum.totalStars : '');
    for (x = 1; x <= weeks; x++) r.push(start ? sum.history[x - 1].minutes : '');
    r.push(start ? sum.programMinutes : '');
    var last = '';
    mine.forEach(function (l) { if (!l.excluded && l.date > last) last = l.date; });
    r.push(last ? "'" + last : '');
    var dm = doneBy[s.sid] || [], em = extraBy[s.sid] || [];
    var xp = FQ.xpStatus(mine, dm, { start: start, weeks: weeks }, c.settings, today, { extra: em, events: c.events });
    var quizzes = em.filter(function (x) { return x.kind === 'quiz' && x.check !== 'ไม่นับ'; });
    r.push(start ? xp.total : '', start ? xp.level.lv + (xp.level.legend ? ' ★' + xp.level.legend : '') : '',
      start ? xp.level.icon + ' ' + xp.level.title : '', dm.filter(function (m) { return m.check !== 'ไม่นับ'; }).length,
      start ? xp.activeDays : '', start ? xp.week : '', xp.weekGoal ? xp.weekGoal.minutes + ' / ' + xp.weekGoal.goal : '',
      start ? xp.stickerCount : '',
      quizzes.length ? quizzes.filter(function (x) { return x.ok; }).length + ' / ' + quizzes.length : '',
      em.filter(function (x) { return x.kind === 'clip' && x.check !== 'ไม่นับ'; }).length || '');
    var wk = { moved: false, minutes: 0 };
    mine.forEach(function (l) {
      if (!l.excluded && l.date >= ws && l.date <= today) { wk.moved = true; wk.minutes += Number(l.minutes) || 0; }
    });
    var of = FQ.PROFILE.outfits.filter(function (o) { return o.id === s.outfit || o.label === s.outfit; })[0];
    var cf = FQ.PROFILE.colors.filter(function (o) { return o.id === s.color || o.label === s.color; })[0];
    people.push({
      sid: s.sid, name: s.nick || ('เลขที่ ' + (s.no || '?')), classId: s.classId, arc: xp.level.arc, lv: xp.level.lv,
      week: start ? xp.week : 0, total: xp.total, moved: wk.moved, minutes: wk.minutes, member: !!s.pinHash && !!s.classId,
      card: cardKey_(s.sid), outfit: of ? of.id : '', color: cf ? cf.id : ''
    });
    snaps.push({
      sid: s.sid,
      logs: mine.filter(function (l) { return l.date && l.date < cut; }),
      done: dm.filter(function (m) { return m.date && m.date < cut; }),
      extra: em.filter(function (x) { return x.kind !== 'cheer' && x.date && x.date < cut; }),
      cheers: [ws, (cheerTo[s.sid] || 0)]
    });
    return r;
  });
  var ss = SpreadsheetApp.getActive();
  var sh = ss.getSheetByName(TAB.summary) || ss.insertSheet(TAB.summary);
  sh.clearContents();
  sh.getRange(1, 1).setValue('อัปเดตล่าสุด ' + nowText_() + (start ? '' : ' · ยังไม่ได้ใส่วันเริ่มโปรแกรมในแท็บตั้งค่า จึงยังไม่นับดาว') +
    ' · คัดลอกคอลัมน์ "ดาว ส.n" ของห้อง ไปวางที่คอลัมน์ดาวบ้าน (J) ในแท็บสัปดาห์ n ของชีตบันทึก XP');
  sh.getRange(2, 1, 1, head.length).setValues([head]).setFontWeight('bold').setBackground('#E8ECF6');
  if (rows.length) sh.getRange(3, 1, rows.length, head.length).setValues(rows);
  sh.setFrozenRows(2);
  writeCache_(people, snaps, cut, c.settings, today, teacherSummary_(tlist, c.settings, today, nowText_()));
  try {
    var tby = {};
    tlist.forEach(function (x) { if (x.s.classId) tby[x.s.sid] = x.logs; });
    tripSave_(FQ.tripCount(tby, c.settings, today));
  } catch (e) {}
  return rows.length;
}

/* เขียนแท็บแคชระบบใหม่ทั้งแท็บ: แถว 2 = อันดับ แถว 3 ขึ้นไป = ข้อมูลเก่าของนักเรียนทีละคน */
var CELL_MAX = 45000;
function writeCache_(people, snaps, cut, s, today, teacher) {
  var ss = SpreadsheetApp.getActive(), now = nowText_();
  var b = FQ.makeBoard(people, s, today, now);
  var tj = JSON.stringify(teacher || null);
  if (tj.length > CELL_MAX) { teacher.missing = teacher.missing.slice(0, 150); tj = JSON.stringify(teacher); }
  var rows = [['#board', JSON.stringify(b.raw), '', "'" + cut, '', "'" + now, '', ''], ['#teacher', tj, '', '', '', "'" + now, '', '']];
  snaps.forEach(function (x) {
    var lj = packLogs_(x.logs), dj = packDone_(x.done), ej = packExtra_(x.extra || []);
    if (lj.length > CELL_MAX || dj.length > CELL_MAX || ej.length > CELL_MAX) return; /* ใหญ่เกินช่อง: คนนี้อ่านสดทั้งแท็บแทน */
    rows.push(["'" + x.sid, lj, dj, "'" + cut, b.ranks[x.sid] ? JSON.stringify(b.ranks[x.sid]) : '', "'" + now, ej, JSON.stringify(x.cheers || null)]);
  });
  var sh = ss.getSheetByName(TAB.cache);
  if (!sh) {
    sh = ss.insertSheet(TAB.cache);
    try { sh.hideSheet(); } catch (e) {}
  }
  sh.clearContents();
  sh.getRange(1, 1, 1, H.cache.length).setValues([H.cache]);
  sh.getRange(2, 1, rows.length, H.cache.length).setValues(rows);
  return rows.length - 2;
}

    return { doPost: doPost, setup_: setup_, rebuildSummary_: rebuildSummary_, FQ: FQ, SETTING_ROWS: SETTING_ROWS, teacherHash_: teacherHash_, todayKey_: todayKey_, cardKey_: cardKey_ };
  })(SpreadsheetApp, Utilities, PropertiesService, LockService, DriveApp, ContentService, CacheService, ScriptApp, Session, UrlFetchApp);

  /* ---------- เก็บลงเครื่อง ---------- */
  function persist() {
    var data = { v: VERSION, nId: nId, props: props, folders: folders, sheets: {} };
    Object.keys(sheets).forEach(function (k) { data.sheets[k] = { cells: sheets[k].cells, hidden: sheets[k].hidden }; });
    try { localStorage.setItem(STORE, JSON.stringify(data)); } catch (e) {}
    /* รูปเล็กเก็บไว้ (ไม่เกิน 200 KB ต่อรูป รวมไม่เกิน 1.5 MB) วิดีโอเก็บแค่ตอนเปิดหน้าอยู่ */
    var keep = {}, total = 0;
    Object.keys(files).map(function (k) { return files[k]; }).filter(function (f) { return !f.trashed && f.bytes && f.bytes.length <= 200 * 1024 && /^image\//.test(f.mime); })
      .sort(function (a, b) { return b.at - a.at; }).forEach(function (f) {
        if (total + f.bytes.length > 1.5 * 1024 * 1024) return;
        total += f.bytes.length;
        keep[f.id] = { name: f.name, mime: f.mime, at: f.at, folder: f.folder, b64: b64(f.bytes) };
      });
    try { localStorage.setItem(FSTORE, JSON.stringify(keep)); } catch (e) {}
  }
  function restore() {
    var data = null;
    try { data = JSON.parse(localStorage.getItem(STORE) || 'null'); } catch (e) {}
    if (!data || data.v !== VERSION || !data.sheets) return false;
    nId = data.nId || 0; props = data.props || {}; folders = data.folders || {};
    Object.keys(data.sheets).forEach(function (k) { sheets[k] = makeSheet(k, data.sheets[k].cells, data.sheets[k].hidden); });
    var keep = {};
    try { keep = JSON.parse(localStorage.getItem(FSTORE) || '{}'); } catch (e) {}
    Object.keys(keep).forEach(function (id) { var f = keep[id]; files[id] = { id: id, name: f.name, mime: f.mime, at: f.at, folder: f.folder, trashed: false, bytes: unb64(f.b64) }; });
    return true;
  }
  function wipe() {
    Object.keys(sheets).forEach(function (k) { delete sheets[k]; });
    props = {}; files = {}; folders = {}; nId = 0;
    try { localStorage.removeItem(STORE); localStorage.removeItem(FSTORE); } catch (e) {}
  }

  /* ---------- ข้อมูลตัวอย่าง ---------- */
  function rng(seed) { return function () { seed |= 0; seed = seed + 0x6D2B79F5 | 0; var t = Math.imul(seed ^ seed >>> 15, 1 | seed); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }
  function post(o) { return JSON.parse(GS.doPost({ postData: { contents: JSON.stringify(o) } }).body); }
  function headIdx(tab) { var H = sheets[tab].cells[0]; return function (h) { return H.indexOf(h); }; }
  function rowOf(tab, obj) { return sheets[tab].cells[0].map(function (h) { return obj.hasOwnProperty(h) ? obj[h] : ''; }); }
  function thDate(k) { var p = k.split('-'); return (+p[2]) + '/' + (+p[1]) + '/' + (+p[0] + 543); }
  function img(kind, seed) {
    var c = document.createElement('canvas'); c.width = 300; c.height = 400;
    var g = c.getContext('2d'), R = rng(seed), hue = Math.floor(R() * 360);
    g.fillStyle = 'hsl(' + hue + ',35%,32%)'; g.fillRect(0, 0, 300, 400);
    g.fillStyle = 'hsl(' + hue + ',30%,22%)'; g.fillRect(0, 280, 300, 120);
    if (kind === 'face') {
      g.fillStyle = '#F2C9A0'; g.beginPath(); g.arc(150, 170, 80, 0, 7); g.fill();
      g.fillStyle = '#3A2A20'; g.beginPath(); g.arc(150, 120, 82, Math.PI, 0); g.fill();
      g.fillStyle = '#2B2B2B'; g.beginPath(); g.arc(122, 175, 8, 0, 7); g.arc(178, 175, 8, 0, 7); g.fill();
      g.strokeStyle = '#B4544A'; g.lineWidth = 6; g.beginPath(); g.arc(150, 200, 26, 0.2, Math.PI - 0.2); g.stroke();
    } else {
      g.fillStyle = ['#FFC93C', '#7FD3FF', '#FF7BB0'][seed % 3];
      if (seed % 3 === 0) { g.beginPath(); g.arc(150, 190, 70, 0, 7); g.fill(); }
      else if (seed % 3 === 1) g.fillRect(105, 120, 90, 150);
      else { g.beginPath(); g.moveTo(150, 100); g.lineTo(235, 270); g.lineTo(65, 270); g.closePath(); g.fill(); }
      g.fillStyle = '#F2C9A0'; g.fillRect(205, 36, 46, 70); g.fillRect(208, 10, 10, 34); g.fillRect(222, 6, 10, 38);
    }
    return c.toDataURL('image/jpeg', 0.8).split(',')[1];
  }
  var FIRST = ['ณัฐ', 'พิม', 'ภูมิ', 'ข้าวหอม', 'ต้นกล้า', 'ใบเตย', 'ปลื้ม', 'กันต์', 'ฟ้าใส', 'ภูผา', 'มายด์', 'ปัณณ์', 'น้ำใส', 'ข้าวปุ้น', 'ธาม', 'แพรวา',
    'ก้อง', 'เอิร์น', 'ไออุ่น', 'ปุณณ์', 'ขิม', 'ภาคิน', 'อันนา', 'ธีร์', 'ฝ้าย', 'กาย', 'ใบบัว', 'ปาล์ม', 'มีนา', 'ซันนี่'];
  var LAST = ['ใจดี', 'รักเรียน', 'สดใส', 'มั่นคง', 'แข็งแรง', 'ยิ้มแย้ม', 'ร่าเริง', 'ดีงาม', 'ใจกล้า', 'สุขสันต์'];
  var OUTFIT_LB = { sport: 'ชุดกีฬา', hero: 'หน้ากากฮีโร่' }, COLOR_LB = ['ม่วง', 'ชมพู', 'ฟ้า', 'เขียวมะนาว'];
  function seed() {
    GS.setup_();
    var F = GS.FQ, today = GS.todayKey_(), monday = F.addDays(today, -F.weekdayIdx(today)), R = rng(2569);
    var S = sheets['ตั้งค่า'].cells, label = function (k) { return GS.SETTING_ROWS.filter(function (d) { return d[1] === k; })[0][0]; };
    S.filter(function (x) { return x && x[0] === label('programStart'); })[0][1] = F.addDays(monday, -21);
    props.TEACHER_HASH = GS.teacherHash_('demo1234');
    /* ศูนย์ฝึกต้นแบบของครู (เปิดให้นักเรียนเยี่ยมชม) */
    props.TCENTER = JSON.stringify({ v: 3, lv: 46, show: true, at: today + ' 08:00' });
    /* อีเวนต์: งานแรกกำลังจัด งานที่สองอีก 6 วันเริ่ม */
    var E = sheets['อีเวนต์'].cells, ec = headIdx('อีเวนต์');
    if (E[1]) { E[1][ec('เริ่ม')] = thDate(F.addDays(today, -2)); E[1][ec('จบ')] = thDate(F.addDays(today, 4)); }
    if (E[2]) { E[2][ec('เริ่ม')] = thDate(F.addDays(today, 6)); E[2][ec('จบ')] = thDate(F.addDays(today, 12)); }

    var acts = ['วิ่งหรือเดินเร็ว', 'ปั่นจักรยาน', 'กระโดดเชือก', 'เต้น', 'เล่นกีฬา', 'เล่นกลางแจ้ง', 'ยืดเหยียด'], feels = ['สนุก', 'สนุก', 'สนุก', 'เฉย ๆ'];
    var moves = F.DEFAULT_MISSIONS.filter(function (m) { return m.type === 'move'; }), habits = F.DEFAULT_MISSIONS.filter(function (m) { return m.type === 'habit'; });
    var logs = [], done = [], extra = [], tokens = {}, kids = [];
    var rc = headIdx('นักเรียน');
    var addKid = function (sid, name, grade, room, no, o) {
      var res = post({ action: 'register', studentId: sid, name: name, grade: grade, room: room, no: no, pin: '1234' });
      tokens[sid] = res.token;
      var row = sheets['นักเรียน'].cells.filter(function (x) { return String(x[0]) === sid; })[0];
      row[rc('สมัครเมื่อ')] = F.addDays(today, -(o.joined || 24)) + ' 07:45:00';
      if (o.nick) row[rc('ชื่อเล่น')] = o.nick;
      if (o.outfit) row[rc('อวตาร (ชุด)')] = OUTFIT_LB[o.outfit];
      if (o.color) row[rc('สีพื้น')] = o.color;
      if (o.sports) row[rc('กีฬาที่ชอบ')] = o.sports;
      if (o.goal) row[rc('เป้าหมาย')] = o.goal;
      if (o.motto) row[rc('คำประจำตัว')] = o.motto;
      if (o.pins) row[rc('สติกเกอร์โชว์')] = o.pins;
      kids.push({ sid: sid, cls: 'ป.' + grade + '/' + room, grade: grade });
    };
    var addHistory = function (sid, cls, rate, lastGap, rr, todayToo) {
      for (var d = 21; d >= lastGap; d--) {
        var day = F.addDays(today, -d);
        if (day < F.addDays(monday, -21) || rr() > rate) continue;
        var t = day + ' ' + (17 + Math.floor(rr() * 3)) + ':' + ('0' + Math.floor(rr() * 60)).slice(-2) + ':00';
        logs.push({ 'รหัสบันทึก': 'D' + sid + d, 'เวลาที่ส่ง': t, 'วันที่ทำ': day, 'ห้อง': cls, 'เลขประจำตัว': sid, 'กิจกรรม': acts[Math.floor(rr() * acts.length)],
          'นาที': [15, 20, 30, 30, 45, 60][Math.floor(rr() * 6)], 'ความรู้สึก': feels[Math.floor(rr() * feels.length)], 'ช่องทาง': 'เว็บแอป' });
        if (rr() < 0.55) {
          var m = moves[Math.floor(rr() * moves.length)], diff = 1 + Math.floor(rr() * 2);
          done.push({ 'รหัส': 'M' + sid + d, 'เวลาที่ส่ง': t, 'วันที่ทำ': day, 'ห้อง': cls, 'เลขประจำตัว': sid, 'ประเภท': 'ขยับ', 'ภารกิจ': m.steps[diff], 'ความยาก': diff === 1 ? '⭐' : '⭐⭐', 'หลักฐาน': 'ไม่มี' });
        }
        if (rr() < 0.4) {
          var h = habits[Math.floor(rr() * habits.length)];
          done.push({ 'รหัส': 'H' + sid + d, 'เวลาที่ส่ง': t, 'วันที่ทำ': day, 'ห้อง': cls, 'เลขประจำตัว': sid, 'ประเภท': 'สุขนิสัย', 'ภารกิจ': h.steps[1], 'ความยาก': '⭐', 'หลักฐาน': 'ไม่มี' });
        }
      }
      if (todayToo) logs.push({ 'รหัสบันทึก': 'D' + sid + 't', 'เวลาที่ส่ง': today + ' 07:10:00', 'วันที่ทำ': today, 'ห้อง': cls, 'เลขประจำตัว': sid, 'กิจกรรม': 'เล่นกีฬา', 'นาที': 20, 'ความรู้สึก': 'สนุก', 'ช่องทาง': 'เว็บแอป' });
    };
    /* เพื่อน 30 คน ป.1–ป.6 ห้องละ 5 คน */
    var n = 0;
    for (var g = 1; g <= 6; g++) {
      for (var k = 1; k <= 5; k++) {
        var i = n++, sid = String(1000 + g * 100 + k), boy = i % 2 === 0;
        var name = (boy ? 'ด.ช.' : 'ด.ญ.') + FIRST[i] + ' ' + LAST[i % LAST.length];
        var rate = [0.85, 0.7, 0.55, 0.4, 0.15][k - 1], gap = k === 5 ? 9 + g : 1;
        addKid(sid, name, g, 1, k * 3, { nick: k === 4 ? '' : FIRST[i], outfit: i % 4 === 0 ? 'hero' : '', color: COLOR_LB[i % 4] });
        addHistory(sid, 'ป.' + g + '/1', rate, gap, rng(i + 7), k <= 2 && g % 2 === 0);
      }
    }
    var never = post({ action: 'register', studentId: '1606', name: 'ด.ช.ภูริ ยังไม่เริ่ม', grade: 6, room: 1, no: 18, pin: '1234' });
    sheets['นักเรียน'].cells.filter(function (x) { return String(x[0]) === '1606'; })[0][rc('สมัครเมื่อ')] = F.addDays(today, -12) + ' 08:00:00';
    void never;
    /* นักเรียนตัวอย่าง 9999 (มีประวัติแล้ว) */
    addKid('9999', 'ด.ญ.ทดลอง ใช้งาน', 4, 1, 30, { nick: 'ทดลอง', outfit: 'sport', color: 'ชมพู', sports: 'ฟุตบอล, เต้น', goal: 'วิ่งเร็วขึ้น', motto: 'ไม่ยอมแพ้!', pins: 'first,fire3', joined: 22 });
    addHistory('9999', 'ป.4/1', 0.8, 1, rng(99), false);
    for (var q = 14; q >= 1; q -= 2) extra.push({ 'รหัส': 'Q9999' + q, 'เวลาที่ส่ง': F.addDays(today, -q) + ' 19:00:00', 'วันที่ทำ': F.addDays(today, -q), 'ห้อง': 'ป.4/1', 'เลขประจำตัว': '9999', 'ประเภท': 'คำถาม', 'เรื่อง': 'คำถามสุขภาพ', 'คำตอบ': 'ก', 'ผล': q % 4 ? 'ถูก' : 'ผิด' });
    ['1401', '1402', '1301'].forEach(function (from, j) {
      extra.push({ 'รหัส': 'C' + from, 'เวลาที่ส่ง': F.addDays(today, -j) + ' 18:30:00', 'วันที่ทำ': F.addDays(today, -j), 'ห้อง': 'ป.4/1', 'เลขประจำตัว': from, 'ประเภท': 'กำลังใจ', 'เรื่อง': 'ให้กำลังใจ 9999', 'คำตอบ': '👏', 'ผล': 'ทำแล้ว' });
    });
    var byTime = function (a, b) { return a['เวลาที่ส่ง'] < b['เวลาที่ส่ง'] ? -1 : a['เวลาที่ส่ง'] > b['เวลาที่ส่ง'] ? 1 : 0; };
    logs.sort(byTime).forEach(function (o) { sheets['บันทึก'].appendRow(rowOf('บันทึก', o)); });
    done.sort(byTime).forEach(function (o) { sheets['ภารกิจที่ทำ'].appendRow(rowOf('ภารกิจที่ทำ', o)); });
    extra.sort(byTime).forEach(function (o) { sheets['กิจกรรมเสริม'].appendRow(rowOf('กิจกรรมเสริม', o)); });
    /* ผลสมรรถภาพ 2 ภาคเรียนของนักเรียนตัวอย่าง */
    [['1/2569', 4, 12, 20, 88], ['2/2569', 7, 17, 18, 101]].forEach(function (r) {
      sheets['สมรรถภาพ'].appendRow(rowOf('สมรรถภาพ', { 'เลขประจำตัว': '9999', 'ห้อง': 'ป.4/1', 'เลขที่': 30, 'ภาคเรียน': r[0], 'นั่งงอตัว (ซม.)': r[1], 'ดันพื้น 30 วิ (ครั้ง)': r[2], 'ลุกนั่ง 60 วิ (ครั้ง)': r[3], 'ยืนยกเข่า 3 นาที (ครั้ง)': r[4], 'บันทึกเมื่อ': today + ' 10:00:00' }));
    });
    /* เควสบ้านตัวอย่างมีคลิปให้ดู (ของจริงครูใส่ลิงก์เองในแท็บเควสบ้าน ช่อง คลิป) */
    var Q = sheets['เควสบ้าน'].cells, qc = headIdx('เควสบ้าน')('คลิป');
    if (qc >= 0) for (var r = 1; r < Q.length; r++) if (Q[r] && Q[r][0] !== '') Q[r][qc] = moves[(r * 3) % moves.length].clip;
    /* ดูคลิปครบวันนี้ 3 คน + เควสบ้านสัปดาห์นี้ 2 คน + นักเรียนตัวอย่างดูคลิปเมื่อวาน + รูปโปรไฟล์รออนุมัติ 1 รูป */
    [['1201', 'move'], ['1402', 'habit'], ['1601', 'move']].forEach(function (x) {
      var r = post({ action: 'clip', token: tokens[x[0]], entry: { kind: x[1], date: today } });
      if (!r.ok && r.code === 'NO_CLIP') post({ action: 'clip', token: tokens[x[0]], entry: { kind: 'move', date: today } });
    });
    ['1401', '1301'].forEach(function (sid) { post({ action: 'quest', token: tokens[sid] }); });
    if (!post({ action: 'clip', token: tokens['9999'], entry: { kind: 'habit', date: F.addDays(today, -1) } }).ok) post({ action: 'clip', token: tokens['9999'], entry: { kind: 'move', date: F.addDays(today, -1) } });
    post({ action: 'photo', token: tokens['1502'], mime: 'image/jpeg', data: img('face', 5) });
    /* เกมศูนย์ฝึก: เพื่อนหลายคนสร้างไว้แล้ว (ใช้เหรียญจากแต้มจริงของแต่ละคน ถ้าเหรียญไม่พอระบบไม่ให้สร้าง) + ถูกใจกันบ้าง */
    /* 6B-23: ศูนย์ฝึกปุ่มเดียว กดอัปเกรดตามจำนวนครั้ง (เหรียญหมดก็หยุด) */
    var gup = function (sid, n) {
      for (var i = 0; i < n; i++) if (!post({ action: 'game', token: tokens[sid], op: 'up' }).ok) break;
    };
    [['1401', 27], ['1402', 8], ['1403', 3], ['1301', 15], ['1302', 4], ['1501', 23], ['1502', 7], ['1601', 18], ['1602', 5], ['1201', 6], ['1202', 2], ['1101', 2], ['1102', 1], ['9999', 4]].forEach(function (x) { gup(x[0], x[1]); });
    /* สัตว์เลี้ยงคู่หูของเพื่อน (เด็กตัวอย่าง 9999 ยังไม่ฟัก จะได้ลองฟักไข่เอง) */
    /* ตัวเลขท้าย = ค่าสุ่มให้เพื่อนได้น้องใหม่ไว้โชว์ (นาก ฟลามิงโก แฮมสเตอร์ แกะ ฉลาม เสือขาว นกฮูก อุรังอุตัง นกอินทรี) */
    [['1401', 'โมจิ', ['cap'], 0.78412], ['1402', 'ข้าวปั้น', ['bow'], 0.93857], ['1403', 'ถั่วแดง', [], 0.23021], ['1301', 'ไข่ตุ๋น', ['beanie', 'scarf'], 0.39271], ['1501', 'เจ้าเหมียว', ['sun', 'whistle'], 0.93286],
     ['1601', 'จัมโบ้', ['flower'], 0.92714], ['1201', 'มะลิ', ['party'], 0.85471], ['1101', 'ปุยฝ้าย', [], 0.94429], ['1502', 'ก้อนเมฆ', ['round'], 0.96143]].forEach(function (x) {
      var R0 = Math.random;
      if (x[3]) Math.random = function () { return x[3]; };
      var hatched;
      try { hatched = post({ action: 'pet', token: tokens[x[0]], op: 'hatch' }); } finally { Math.random = R0; }
      if (!hatched.ok) return;
      post({ action: 'pet', token: tokens[x[0]], op: 'name', name: x[1] });
      x[2].forEach(function (w) { post({ action: 'pet', token: tokens[x[0]], op: 'buy', item: w }); });
      post({ action: 'pet', token: tokens[x[0]], op: 'feed', item: 'apple' });
    });
    [['1402', '9999'], ['1301', '9999'], ['1403', '1401'], ['1402', '1401'], ['1501', '1401'], ['9999', '1401'], ['1601', '1501'], ['1201', '1601']].forEach(function (x) {
      post({ action: 'glike', token: tokens[x[0]], k: GS.cardKey_(x[1]) });
    });
    GS.rebuildSummary_();
    persist();
  }

  /* ---------- ทางเข้าจากหน้าเว็บ ---------- */
  var WRITES = { register: 1, submit: 1, delete: 1, mission: 1, quest: 1, clip: 1, quiz: 1, event: 1, profile: 1, photo: 1, photodel: 1, cheer: 1, tphoto: 1, tfitsave: 1, dust: 1 };
  /* โหมดตัวอย่าง: วันนี้เป็นวันฝุ่นสีส้มเสมอ (ครูเปลี่ยนสีเองได้ในโหมดครู) */
  function demoDust() {
    var t = GS.todayKey_(), d = null;
    try { d = JSON.parse(props.DUST || 'null'); } catch (e) {}
    if (!d || d.date !== t) props.DUST = JSON.stringify({ date: t, v: 52.4, lv: 4, at: t + ' 13:00', st: 'เขตปทุมวัน (ข้อมูลตัวอย่าง)', id: 'demo', max: 4, ovr: 0, err: '' });
  }
  function api(body) {
    var out;
    try { demoDust(); } catch (e) {}
    try { out = JSON.parse(GS.doPost({ postData: { contents: JSON.stringify(body || {}) } }).body); }
    catch (e) { out = { ok: false, code: 'DEMO_ERR', error: 'โหมดตัวอย่างขัดข้อง: ' + (e && e.message) }; }
    if (WRITES[body && body.action] && out && out.ok !== false) { try { GS.rebuildSummary_(); } catch (e) {} }
    persist();
    return out;
  }
  function start() { if (!restore()) seed(); }
  start();
  window.HBDemo = {
    api: function (body) { return new Promise(function (ok) { setTimeout(function () { ok(api(body)); }, 120); }); },
    reset: function () { wipe(); seed(); },
    teacherPass: 'demo1234', student: { sid: '9999', pin: '1234' },
    _sheets: sheets, _gs: GS
  };
})();
