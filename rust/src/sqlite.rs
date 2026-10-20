//! A thin, safe-ish wrapper over the vendored SQLite C library. std + our own
//! FFI only — no rusqlite. Exposes just what this server needs: open, exec,
//! parameterised query returning JSON rows, execute, and last_insert_rowid.

use std::ffi::{c_char, c_double, c_int, c_void, CStr, CString};
use std::path::Path;

use crate::json::{Object, Value};

#[allow(non_camel_case_types)]
type sqlite3 = c_void;
#[allow(non_camel_case_types)]
type sqlite3_stmt = c_void;

const SQLITE_OK: c_int = 0;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;
const SQLITE_OPEN_READWRITE: c_int = 0x00000002;
const SQLITE_OPEN_CREATE: c_int = 0x00000004;
// Column types
const SQLITE_INTEGER: c_int = 1;
const SQLITE_FLOAT: c_int = 2;
const SQLITE_TEXT: c_int = 3;
const SQLITE_NULL: c_int = 5;

extern "C" {
    fn sqlite3_open_v2(
        filename: *const c_char,
        db: *mut *mut sqlite3,
        flags: c_int,
        vfs: *const c_char,
    ) -> c_int;
    fn sqlite3_close(db: *mut sqlite3) -> c_int;
    fn sqlite3_errmsg(db: *mut sqlite3) -> *const c_char;
    fn sqlite3_busy_timeout(db: *mut sqlite3, ms: c_int) -> c_int;
    fn sqlite3_exec(
        db: *mut sqlite3,
        sql: *const c_char,
        cb: *const c_void,
        arg: *mut c_void,
        errmsg: *mut *mut c_char,
    ) -> c_int;
    fn sqlite3_free(p: *mut c_void);
    fn sqlite3_prepare_v2(
        db: *mut sqlite3,
        sql: *const c_char,
        nbyte: c_int,
        stmt: *mut *mut sqlite3_stmt,
        tail: *mut *const c_char,
    ) -> c_int;
    fn sqlite3_bind_null(stmt: *mut sqlite3_stmt, idx: c_int) -> c_int;
    fn sqlite3_bind_int64(stmt: *mut sqlite3_stmt, idx: c_int, v: i64) -> c_int;
    fn sqlite3_bind_double(stmt: *mut sqlite3_stmt, idx: c_int, v: c_double) -> c_int;
    fn sqlite3_bind_text(
        stmt: *mut sqlite3_stmt,
        idx: c_int,
        text: *const c_char,
        n: c_int,
        destructor: Option<unsafe extern "C" fn(*mut c_void)>,
    ) -> c_int;
    fn sqlite3_step(stmt: *mut sqlite3_stmt) -> c_int;
    fn sqlite3_finalize(stmt: *mut sqlite3_stmt) -> c_int;
    fn sqlite3_column_count(stmt: *mut sqlite3_stmt) -> c_int;
    fn sqlite3_column_name(stmt: *mut sqlite3_stmt, i: c_int) -> *const c_char;
    fn sqlite3_column_type(stmt: *mut sqlite3_stmt, i: c_int) -> c_int;
    fn sqlite3_column_int64(stmt: *mut sqlite3_stmt, i: c_int) -> i64;
    fn sqlite3_column_double(stmt: *mut sqlite3_stmt, i: c_int) -> c_double;
    fn sqlite3_column_text(stmt: *mut sqlite3_stmt, i: c_int) -> *const u8;
    fn sqlite3_column_bytes(stmt: *mut sqlite3_stmt, i: c_int) -> c_int;
    fn sqlite3_changes(db: *mut sqlite3) -> c_int;
    fn sqlite3_last_insert_rowid(db: *mut sqlite3) -> i64;
}

/// A value bound to a query parameter.
#[derive(Clone, Debug)]
pub enum SqlValue {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
}

pub struct Connection {
    db: *mut sqlite3,
}

// The raw handle is only ever touched behind a Mutex in Database, and SQLite is
// built with SQLITE_THREADSAFE=1.
unsafe impl Send for Connection {}

impl Connection {
    pub fn open(path: &Path) -> Result<Connection, String> {
        let cpath = CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| "bad path".to_string())?;
        let mut db: *mut sqlite3 = std::ptr::null_mut();
        let rc = unsafe {
            sqlite3_open_v2(
                cpath.as_ptr(),
                &mut db,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                std::ptr::null(),
            )
        };
        if rc != SQLITE_OK {
            let msg = errmsg(db);
            unsafe { sqlite3_close(db) };
            return Err(msg);
        }
        unsafe { sqlite3_busy_timeout(db, 30000) };
        Ok(Connection { db })
    }

    /// Run one or more statements with no parameters (schema, PRAGMAs).
    pub fn exec(&self, sql: &str) -> Result<(), String> {
        let csql = CString::new(sql).map_err(|_| "bad sql".to_string())?;
        let mut err: *mut c_char = std::ptr::null_mut();
        let rc = unsafe {
            sqlite3_exec(
                self.db,
                csql.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                &mut err,
            )
        };
        if rc != SQLITE_OK {
            let msg = if err.is_null() {
                errmsg(self.db)
            } else {
                let m = unsafe { CStr::from_ptr(err) }.to_string_lossy().into_owned();
                unsafe { sqlite3_free(err as *mut c_void) };
                m
            };
            return Err(msg);
        }
        Ok(())
    }

    fn prepare(&self, sql: &str) -> Result<Stmt, String> {
        let csql = CString::new(sql).map_err(|_| "bad sql".to_string())?;
        let mut stmt: *mut sqlite3_stmt = std::ptr::null_mut();
        let rc = unsafe {
            sqlite3_prepare_v2(self.db, csql.as_ptr(), -1, &mut stmt, std::ptr::null_mut())
        };
        if rc != SQLITE_OK {
            return Err(errmsg(self.db));
        }
        Ok(Stmt { stmt })
    }

    /// Run a query and return the matching rows as JSON objects.
    pub fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Object>, String> {
        let stmt = self.prepare(sql)?;
        // Keep bound text alive until after stepping (SQLITE_STATIC, no copy).
        let _held = bind_all(&stmt, params)?;
        let ncol = unsafe { sqlite3_column_count(stmt.stmt) };
        let names: Vec<String> = (0..ncol)
            .map(|i| unsafe {
                CStr::from_ptr(sqlite3_column_name(stmt.stmt, i))
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        let mut rows = Vec::new();
        loop {
            let rc = unsafe { sqlite3_step(stmt.stmt) };
            if rc == SQLITE_ROW {
                let mut obj = Object::new();
                for i in 0..ncol {
                    obj.insert(names[i as usize].clone(), column_value(&stmt, i));
                }
                rows.push(obj);
            } else if rc == SQLITE_DONE {
                break;
            } else {
                return Err(errmsg(self.db));
            }
        }
        Ok(rows)
    }

    /// Execute a statement, returning the number of rows changed.
    pub fn execute(&self, sql: &str, params: &[SqlValue]) -> Result<usize, String> {
        let stmt = self.prepare(sql)?;
        let _held = bind_all(&stmt, params)?;
        loop {
            let rc = unsafe { sqlite3_step(stmt.stmt) };
            if rc == SQLITE_DONE {
                break;
            } else if rc == SQLITE_ROW {
                continue;
            } else {
                return Err(errmsg(self.db));
            }
        }
        Ok(unsafe { sqlite3_changes(self.db) } as usize)
    }

    pub fn last_insert_rowid(&self) -> i64 {
        unsafe { sqlite3_last_insert_rowid(self.db) }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        unsafe { sqlite3_close(self.db) };
    }
}

struct Stmt {
    stmt: *mut sqlite3_stmt,
}
impl Drop for Stmt {
    fn drop(&mut self) {
        unsafe { sqlite3_finalize(self.stmt) };
    }
}

fn bind_all(stmt: &Stmt, params: &[SqlValue]) -> Result<Vec<CString>, String> {
    let mut held: Vec<CString> = Vec::new();
    for (i, p) in params.iter().enumerate() {
        let idx = (i + 1) as c_int;
        let rc = unsafe {
            match p {
                SqlValue::Null => sqlite3_bind_null(stmt.stmt, idx),
                SqlValue::Int(n) => sqlite3_bind_int64(stmt.stmt, idx, *n),
                SqlValue::Real(f) => sqlite3_bind_double(stmt.stmt, idx, *f),
                SqlValue::Text(s) => {
                    let c = CString::new(s.as_bytes())
                        .unwrap_or_else(|_| CString::new(s.replace('\0', "")).unwrap());
                    let len = c.as_bytes().len() as c_int;
                    let ptr = c.as_ptr();
                    held.push(c);
                    // SQLITE_STATIC: we keep `c` alive in `held` until finalize.
                    sqlite3_bind_text(stmt.stmt, idx, ptr, len, None)
                }
            }
        };
        if rc != SQLITE_OK {
            return Err(format!("bind error at parameter {idx}"));
        }
    }
    Ok(held)
}

fn column_value(stmt: &Stmt, i: c_int) -> Value {
    unsafe {
        match sqlite3_column_type(stmt.stmt, i) {
            SQLITE_INTEGER => Value::Int(sqlite3_column_int64(stmt.stmt, i)),
            SQLITE_FLOAT => Value::Float(sqlite3_column_double(stmt.stmt, i)),
            SQLITE_TEXT => {
                let ptr = sqlite3_column_text(stmt.stmt, i);
                let len = sqlite3_column_bytes(stmt.stmt, i) as usize;
                if ptr.is_null() {
                    Value::Str(String::new())
                } else {
                    let bytes = std::slice::from_raw_parts(ptr, len);
                    Value::Str(String::from_utf8_lossy(bytes).into_owned())
                }
            }
            SQLITE_NULL => Value::Null,
            _ => {
                // BLOB: return as lossy string (not used by this schema).
                let ptr = sqlite3_column_text(stmt.stmt, i);
                let len = sqlite3_column_bytes(stmt.stmt, i) as usize;
                if ptr.is_null() {
                    Value::Null
                } else {
                    let bytes = std::slice::from_raw_parts(ptr, len);
                    Value::Str(String::from_utf8_lossy(bytes).into_owned())
                }
            }
        }
    }
}

fn errmsg(db: *mut sqlite3) -> String {
    if db.is_null() {
        return "sqlite: null handle".to_string();
    }
    unsafe {
        let p = sqlite3_errmsg(db);
        if p.is_null() {
            "sqlite error".to_string()
        } else {
            CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_exec_query() {
        let dir = std::env::temp_dir().join(format!("russdesk-sq-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let conn = Connection::open(&dir.join("t.db")).unwrap();
        conn.exec("CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT, score REAL)")
            .unwrap();
        let n = conn
            .execute(
                "INSERT INTO t(name, score) VALUES (?1, ?2)",
                &[SqlValue::Text("alice".into()), SqlValue::Real(1.5)],
            )
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(conn.last_insert_rowid(), 1);
        conn.execute(
            "INSERT INTO t(name, score) VALUES (?1, ?2)",
            &[SqlValue::Text("bob".into()), SqlValue::Null],
        )
        .unwrap();
        let rows = conn.query("SELECT * FROM t ORDER BY id", &[]).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get("name").unwrap().as_str(), Some("alice"));
        assert_eq!(rows[0].get("score").unwrap().as_f64(), Some(1.5));
        assert!(rows[1].get("score").unwrap().is_null());
        let one = conn
            .query("SELECT name FROM t WHERE name = ?1", &[SqlValue::Text("bob".into())])
            .unwrap();
        assert_eq!(one.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
