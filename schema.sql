/* This file is sourced during the initialization
 * of the crawler. Make sure everything is CREATE
 * IF NOT EXISTS, otherwise there will be errors
 */

/* Crawler Tables */


CREATE TABLE IF NOT EXISTS crawl (
    crawl_id INTEGER PRIMARY KEY AUTOINCREMENT,
    upload_crawl_id integer,
    finished BOOLEAN NOT NULL DEFAULT 0,
    start_time DATETIME DEFAULT  (datetime('now', 'localtime')));

CREATE TABLE IF NOT EXISTS site_visits (
    visit_id INTEGER PRIMARY KEY,
    crawl_id INTEGER NOT NULL,
    site_url VARCHAR(500) NOT NULL,
    hash_url VARCHAR(500) NOT NULL,
    create_time DATETIME DEFAULT  (datetime('now', 'localtime')),
    FOREIGN KEY(crawl_id) REFERENCES crawl(id));

/* Firefox Storage Vector Dumps */

CREATE TABLE IF NOT EXISTS flash_cookies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    crawl_id INTEGER NOT NULL,
    visit_id INTEGER NOT NULL,
    domain VARCHAR(500),
    filename VARCHAR(500),
    local_path VARCHAR(1000),
    key TEXT,
    content TEXT,
    FOREIGN KEY(crawl_id) REFERENCES crawl(id),
    FOREIGN KEY(visit_id) REFERENCES site_visits(id));

CREATE TABLE IF NOT EXISTS firefox_profile_cookies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    crawl_id INTEGER NOT NULL,
    visit_id INTEGER NOT NULL,
    baseDomain TEXT,
    name TEXT,
    value TEXT,
    host TEXT,
    path TEXT,
    expiry INTEGER,
    accessed INTEGER,
    creationTime INTEGER,
    isSecure INTEGER,
    InbrowserElement Integer,
    samesite text,
    isHttpOnly INTEGER, stage text);

CREATE TABLE IF NOT EXISTS chrome_profile_cookies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    crawl_id INTEGER NOT NULL,
    visit_id INTEGER NOT NULL,
    creation_utc    INTEGER NOT NULL,
    host_key        TEXT    NOT NULL,
    name            TEXT    NOT NULL,
    value           TEXT    NOT NULL,
    decrypted_value           TEXT,
    path            TEXT    NOT NULL,
    expires_utc     INTEGER NOT NULL,
    is_secure       INTEGER NOT NULL,
    is_httponly     INTEGER NOT NULL,
    last_access_utc INTEGER NOT NULL,
    has_expires     INTEGER NOT NULL
                            DEFAULT 1,
    is_persistent   INTEGER NOT NULL
                            DEFAULT 1,
    priority        INTEGER NOT NULL
                            DEFAULT 1,
    encrypted_value BLOB    DEFAULT '',
    firstpartyonly  INTEGER NOT NULL
                            DEFAULT 0,
    stage    text);


CREATE TABLE IF NOT EXISTS session_cookies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    crawl_id INTEGER NOT NULL,
    visit_id INTEGER NOT NULL,
    baseDomain TEXT,
    name TEXT,
    value TEXT,
    host TEXT,
    path TEXT,
    expiry INTEGER,
    accessed INTEGER,
    creationTime INTEGER,
    isSecure INTEGER,
    isHttpOnly INTEGER,
    FOREIGN KEY(crawl_id) REFERENCES crawl(id),
    FOREIGN KEY(visit_id) REFERENCES site_visits(id));


CREATE TABLE IF NOT EXISTS js_localStorage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    crawl_id INTEGER NOT NULL,
    visit_id INTEGER NOT NULL,
    scope TEXT,
    KEY TEXT,
    value TEXT, stage text,
    create_time DATETIME DEFAULT  (datetime('now', 'localtime')),
    FOREIGN KEY(crawl_id) REFERENCES crawl(id));


CREATE TABLE IF NOT EXISTS profile_localStorage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    crawl_id INTEGER NOT NULL,
    scope TEXT,
    KEY TEXT,
    value TEXT,
    stage text,
    create_time DATETIME DEFAULT  (datetime('now', 'localtime')),
    FOREIGN KEY(crawl_id) REFERENCES crawl(id));

CREATE TABLE IF NOT EXISTS js_sessionStorage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    crawl_id INTEGER NOT NULL,
    visit_id INTEGER NOT NULL,
    scope TEXT,
    KEY TEXT,
    value TEXT,
    create_time DATETIME DEFAULT  (datetime('now', 'localtime')),
    FOREIGN KEY(crawl_id) REFERENCES crawl(id));




CREATE TABLE openWPM_javascript (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    crawl_id        INTEGER,
    script_url      TEXT,
    script_line     TEXT,
    script_col      TEXT,
    func_name       TEXT,
    script_loc_eval TEXT,
    call_stack      TEXT,
    symbol          TEXT,
    operation       TEXT,
    value           TEXT,
    arguments       TEXT
);

CREATE TABLE DFPM_javascript (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    crawl_id        INTEGER,
    level           VARCHAR (30),
    category        VARCHAR (100),
    url             VARCHAR (1000),
    method          VARCHAR (20),
    symbol       VARCHAR (10000),
    host            VARCHAR (1000),
    function_name      TEXT,
    script_url      TEXT,
    script_line     TEXT,
    script_col      TEXT,
    createdate      DATETIME        DEFAULT (datetime('now', 'localtime') ) 
);




CREATE TABLE IF NOT EXISTS links_found (
    crawl_id INTEGER ,
    visit_id INTEGER ,
    found_on TEXT,
    location TEXT,
   type text, hash_url text    );

CREATE TABLE IF NOT EXISTS device_config (
    crawl_id INTEGER ,
    visit_id INTEGER ,
    key TEXT,
    value TEXT   );
