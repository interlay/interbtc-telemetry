CREATE TABLE clients
(
    account_id     TEXT PRIMARY KEY,
    client_name    TEXT NOT NULL,
    client_version TEXT NOT NULL,
    ip_addr        VARCHAR(15),
    updated        TIMESTAMP
);