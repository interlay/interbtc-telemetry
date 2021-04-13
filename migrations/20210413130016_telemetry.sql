CREATE TABLE clients
(
    account_id     TEXT PRIMARY KEY,
    client_version TEXT NOT NULL,
    ip_addr        VARCHAR(15),
    updated        TIMESTAMP
);