CREATE DATABASE db_repository;

USE db_repository;

CREATE TABLE data_prodi (
    id INT PRIMARY KEY AUTO_INCREMENT, kode_prodi CHAR(5), nama_prodi VARCHAR(100)
);

CREATE TABLE data_dosen (
    nip VARCHAR(30) PRIMARY KEY, nama_lengkap VARCHAR(100), prodi_id INT, FOREIGN KEY (prodi_id) REFERENCES data_prodi (id)
);

CREATE TABLE data_dokumen (
    id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT, nip VARCHAR(30), type_dokumen ENUM('file', 'url'), nama_dokumen VARCHAR(255), nama_file VARCHAR(255), FOREIGN KEY (nip) REFERENCES data_dosen (nip)
);

CREATE TABLE invalidtoken (
    id INT AUTO_INCREMENT PRIMARY KEY, jti VARCHAR(36) NOT NULL UNIQUE
);