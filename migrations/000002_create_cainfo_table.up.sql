CREATE TABLE IF NOT EXISTS `T_CAINFO` (
  `id` VARCHAR(36) NOT NULL PRIMARY KEY,
  `password` VARCHAR(255) NOT NULL DEFAULT '',
  `created` VARCHAR(19) NOT NULL DEFAULT '1970-01-01T09:00:00'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;