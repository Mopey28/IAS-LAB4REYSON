-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Jun 10, 2025 at 04:43 AM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `access_db`
--

-- --------------------------------------------------------

--
-- Table structure for table `access_logs`
--

CREATE TABLE `access_logs` (
  `id` int(11) NOT NULL,
  `user_id` varchar(50) NOT NULL,
  `action` varchar(50) NOT NULL,
  `status` varchar(20) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `user_agent` varchar(255) DEFAULT NULL,
  `timestamp` datetime NOT NULL,
  `details` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `access_logs`
--

INSERT INTO `access_logs` (`id`, `user_id`, `action`, `status`, `ip_address`, `user_agent`, `timestamp`, `details`) VALUES
(1, '0', 'LOGIN', 'success', '::1', NULL, '2025-06-10 04:46:17', NULL),
(2, '0', 'MFA_VERIFICATION', 'success', '::1', NULL, '2025-06-10 04:47:01', NULL),
(3, '0', 'LOGOUT', 'success', '::1', NULL, '2025-06-10 04:47:13', NULL),
(4, '0', 'LOGIN', 'success', '::1', NULL, '2025-06-10 04:58:31', NULL),
(5, '0', 'MFA_VERIFICATION', 'success', '::1', NULL, '2025-06-10 04:58:51', NULL),
(6, '0', 'LOGOUT', 'success', '::1', NULL, '2025-06-10 04:59:17', NULL),
(7, '0', 'LOGIN', 'success', '::1', NULL, '2025-06-10 05:07:02', NULL),
(8, '0', 'MFA_VERIFICATION', 'failed', '::1', NULL, '2025-06-10 05:07:31', NULL),
(9, '0', 'MFA_VERIFICATION', 'failed', '::1', NULL, '2025-06-10 05:07:42', NULL),
(10, '0', 'MFA_VERIFICATION', 'success', '::1', NULL, '2025-06-10 05:07:48', NULL),
(11, '0', 'LOGOUT', 'success', '::1', NULL, '2025-06-10 05:10:31', NULL),
(12, '0', 'LOGIN', 'success', '::1', NULL, '2025-06-10 05:11:26', NULL),
(13, '0', 'MFA_VERIFICATION', 'failed', '::1', NULL, '2025-06-10 05:12:45', NULL),
(14, '0', 'MFA_VERIFICATION', 'success', '::1', NULL, '2025-06-10 05:12:58', NULL),
(15, '0', 'LOGOUT', 'success', '::1', NULL, '2025-06-10 05:22:37', NULL),
(16, '0', 'LOGIN', 'success', '::1', NULL, '2025-06-10 05:28:01', NULL),
(17, '0', 'MFA_VERIFICATION', 'success', '::1', NULL, '2025-06-10 05:28:29', NULL),
(18, '0', 'LOGOUT', 'success', '::1', NULL, '2025-06-10 05:32:30', NULL),
(19, '0', 'LOGIN', 'success', '::1', NULL, '2025-06-10 05:34:02', NULL),
(20, '0', 'MFA_VERIFICATION', 'failed', '::1', NULL, '2025-06-10 05:35:29', NULL),
(21, '0', 'MFA_VERIFICATION', 'success', '::1', NULL, '2025-06-10 05:36:09', NULL),
(22, '0', 'LOGOUT', 'success', '::1', NULL, '2025-06-10 05:38:19', NULL),
(23, '0', 'LOGIN', 'success', '::1', NULL, '2025-06-10 05:38:24', NULL),
(24, '0', 'MFA_VERIFICATION', 'success', '::1', NULL, '2025-06-10 05:44:29', NULL),
(25, '0', 'LOGOUT', 'success', '::1', NULL, '2025-06-10 05:46:40', NULL),
(26, '0', 'LOGIN', 'success', '::1', NULL, '2025-06-10 05:46:52', NULL),
(27, '0', 'MFA_VERIFICATION', 'success', '::1', NULL, '2025-06-10 05:47:29', NULL),
(28, '0', 'LOGOUT', 'success', '::1', NULL, '2025-06-10 05:57:10', NULL),
(29, '0', 'LOGIN', 'success', '::1', NULL, '2025-06-10 05:57:16', NULL),
(30, '0', 'MFA_VERIFICATION', 'success', '::1', NULL, '2025-06-10 05:57:53', NULL),
(31, '0', 'LOGOUT', 'success', '::1', NULL, '2025-06-10 06:12:00', NULL),
(32, '0', 'LOGIN', 'success', '::1', NULL, '2025-06-10 06:17:11', NULL),
(33, '0', 'MFA_VERIFICATION', 'success', '::1', NULL, '2025-06-10 06:17:36', NULL),
(34, '0', 'LOGOUT', 'success', '::1', NULL, '2025-06-10 06:17:56', NULL),
(35, '0', 'LOGIN', 'success', '::1', NULL, '2025-06-10 06:18:16', NULL),
(36, '0', 'MFA_VERIFICATION', 'success', '::1', NULL, '2025-06-10 06:18:32', NULL),
(37, '0', 'LOGOUT', 'success', '::1', NULL, '2025-06-10 06:19:02', NULL),
(38, '0', 'LOGIN', 'success', '::1', NULL, '2025-06-10 06:20:50', NULL),
(39, '0', 'MFA_VERIFICATION', 'success', '::1', NULL, '2025-06-10 06:21:08', NULL),
(40, '0', 'LOGIN', 'success', '::1', NULL, '2025-06-10 06:25:51', NULL),
(41, '0', 'MFA_VERIFICATION', 'success', '::1', NULL, '2025-06-10 06:26:23', NULL),
(42, '0', 'LOGOUT', 'success', '::1', NULL, '2025-06-10 06:29:08', NULL),
(43, '0', 'LOGOUT', 'success', '::1', NULL, '2025-06-10 06:49:31', NULL),
(44, '0', 'LOGIN', 'success', '::1', NULL, '2025-06-10 06:49:37', NULL),
(45, '0', 'LOGIN', 'success', '::1', NULL, '2025-06-10 06:50:32', NULL),
(46, '0', 'LOGIN', 'success', '::1', NULL, '2025-06-10 06:50:35', NULL),
(47, '0', 'MFA_VERIFICATION', 'success', '::1', NULL, '2025-06-10 06:51:14', NULL),
(48, '0', 'LOGOUT', 'success', '::1', NULL, '2025-06-10 07:03:09', NULL),
(49, '0', 'LOGIN', 'success', '::1', NULL, '2025-06-10 07:03:22', NULL),
(50, 'admin', 'MFA_VERIFICATION', 'failed', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0', '2025-06-10 07:11:47', ''),
(51, 'admin', 'MFA_VERIFICATION', 'success', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0', '2025-06-10 07:12:01', ''),
(52, 'user', 'LOGIN', 'success', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', '2025-06-10 07:18:49', ''),
(53, 'user', 'MFA_VERIFICATION', 'failed', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', '2025-06-10 07:19:08', ''),
(54, 'user', 'MFA_VERIFICATION', 'failed', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', '2025-06-10 07:19:10', ''),
(55, 'user', 'MFA_VERIFICATION', 'success', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', '2025-06-10 07:19:30', ''),
(56, 'admin', 'LOGIN', 'success', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', '2025-06-10 10:22:23', ''),
(57, 'admin', 'MFA_VERIFICATION', 'failed', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', '2025-06-10 10:23:08', ''),
(58, 'admin', 'MFA_VERIFICATION', 'success', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', '2025-06-10 10:23:15', ''),
(59, 'user', 'LOGIN', 'success', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0', '2025-06-10 10:25:20', ''),
(60, 'user', 'MFA_VERIFICATION', 'success', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0', '2025-06-10 10:25:31', '');

-- --------------------------------------------------------

--
-- Table structure for table `security_alerts`
--

CREATE TABLE `security_alerts` (
  `id` int(11) NOT NULL,
  `alert_type` varchar(50) NOT NULL,
  `severity` enum('low','medium','high','critical') NOT NULL,
  `description` text NOT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_id` varchar(50) DEFAULT NULL,
  `timestamp` datetime NOT NULL,
  `status` enum('new','investigating','resolved') NOT NULL DEFAULT 'new'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `security_alerts`
--

INSERT INTO `security_alerts` (`id`, `alert_type`, `severity`, `description`, `ip_address`, `user_id`, `timestamp`, `status`) VALUES
(1, 'suspicious_ip', 'medium', 'Suspicious activity from IP: ::1 - Multiple user attempts', '::1', NULL, '2025-06-10 07:18:49', 'new'),
(2, 'suspicious_ip', 'medium', 'Suspicious activity from IP: ::1 - Multiple user attempts', '::1', NULL, '2025-06-10 07:19:08', 'new'),
(3, 'suspicious_ip', 'medium', 'Suspicious activity from IP: ::1 - Multiple user attempts', '::1', NULL, '2025-06-10 07:19:10', 'new'),
(4, 'suspicious_ip', 'medium', 'Suspicious activity from IP: ::1 - Multiple user attempts', '::1', NULL, '2025-06-10 07:19:30', 'new');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) DEFAULT NULL,
  `password` varchar(255) NOT NULL,
  `role` varchar(20) NOT NULL,
  `mfa_secret` varchar(32) DEFAULT NULL,
  `failed_attempts` int(11) DEFAULT 0,
  `is_locked` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `email`, `password`, `role`, `mfa_secret`, `failed_attempts`, `is_locked`) VALUES
(7, 'admin', NULL, '$2y$10$sNhw6nRzKk1Wq1DkTR49QublgDO7agOnWfNduQ1au8rYv8k/TNGEe', 'admin', 'V4CDXUB3DOHVKS4H', 0, 0),
(8, 'user', NULL, '$2y$10$M5c4xDG/a/u2jC4svSbCDO7sQNwuocXOdTL.1XufIQW3Ifnj9jjC.', 'user', '6AFKNBMR32TWMLF5', 0, 0),
(9, 'Jandel', NULL, '$2y$10$T8lk/OHbGUNQlYik87vmeuHGspKJ54BPLZnTwPGePNR1KCXqERkqu', 'user', 'QSHW3VOZGOT6CLTJ', 0, 0);

--
-- Indexes for dumped tables
--

--
-- Indexes for table `access_logs`
--
ALTER TABLE `access_logs`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `security_alerts`
--
ALTER TABLE `security_alerts`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `access_logs`
--
ALTER TABLE `access_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=61;

--
-- AUTO_INCREMENT for table `security_alerts`
--
ALTER TABLE `security_alerts`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=10;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
