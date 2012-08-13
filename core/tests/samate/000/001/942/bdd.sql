CREATE TABLE `books` (
  `BookID` tinyint(4) NOT NULL auto_increment,
  `Name` varchar(255) collate latin1_general_ci default NULL,
  `Author` varchar(127) collate latin1_general_ci default NULL,
  PRIMARY KEY  (`BookID`),
  UNIQUE KEY `Name` (`Name`,`Author`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1 COLLATE=latin1_general_ci AUTO_INCREMENT=1 ;

-- 
-- Dumping data for table `books`
--
INSERT INTO `books` VALUES (1, 'A la recherche du temps perdu', 'Marcel Proust');
INSERT INTO `books` VALUES (2, 'Ulysses', 'James Joyce');
INSERT INTO `books` VALUES (3, 'Germinal', 'Emile Zola');
INSERT INTO `books` VALUES (4, 'L''etranger', 'Albert Camus');